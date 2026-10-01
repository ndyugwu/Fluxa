package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyRateLimit_AllowsUpToBurstThenRejects(t *testing.T) {
	mw := VerifyRateLimit()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Burst is 60: the first 60 requests from the same IP succeed...
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/webhooks/verify", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, rec.Code)
		}
	}

	// ...and the 61st, still within the same instant, is rejected.
	req := httptest.NewRequest(http.MethodPost, "/v1/webhooks/verify", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("61st request: status = %d, want 429", rec.Code)
	}
}

func TestVerifyRateLimit_DifferentIPsHaveIndependentBudgets(t *testing.T) {
	mw := VerifyRateLimit()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust IP A's budget.
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/webhooks/verify", nil)
		req.RemoteAddr = "203.0.113.20:1"
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	reqA := httptest.NewRequest(http.MethodPost, "/v1/webhooks/verify", nil)
	reqA.RemoteAddr = "203.0.113.20:1"
	recA := httptest.NewRecorder()
	handler.ServeHTTP(recA, reqA)
	if recA.Code != http.StatusTooManyRequests {
		t.Fatalf("IP A should be rate limited, got status %d", recA.Code)
	}

	// IP B, which has sent nothing yet, must not be affected by IP A's usage
	// — this is the whole point of a per-IP (not global) limiter.
	reqB := httptest.NewRequest(http.MethodPost, "/v1/webhooks/verify", nil)
	reqB.RemoteAddr = "203.0.113.21:1"
	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, reqB)
	if recB.Code != http.StatusOK {
		t.Fatalf("IP B should not be affected by IP A's rate limit, got status %d", recB.Code)
	}
}

func TestSenderSignatureVerifiesSuccessfully(t *testing.T) {
	secret := "whsec_testsecret123"
	timestamp := "1700000000"
	body := `{"event":"transfer.settled"}`

	// Produce signature using the sender's signing function
	sig := sign(secret, timestamp, []byte(body))

	// Override nowFunc so the timestamp check falls within the tolerance window
	originalNow := nowFunc
	nowFunc = func() time.Time {
		return time.Unix(1700000010, 0)
	}
	defer func() { nowFunc = originalNow }()

	result := Verify(secret, timestamp, body, sig)
	if !result.Valid {
		t.Fatalf("expected sender signature to verify successfully, got reason: %s", result.Reason)
	}

	// Also assert acceptance by docs/webhook-verification/verify.go equivalent logic
	docsValid := docsVerify(secret, timestamp, body, sig, verifyToleranceSeconds)
	if !docsValid {
		t.Fatalf("expected sender signature to be accepted by docs/webhook-verification/verify.go logic")
	}
}

func docsVerify(secret, timestampHeader, body string, signatureHeader string, toleranceSeconds int) bool {
	if len(signatureHeader) < 7 || signatureHeader[:7] != "sha256=" {
		return false
	}
	recvSig := signatureHeader[7:]

	ts, err := time.ParseDuration(timestampHeader + "s")
	_ = ts
	// simpler parse for test
	var tSec int64
	_, _ = fmt.Sscanf(timestampHeader, "%d", &tSec)

	now := int64(1700000010)
	if now-tSec > int64(toleranceSeconds) || tSec-now > int64(toleranceSeconds) {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestampHeader + "."))
	mac.Write([]byte(body))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(recvSig), []byte(expectedSig))
}
