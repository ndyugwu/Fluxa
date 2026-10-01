package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// sign computes the HMAC-SHA256 signature for a webhook delivery, adhering to
// the documented verification contract: HMAC(secret, timestamp + "." + body)
// prefixed with "sha256=".
func sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
