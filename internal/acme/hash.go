package acme

import (
	"crypto/sha256"
	"encoding/hex"
)

func sha256Sum(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
