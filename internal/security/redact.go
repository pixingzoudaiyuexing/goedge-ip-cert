package security

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	pemPrivateKeyPattern = regexp.MustCompile(`(?s)-----BEGIN [^-]*(?:PRIVATE KEY)-----.*?-----END [^-]*(?:PRIVATE KEY)-----`)
	headerSecretPattern  = regexp.MustCompile(`(?i)(authorization|x-edge-access-token|edge-access-token)\s*[:=]\s*[^\r\n,;]+`)
	dsnPasswordPattern   = regexp.MustCompile(`([^\s:@/]+):([^\s@/]+)@`)
	ansiPattern          = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))`)
)

type Redactor struct {
	secrets []string
}

func NewRedactor(secrets ...string) *Redactor {
	filtered := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if len(secret) >= 4 {
			filtered = append(filtered, secret)
		}
	}
	return &Redactor{secrets: filtered}
}

func (r *Redactor) Redact(value string) string {
	value = ansiPattern.ReplaceAllString(value, "")
	value = pemPrivateKeyPattern.ReplaceAllString(value, "[REDACTED_PRIVATE_KEY]")
	value = headerSecretPattern.ReplaceAllStringFunc(value, func(match string) string {
		index := strings.IndexAny(match, ":=")
		if index < 0 {
			return "[REDACTED_HEADER]"
		}
		return match[:index+1] + "[REDACTED]"
	})
	value = dsnPasswordPattern.ReplaceAllString(value, "$1:[REDACTED]@")
	for _, secret := range r.secrets {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return strings.Map(func(char rune) rune {
		if char == '\n' || char == '\r' || char == '\t' || unicode.IsControl(char) ||
			(char >= '\u202a' && char <= '\u202e') || (char >= '\u2066' && char <= '\u2069') ||
			char == '\u200b' || char == '\u200c' || char == '\u200d' || char == '\ufeff' ||
			(char >= '\U000e0000' && char <= '\U000e007f') {
			return -1
		}
		return char
	}, value)
}
