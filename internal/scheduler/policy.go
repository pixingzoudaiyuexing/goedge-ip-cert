package scheduler

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

type ErrorCategory string

const (
	ErrorTransient ErrorCategory = "transient"
	ErrorConfig    ErrorCategory = "config"
	ErrorAuth      ErrorCategory = "auth"
	ErrorSchema    ErrorCategory = "schema"
	ErrorSecurity  ErrorCategory = "security"
)

type Policy struct {
	RenewBefore time.Duration
	RetryMin    time.Duration
	RetryMax    time.Duration
	JitterMax   time.Duration
}

func (p Policy) Validate() error {
	if p.RenewBefore < 48*time.Hour || p.RenewBefore > 96*time.Hour {
		return errors.New("renew before 必须在 48h 到 96h")
	}
	if p.RetryMin <= 0 || p.RetryMax < p.RetryMin || p.JitterMax < 0 {
		return errors.New("retry/jitter 配置无效")
	}
	return nil
}

func (p Policy) NextRenewal(ip string, expiresAt time.Time) time.Time {
	return expiresAt.Add(-p.RenewBefore).Add(p.jitter(ip, expiresAt))
}

func (p Policy) Due(now, nextRenewal time.Time) bool {
	return !now.Before(nextRenewal)
}

func (p Policy) RetryDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	delay := p.RetryMin
	for i := 0; i < attempt; i++ {
		if delay >= p.RetryMax/2 {
			return p.RetryMax
		}
		delay *= 2
	}
	if delay > p.RetryMax {
		return p.RetryMax
	}
	return delay
}

func (p Policy) jitter(ip string, expiresAt time.Time) time.Duration {
	if p.JitterMax <= 0 {
		return 0
	}
	digest := sha256.Sum256([]byte(ip + expiresAt.UTC().Format(time.RFC3339)))
	return time.Duration(binary.BigEndian.Uint64(digest[:8]) % uint64(p.JitterMax))
}
