package scheduler

import (
	"testing"
	"time"
)

func TestShortLivedCertificateGetsHourlyRenewalWindow(t *testing.T) {
	issued := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(160 * time.Hour)
	policy := Policy{RenewBefore: 72 * time.Hour, RetryMin: 15 * time.Minute, RetryMax: 6 * time.Hour, JitterMax: 10 * time.Minute}
	next := policy.NextRenewal("8.8.8.8", expires)
	if next.Before(expires.Add(-72*time.Hour)) || !next.Before(expires.Add(-72*time.Hour+10*time.Minute)) {
		t.Fatalf("next renewal %s outside expected window", next)
	}
	found := false
	for now := issued; now.Before(expires); now = now.Add(time.Hour) {
		if policy.Due(now, next) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("160h certificate never became due during hourly checks")
	}
}

func TestRetryDelayIsBounded(t *testing.T) {
	policy := Policy{RetryMin: 15 * time.Minute, RetryMax: 6 * time.Hour}
	if got := policy.RetryDelay(0); got != 15*time.Minute {
		t.Fatalf("first retry=%s", got)
	}
	if got := policy.RetryDelay(20); got != 6*time.Hour {
		t.Fatalf("bounded retry=%s", got)
	}
}
