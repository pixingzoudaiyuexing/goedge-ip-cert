package state

import "errors"

type LifecycleState string

const (
	StateNew              LifecycleState = "NEW"
	StateChallengePresent LifecycleState = "CHALLENGE_PRESENT"
	StateCertIssued       LifecycleState = "CERT_ISSUED"
	StateCertCreated      LifecycleState = "CERT_CREATED"
	StatePolicyBound      LifecycleState = "POLICY_BOUND"
	StateActive           LifecycleState = "ACTIVE"
	StateRenewing         LifecycleState = "RENEWING"
	StateError            LifecycleState = "ERROR"
	StateNeedsAttention   LifecycleState = "NEEDS_ATTENTION"
)

const (
	OperationIssue = "issue"
	OperationRenew = "renew"
)

const RecoveryNeedsAttention = "needs-attention"

var (
	ErrNotFound = errors.New("state: not found")
	ErrConflict = errors.New("state: concurrent transition conflict")
)

type ManagedCert struct {
	IPv4              string
	ServerID          int64
	PolicyID          int64
	CertID            int64
	AccountReference  string
	State             LifecycleState
	LastSuccessAt     int64
	ExpiresAt         int64
	NextRenewalAt     int64
	LastErrorCategory string
	LastError         string
	RecoveryMarker    string
}

type Operation struct {
	ID              string
	IPv4            string
	Kind            string
	Stage           LifecycleState
	Marker          string
	ServerID        int64
	PolicyID        int64
	CertID          int64
	UserID          int64
	CertFingerprint string
	ExpiresAt       int64
	ErrorCategory   string
	ErrorMessage    string
	RecoveryMarker  string
	RetryCount      int
	NextRetryAt     int64
	CreatedAt       int64
	UpdatedAt       int64
}

type RetryInfo struct {
	Attempt int
	NextAt  int64
}

func IsFirstIssueFailure(operation Operation) bool {
	return operation.Kind == OperationIssue && operation.Stage == StateError && operation.CertID == 0
}
