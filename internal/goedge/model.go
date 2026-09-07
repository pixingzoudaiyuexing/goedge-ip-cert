package goedge

import (
	"encoding/json"
	"errors"
)

var (
	ErrAuthentication       = errors.New("GoEdge authentication failed")
	ErrUnexpectedResponse   = errors.New("GoEdge unexpected response")
	ErrServerNotFound       = errors.New("GoEdge server not found")
	ErrMultipleServers      = errors.New("multiple GoEdge servers match IPv4")
	ErrCertificateNotBound  = errors.New("GoEdge certificate is not bound to SSL policy")
	ErrCertificateNotFound  = errors.New("GoEdge certificate not found")
	ErrMultipleCertificates = errors.New("multiple GoEdge certificates match marker")
)

type Credentials struct {
	IdentityType string
	AccessKeyID  string
	AccessKey    string
}

type CredentialProvider interface {
	Credentials() (Credentials, error)
}

type CertificateInput struct {
	ID          int64
	UserID      int64
	IsOn        bool
	Name        string
	Description string
	ServerName  string
	IsCA        bool
	CertData    []byte
	KeyData     []byte
	TimeBeginAt int64
	TimeEndAt   int64
	DNSNames    []string
	CommonNames []string
}

type CertificateConfig struct {
	ID          int64    `json:"id"`
	IsOn        bool     `json:"isOn"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	CertData    []byte   `json:"certData"`
	KeyData     []byte   `json:"keyData"`
	ServerName  string   `json:"serverName"`
	IsCA        bool     `json:"isCA"`
	IsACME      bool     `json:"isACME"`
	TimeBeginAt int64    `json:"timeBeginAt"`
	TimeEndAt   int64    `json:"timeEndAt"`
	DNSNames    []string `json:"dnsNames"`
	CommonNames []string `json:"commonNames"`
}

type ServerName struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	SubNames []string `json:"subNames"`
}

type SSLPolicyRef struct {
	IsOn        bool  `json:"isOn"`
	SSLPolicyID int64 `json:"sslPolicyId"`
}

type ServerTarget struct {
	ID        int64
	UserID    int64
	PolicyID  int64
	HTTPSIsOn bool
}

type Website struct {
	ServerID   int64  `json:"serverId"`
	UserID     int64  `json:"userId"`
	Name       string `json:"name"`
	IPv4       string `json:"ipv4"`
	PolicyID   int64  `json:"policyId"`
	ClusterID  int64  `json:"clusterId"`
	Cluster    string `json:"cluster"`
	NodeOnline bool   `json:"nodeOnline"`
}

type SSLCertRef struct {
	IsOn   bool  `json:"isOn"`
	CertID int64 `json:"certId"`
}

type SSLPolicy struct {
	ID               int64           `json:"id"`
	IsOn             bool            `json:"isOn"`
	CertRefs         []SSLCertRef    `json:"certRefs"`
	ClientAuthType   int32           `json:"clientAuthType"`
	ClientCARefs     []SSLCertRef    `json:"clientCARefs"`
	MinVersion       string          `json:"minVersion"`
	CipherSuitesIsOn bool            `json:"cipherSuitesIsOn"`
	CipherSuites     []string        `json:"cipherSuites"`
	HSTS             json.RawMessage `json:"hsts"`
	HTTP2Enabled     bool            `json:"http2Enabled"`
	HTTP3Enabled     bool            `json:"http3Enabled"`
	OCSPIsOn         bool            `json:"ocspIsOn"`
}
