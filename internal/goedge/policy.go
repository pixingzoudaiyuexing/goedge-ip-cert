package goedge

import (
	"context"
	"encoding/json"
	"fmt"
)

func (c *Client) Policy(ctx context.Context, policyID int64) (SSLPolicy, error) {
	var response struct {
		SSLPolicyJSON []byte `json:"sslPolicyJSON"`
	}
	if err := c.call(ctx, "/SSLPolicyService/findEnabledSSLPolicyConfig",
		map[string]any{"sslPolicyId": policyID, "ignoreData": true}, &response); err != nil {
		return SSLPolicy{}, err
	}
	var policy SSLPolicy
	if len(response.SSLPolicyJSON) == 0 || string(response.SSLPolicyJSON) == "null" || json.Unmarshal(response.SSLPolicyJSON, &policy) != nil || policy.ID <= 0 {
		return SSLPolicy{}, fmt.Errorf("%w: 无效 sslPolicyJSON", ErrUnexpectedResponse)
	}
	return normalizePolicy(policy), nil
}

// VerifyCertificateBound 只读确认管理员已经在 EdgeAdmin 完成证书绑定。
func (c *Client) VerifyCertificateBound(ctx context.Context, policyID, certID int64) error {
	policy, err := c.Policy(ctx, policyID)
	if err != nil {
		return err
	}
	if !policy.IsOn {
		return errorsNew("SSL Policy 未启用")
	}
	for _, ref := range policy.CertRefs {
		if ref.CertID == certID && ref.IsOn {
			return nil
		}
	}
	return fmt.Errorf("%w: certificate ID %d, policy ID %d; 请在 EdgeAdmin 手工绑定后重试",
		ErrCertificateNotBound, certID, policyID)
}

func normalizePolicy(policy SSLPolicy) SSLPolicy {
	if policy.CertRefs == nil {
		policy.CertRefs = []SSLCertRef{}
	}
	if policy.ClientCARefs == nil {
		policy.ClientCARefs = []SSLCertRef{}
	}
	if policy.CipherSuites == nil {
		policy.CipherSuites = []string{}
	}
	if len(policy.HSTS) == 0 {
		policy.HSTS = json.RawMessage("null")
	}
	return policy
}
