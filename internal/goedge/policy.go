package goedge

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
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

func (c *Client) BindCertificate(ctx context.Context, policyID, certID int64) (bool, error) {
	base, err := c.Policy(ctx, policyID)
	if err != nil {
		return false, err
	}
	if !base.IsOn {
		return false, errorsNew("SSL Policy 未启用")
	}
	matches := 0
	enabled := false
	for _, ref := range base.CertRefs {
		if ref.CertID == certID {
			matches++
			enabled = enabled || ref.IsOn
		}
	}
	if matches == 1 && enabled {
		return true, nil
	}
	if matches > 0 {
		return false, errorsNew("SSL Policy 已存在禁用或重复的目标证书引用，拒绝自动覆盖")
	}
	expected := base
	expected.CertRefs = append(append([]SSLCertRef(nil), base.CertRefs...), SSLCertRef{IsOn: true, CertID: certID})

	current, err := c.Policy(ctx, policyID)
	if err != nil {
		return false, err
	}
	if !reflect.DeepEqual(base, current) {
		return false, ErrPolicyDrift
	}
	certsJSON, _ := json.Marshal(expected.CertRefs)
	clientCAsJSON, _ := json.Marshal(expected.ClientCARefs)
	hstsJSON := []byte(nil)
	if len(expected.HSTS) > 0 && string(expected.HSTS) != "null" {
		hstsJSON = expected.HSTS
	}
	request := map[string]any{
		"sslPolicyId": policyID, "http2Enabled": expected.HTTP2Enabled, "http3Enabled": expected.HTTP3Enabled,
		"minVersion": expected.MinVersion, "sslCertsJSON": certsJSON, "hstsJSON": hstsJSON,
		"clientAuthType": expected.ClientAuthType, "clientCACertsJSON": clientCAsJSON,
		"cipherSuites": expected.CipherSuites, "cipherSuitesIsOn": expected.CipherSuitesIsOn, "ocspIsOn": expected.OCSPIsOn,
	}
	if err := c.call(ctx, "/SSLPolicyService/updateSSLPolicy", request, &struct{}{}); err != nil {
		return false, err
	}
	readBack, err := c.Policy(ctx, policyID)
	if err != nil {
		return false, err
	}
	if !reflect.DeepEqual(normalizePolicy(expected), readBack) {
		return false, ErrPolicyDrift
	}
	return false, nil
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
