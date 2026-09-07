package goedge

import (
	"context"
	"encoding/json"
	"fmt"
)

func (c *Client) CreateCertificate(ctx context.Context, input CertificateInput) (int64, error) {
	var response struct {
		SSLCertID int64 `json:"sslCertId"`
	}
	err := c.call(ctx, "/SSLCertService/createSSLCert", map[string]any{
		"userId": input.UserID, "isOn": input.IsOn, "name": input.Name, "description": input.Description,
		"serverName": input.ServerName, "isCA": input.IsCA, "certData": input.CertData, "keyData": input.KeyData,
		"timeBeginAt": input.TimeBeginAt, "timeEndAt": input.TimeEndAt, "dnsNames": input.DNSNames,
		"commonNames": input.CommonNames,
	}, &response)
	if err != nil {
		return 0, err
	}
	if response.SSLCertID <= 0 {
		return 0, fmt.Errorf("%w: createSSLCert 未返回 ID", ErrUnexpectedResponse)
	}
	return response.SSLCertID, nil
}

func (c *Client) UpdateCertificate(ctx context.Context, input CertificateInput) error {
	if input.ID <= 0 {
		return errorsNew("sslCertId 必须大于 0")
	}
	return c.call(ctx, "/SSLCertService/updateSSLCert", map[string]any{
		"sslCertId": input.ID, "isOn": input.IsOn, "name": input.Name, "description": input.Description,
		"serverName": input.ServerName, "isCA": input.IsCA, "certData": input.CertData, "keyData": input.KeyData,
		"timeBeginAt": input.TimeBeginAt, "timeEndAt": input.TimeEndAt, "dnsNames": input.DNSNames,
		"commonNames": input.CommonNames,
	}, &struct{}{})
}

func (c *Client) Certificate(ctx context.Context, certID int64) (CertificateConfig, error) {
	var response struct {
		SSLCertJSON []byte `json:"sslCertJSON"`
	}
	if err := c.call(ctx, "/SSLCertService/findEnabledSSLCertConfig", map[string]int64{"sslCertId": certID}, &response); err != nil {
		return CertificateConfig{}, err
	}
	if len(response.SSLCertJSON) == 0 || string(response.SSLCertJSON) == "null" {
		return CertificateConfig{}, ErrCertificateNotFound
	}
	var cert CertificateConfig
	if err := json.Unmarshal(response.SSLCertJSON, &cert); err != nil || cert.ID <= 0 {
		return CertificateConfig{}, fmt.Errorf("%w: 无效 sslCertJSON", ErrUnexpectedResponse)
	}
	return cert, nil
}

func (c *Client) FindCertificateByMarker(ctx context.Context, marker string, userID int64) (CertificateConfig, error) {
	var response struct {
		SSLCertsJSON []byte `json:"sslCertsJSON"`
	}
	request := map[string]any{"keyword": marker, "userId": userID, "offset": 0, "size": 100}
	if err := c.call(ctx, "/SSLCertService/listSSLCerts", request, &response); err != nil {
		return CertificateConfig{}, err
	}
	var certs []CertificateConfig
	if err := json.Unmarshal(response.SSLCertsJSON, &certs); err != nil {
		return CertificateConfig{}, fmt.Errorf("%w: 无效 sslCertsJSON", ErrUnexpectedResponse)
	}
	var matches []CertificateConfig
	for _, cert := range certs {
		if cert.Name == marker {
			matches = append(matches, cert)
		}
	}
	if len(matches) == 0 {
		return CertificateConfig{}, ErrCertificateNotFound
	}
	if len(matches) != 1 {
		return CertificateConfig{}, ErrMultipleCertificates
	}
	return matches[0], nil
}

func errorsNew(message string) error { return fmt.Errorf("GoEdge client: %s", message) }
