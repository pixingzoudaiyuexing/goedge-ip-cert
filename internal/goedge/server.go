package goedge

import (
	"context"
	"encoding/json"
	"fmt"
)

type serverResponse struct {
	ID              int64  `json:"id"`
	UserID          int64  `json:"userId"`
	ServerNamesJSON []byte `json:"serverNamesJSON"`
	HTTPSJSON       []byte `json:"httpsJSON"`
}

type httpsConfig struct {
	IsOn         bool          `json:"isOn"`
	SSLPolicyRef *SSLPolicyRef `json:"sslPolicyRef"`
}

func (c *Client) DiscoverServer(ctx context.Context, ipv4 string) (ServerTarget, error) {
	const (
		pageSize            = 100
		maxServerCandidates = 10_000
	)
	var countResponse struct {
		Count int64 `json:"count"`
	}
	if err := c.call(ctx, "/ServerService/countAllEnabledServersMatch", map[string]any{
		"keyword": ipv4, "protocolFamily": "http",
	}, &countResponse); err != nil {
		return ServerTarget{}, err
	}
	if countResponse.Count <= 0 {
		return ServerTarget{}, ErrServerNotFound
	}
	if countResponse.Count > maxServerCandidates {
		return ServerTarget{}, fmt.Errorf("候选 Server 数量 %d 超过安全上限 %d", countResponse.Count, maxServerCandidates)
	}
	var exact []ServerTarget
	for offset := int64(0); offset < countResponse.Count; offset += pageSize {
		var response struct {
			Servers []serverResponse `json:"servers"`
		}
		err := c.call(ctx, "/ServerService/listEnabledServersMatch", map[string]any{
			"offset": offset, "size": pageSize, "keyword": ipv4, "protocolFamily": "http",
			"ignoreServerNames": false, "ignoreSSLCerts": true,
		}, &response)
		if err != nil {
			return ServerTarget{}, err
		}
		for _, server := range response.Servers {
			var names []ServerName
			if err := json.Unmarshal(server.ServerNamesJSON, &names); err != nil {
				return ServerTarget{}, fmt.Errorf("%w: server %d names", ErrUnexpectedResponse, server.ID)
			}
			if !containsExactName(names, ipv4) {
				continue
			}
			var https httpsConfig
			if len(server.HTTPSJSON) == 0 || string(server.HTTPSJSON) == "null" || json.Unmarshal(server.HTTPSJSON, &https) != nil {
				return ServerTarget{}, fmt.Errorf("server %d HTTPS 配置无效", server.ID)
			}
			policyID := int64(0)
			if https.SSLPolicyRef != nil && https.SSLPolicyRef.IsOn {
				policyID = https.SSLPolicyRef.SSLPolicyID
			}
			exact = append(exact, ServerTarget{ID: server.ID, UserID: server.UserID, PolicyID: policyID, HTTPSIsOn: https.IsOn})
		}
		if len(response.Servers) == 0 || len(response.Servers) < pageSize {
			break
		}
	}
	if len(exact) == 0 {
		return ServerTarget{}, ErrServerNotFound
	}
	if len(exact) != 1 {
		return ServerTarget{}, fmt.Errorf("%w: %d", ErrMultipleServers, len(exact))
	}
	if !exact[0].HTTPSIsOn || exact[0].PolicyID <= 0 {
		return ServerTarget{}, fmt.Errorf("server %d 没有启用的 HTTPS SSL Policy，默认拒绝自动创建", exact[0].ID)
	}
	return exact[0], nil
}

func containsExactName(names []ServerName, ipv4 string) bool {
	for _, name := range names {
		if name.Name == ipv4 && (name.Type == "" || name.Type == "full") {
			return true
		}
		for _, subName := range name.SubNames {
			if subName == ipv4 {
				return true
			}
		}
	}
	return false
}
