package goedge

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/ipv4"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/security"
)

type serverResponse struct {
	ID              int64  `json:"id"`
	UserID          int64  `json:"userId"`
	Name            string `json:"name"`
	ServerNamesJSON []byte `json:"serverNamesJSON"`
	HTTPSJSON       []byte `json:"httpsJSON"`
	NodeCluster     *struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	} `json:"nodeCluster"`
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

// ListEligibleWebsites lists, without mutating GoEdge, HTTP websites whose
// complete identity is one canonical public IPv4 and whose HTTPS/cluster
// topology can be managed safely.
func (c *Client) ListEligibleWebsites(ctx context.Context) ([]Website, error) {
	const pageSize = 100
	var count struct {
		Count int64 `json:"count"`
	}
	if err := c.call(ctx, "/ServerService/countAllEnabledServersMatch", map[string]any{
		"protocolFamily": "http",
	}, &count); err != nil {
		return nil, err
	}
	if count.Count < 0 || count.Count > 10_000 {
		return nil, fmt.Errorf("网站数量 %d 超过安全上限", count.Count)
	}
	result := make([]Website, 0)
	for offset := int64(0); offset < count.Count; offset += pageSize {
		var page struct {
			Servers []serverResponse `json:"servers"`
		}
		if err := c.call(ctx, "/ServerService/listEnabledServersMatch", map[string]any{
			"offset": offset, "size": pageSize, "protocolFamily": "http",
			"ignoreServerNames": false, "ignoreSSLCerts": true,
		}, &page); err != nil {
			return nil, err
		}
		for _, server := range page.Servers {
			website, ok, err := c.eligibleWebsite(ctx, server)
			if err != nil {
				return nil, err
			}
			if ok {
				result = append(result, website)
			}
		}
		if len(page.Servers) < pageSize {
			break
		}
	}
	counts := make(map[string]int, len(result))
	for _, website := range result {
		counts[website.IPv4]++
	}
	unique := result[:0]
	for _, website := range result {
		if counts[website.IPv4] == 1 {
			unique = append(unique, website)
		}
	}
	result = unique
	sort.Slice(result, func(i, j int) bool { return result[i].IPv4 < result[j].IPv4 })
	return result, nil
}

func (c *Client) eligibleWebsite(ctx context.Context, server serverResponse) (Website, bool, error) {
	var names []ServerName
	if err := json.Unmarshal(server.ServerNamesJSON, &names); err != nil {
		return Website{}, false, fmt.Errorf("%w: server %d names", ErrUnexpectedResponse, server.ID)
	}
	if len(names) != 1 || names[0].Name == "" || len(names[0].SubNames) != 0 ||
		(names[0].Type != "" && names[0].Type != "full") {
		return Website{}, false, nil
	}
	identity := names[0].Name
	ip, err := ipv4.ParsePublic(identity)
	if err != nil || ip.String() != identity {
		return Website{}, false, nil
	}
	var https httpsConfig
	if len(server.HTTPSJSON) == 0 || string(server.HTTPSJSON) == "null" || json.Unmarshal(server.HTTPSJSON, &https) != nil ||
		!https.IsOn || https.SSLPolicyRef == nil || !https.SSLPolicyRef.IsOn || https.SSLPolicyRef.SSLPolicyID <= 0 ||
		server.NodeCluster == nil || server.NodeCluster.ID <= 0 {
		return Website{}, false, nil
	}
	online, valid, err := c.clusterNodeState(ctx, server.NodeCluster.ID)
	if err != nil {
		return Website{}, false, err
	}
	if !valid {
		return Website{}, false, nil
	}
	policy, err := c.Policy(ctx, https.SSLPolicyRef.SSLPolicyID)
	if err != nil {
		return Website{}, false, err
	}
	if !policy.IsOn {
		return Website{}, false, nil
	}
	name := server.Name
	if name == "" {
		name = identity
	}
	redactor := security.NewRedactor()
	return Website{ServerID: server.ID, UserID: server.UserID, Name: redactor.Redact(name), IPv4: identity,
		PolicyID: https.SSLPolicyRef.SSLPolicyID, ClusterID: server.NodeCluster.ID,
		Cluster: redactor.Redact(server.NodeCluster.Name), NodeOnline: online}, true, nil
}

func (c *Client) clusterNodeState(ctx context.Context, clusterID int64) (online, valid bool, err error) {
	var response struct {
		Nodes []struct {
			IsInstalled bool `json:"isInstalled"`
			IsOn        bool `json:"isOn"`
			IsUp        bool `json:"isUp"`
		} `json:"nodes"`
	}
	if err := c.call(ctx, "/NodeService/listEnabledNodesMatch", map[string]any{
		"offset": 0, "size": 100, "nodeClusterId": clusterID,
	}, &response); err != nil {
		return false, false, err
	}
	for _, node := range response.Nodes {
		if node.IsInstalled && node.IsOn {
			valid = true
			if node.IsUp {
				online = true
			}
		}
	}
	return online, valid, nil
}
