package ipv4

import (
	"fmt"
	"net/netip"
	"strings"
)

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// ParsePublic 只接受一个规范化、可公开验证的 IPv4 字面量。
func ParsePublic(value string) (netip.Addr, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed != value {
		return netip.Addr{}, fmt.Errorf("IPv4 必须是非空且无首尾空格的规范字面量")
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() || addr.Is4In6() {
		return netip.Addr{}, fmt.Errorf("%q 不是原生 IPv4 地址", value)
	}
	if addr.String() != value {
		return netip.Addr{}, fmt.Errorf("IPv4 %q 不是规范格式", value)
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("IPv4 %q 不是可公开验证的公网地址", value)
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return netip.Addr{}, fmt.Errorf("IPv4 %q 位于不可公开验证的保留网段", value)
		}
	}
	return addr, nil
}
