package ipv4

import "testing"

func TestParsePublicV1Boundary(t *testing.T) {
	tests := []struct {
		value string
		ok    bool
	}{
		{"8.8.8.8", true}, {"1.1.1.1", true}, {"10.0.0.1", false}, {"127.0.0.1", false},
		{"169.254.1.1", false}, {"100.64.0.1", false}, {"192.0.2.1", false}, {"198.18.0.1", false},
		{"224.0.0.1", false}, {"0.0.0.0", false}, {"255.255.255.255", false}, {"2001:db8::1", false},
		{"::ffff:8.8.8.8", false}, {"8.8.8.8 ", false}, {"example.com", false}, {"8.8.8.8,1.1.1.1", false},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			_, err := ParsePublic(test.value)
			if (err == nil) != test.ok {
				t.Fatalf("ParsePublic(%q) error=%v, ok=%v", test.value, err, test.ok)
			}
		})
	}
}
