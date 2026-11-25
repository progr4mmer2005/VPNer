package app

import "testing"

func TestSubscriptionLinks(t *testing.T) {
	cases := map[string]string{
		"happ://add/https://sub.example.com/abc":                        "https://sub.example.com/abc",
		"happ://add/https%3A%2F%2Fsub.example.com%2Fabc":                "https://sub.example.com/abc",
		"clash://install-config?url=https%3A%2F%2Fx.io%2Fs%3Ftoken%3D1": "https://x.io/s?token=1",
		" https://panel.example/sub/xyz ":                               "https://panel.example/sub/xyz",
	}
	for in, want := range cases {
		if got := NormalizeSubscription(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	if !IsSubscriptionLink("https://panel.example/sub/xyz") {
		t.Error("subscription not detected")
	}
	if IsSubscriptionLink("http://user:pass@1.2.3.4:8080") {
		t.Error("http proxy link mistaken for a subscription")
	}
	if IsSubscriptionLink("https://1.2.3.4:443") {
		t.Error("bare https proxy mistaken for a subscription")
	}
}
