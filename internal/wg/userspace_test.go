package wg

import (
	"strings"
	"testing"
)

// TestUserspaceRenderSkipsHeldPort: the listen port travels to
// wireguard-go only when it changes, because every listen_port line
// makes it close and reopen its socket.
func TestUserspaceRenderSkipsHeldPort(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	u := &userspaceDevice{}
	cfg := Config{PrivateKey: priv, ListenPort: 51820}
	if got := u.render(cfg, nil); !strings.Contains(got, "listen_port=51820\n") {
		t.Errorf("first configure lacks the port:\n%s", got)
	}
	u.port = 51820
	if got := u.render(cfg, nil); strings.Contains(got, "listen_port") {
		t.Errorf("rebind requested for the port already held:\n%s", got)
	}
	cfg.ListenPort = 51821
	if got := u.render(cfg, nil); !strings.Contains(got, "listen_port=51821\n") {
		t.Errorf("port change not sent:\n%s", got)
	}
}
