package client

import "testing"

func TestFollowExitNode(t *testing.T) {
	peers := []Peer{
		{ID: "p1", Name: "gw-nl", ExitNode: true},
		{ID: "p2", Name: "gw", ExitNode: true},
		{ID: "p3", Name: "nas"},
	}
	cases := []struct {
		name        string
		in          State
		wantID      string
		wantName    string
		wantChanged bool
	}{
		{"none chosen", State{}, "", "", false},
		{"id follows a rename", State{ExitNode: "gw", ExitNodeID: "p1"}, "p1", "gw-nl", true},
		{"id unchanged", State{ExitNode: "gw-nl", ExitNodeID: "p1"}, "p1", "gw-nl", false},
		{"id gone keeps the last name", State{ExitNode: "old", ExitNodeID: "p9"}, "p9", "old", false},
		{"name only is resolved once", State{ExitNode: "gw"}, "p2", "gw", true},
		{"name only needs an exit node", State{ExitNode: "nas"}, "", "nas", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.in
			if got := followExitNode(&st, peers); got != tc.wantChanged {
				t.Errorf("changed = %v, want %v", got, tc.wantChanged)
			}
			if st.ExitNodeID != tc.wantID || st.ExitNode != tc.wantName {
				t.Errorf("state = id %q name %q, want id %q name %q", st.ExitNodeID, st.ExitNode, tc.wantID, tc.wantName)
			}
		})
	}
}
