// SPDX-License-Identifier: Apache-2.0
package datapath

import "testing"

func TestMaskedIntersection(t *testing.T) {
	for _, tt := range []struct {
		key, a, b, want string
		ok              bool
	}{
		{"ipv4.dst", "10.1.2.0/255.255.255.0", "10.1.2.9", "10.1.2.9", true},
		{"ipv4.dst", "10.1.2.0/24", "10.1.3.9", "", false},
		{"tcp.dst", "0/0", "8080", "8080", true},
		{"tcp.dst", "80", "443", "", false},
		{"ipv6.dst", "fd00::/64", "fd00::12", "fd00::12", true},
		{"ct_state", "0x20/0x20", "0x21/0x21", "33/33", true},
	} {
		t.Run(tt.key+tt.a, func(t *testing.T) {
			got, ok := Intersect(tt.key, tt.a, tt.b)
			if ok != tt.ok || ok && got != tt.want {
				t.Fatalf("got %q,%t; want %q,%t", got, ok, tt.want, tt.ok)
			}
		})
	}
	if Exact("tcp.dst", "0/0") != "" {
		t.Fatal("wildcard became an exact port")
	}
}
func TestRecirculationComposition(t *testing.T) {
	raw := `ufid:a, recirc_id(0),in_port(4),ipv4(src=10.0.0.2,dst=10.0.0.0/24,proto=6),tcp(src=0/0,dst=0/0), packets:5, actions:ct(zone=1),recirc(0xa)
ufid:b, recirc_id(10),in_port(4),ipv4(dst=10.0.0.3,proto=6),tcp(dst=443), packets:5, actions:drop
ufid:c, recirc_id(10),in_port(4),ipv4(dst=10.1.0.3,proto=6),tcp(dst=80), packets:2, actions:drop`
	fs, errs := Parse(raw)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	paths := Reconstruct(fs)
	if len(paths) != 2 {
		t.Fatalf("paths=%+v", paths)
	}
	if len(paths[0].Flows) != 2 || paths[0].Identity["tcp.dst"] != "443" || !paths[0].Complete {
		t.Fatalf("composition: %+v", paths[0])
	}
	if paths[1].Complete || len(paths[1].Flows) != 1 {
		t.Fatal("incompatible continuation attached to ingress")
	}
}
func TestNATAndUnknownActions(t *testing.T) {
	m := map[string]string{"ipv4.dst": "10.96.0.2", "tcp.dst": "80", "ct_state": "0x20", "eth_type": "0x800"}
	n, w := Transform(m, "ct(zone=2,nat),recirc(1)")
	if _, ok := n["ipv4.dst"]; ok || len(w) == 0 {
		t.Fatal("NAT must discard pre-translation tuple and retain uncertainty")
	}
	n, w = Transform(m, "set(ipv4(dst=10.244.0.9)),recirc(3)")
	if n["ipv4.dst"] != "10.244.0.9" || len(w) != 0 {
		t.Fatal(n, w)
	}
	_, w = Transform(m, "clone(recirc(8)),recirc(9)")
	if len(w) == 0 {
		t.Fatal("conditional branch needs warning")
	}
	if Terminal("2,drop") != "" || Terminal("clone(drop),2") != "" {
		t.Fatal("forwarded traffic classified as an unconditional drop")
	}
}
func TestParseOffload(t *testing.T) {
	for _, tt := range []struct {
		provider string
		want     bool
	}{{"offloaded:yes, dp:tc", true}, {"dp:dpdk", false}, {"offloaded:no", false}} {
		f, e := ParseFlow("ufid:123, recirc_id(0),in_port(1), packets:7, bytes:42, " + tt.provider + ", actions:drop")
		if e != nil || f.Offloaded != tt.want || f.Packets != 7 {
			t.Fatal(f, e)
		}
	}
}
func TestCycleBounded(t *testing.T) {
	fs, _ := Parse("ufid:a, recirc_id(0),in_port(1), actions:recirc(1)\nufid:b, recirc_id(1),in_port(1), actions:recirc(1)")
	if len(Reconstruct(fs)) != 0 {
		t.Fatal("cycle should not invent a drop")
	}
}

func TestDropAfterConntrackCommit(t *testing.T) {
	commit := "ct(commit,zone=21,mark=0/0x41,label=0/0xffff00000000000000000000,nat(src))"
	for _, actions := range []string{commit, "set(skb_mark(0))," + commit, "ct_clear," + commit} {
		if Terminal(actions) != "drop" {
			t.Fatalf("missed implicit drop: %s", actions)
		}
	}
	for _, actions := range []string{commit + ",eth0", commit + ",recirc(1)", "clone(eth0)," + commit, "userspace(pid=1)," + commit, "ct(zone=21)", "ct(commit,table=1)", "drop(1),2"} {
		if Terminal(actions) != "" {
			t.Fatalf("invented unconditional drop: %s", actions)
		}
	}
	flows, _ := Parse("ufid:a,recirc_id(0),in_port(4),ipv4(src=10.0.0.2,dst=203.0.113.8),packets:3,actions:ct(zone=21,nat),recirc(1)\nufid:b,recirc_id(1),in_port(4),packets:3,actions:" + commit)
	paths := Reconstruct(flows)
	if len(paths) != 1 || len(paths[0].Flows) != 2 || paths[0].Original["ipv4.src"] != "10.0.0.2" {
		t.Fatal(paths)
	}
	if paths[0].Identity["ipv4.dst"] != "" {
		t.Fatal("pre-NAT destination was presented as known")
	}
}

func TestMaskedIngressPortAndSharedContinuation(t *testing.T) {
	fs, _ := Parse(`ufid:a,recirc_id(0),in_port(4),ipv4(src=10.0.0.1),packets:3,actions:recirc(1)
ufid:b,recirc_id(0),in_port(5),ipv4(src=10.0.0.2),packets:4,actions:recirc(1)
ufid:c,recirc_id(1),in_port(0/0),ipv4(src=0.0.0.0/0),packets:7,actions:drop`)
	paths := Reconstruct(fs)
	if len(paths) != 2 || len(paths[0].Flows) != 2 || len(paths[1].Flows) != 2 {
		t.Fatalf("masked continuation was not shared: %+v", paths)
	}
	if paths[0].Flows[1].ID != paths[1].Flows[1].ID {
		t.Fatal("shared counter identity was lost")
	}
}
func FuzzParse(f *testing.F) {
	f.Add("ufid:a,recirc_id(0),in_port(4),ipv4(src=10.0.0.1,dst=10.0.0.2), packets:1, actions:drop")
	f.Fuzz(func(t *testing.T, s string) {
		flows, _ := Parse(s)
		if len(flows) < 20 {
			_ = Reconstruct(flows)
		}
	})
}
