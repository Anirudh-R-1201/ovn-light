// SPDX-License-Identifier: Apache-2.0
package datapath

import (
	"fmt"
	"math/big"
	"net/netip"
	"strconv"
	"strings"
)

type bits struct {
	value, mask *big.Int
	width       int
	kind        string
}

func parseBits(key, s string) (bits, bool) {
	value, mask, masked := strings.Cut(s, "/")
	b := bits{value: new(big.Int), mask: new(big.Int), width: 64, kind: "number"}
	if ip, err := netip.ParseAddr(value); err == nil {
		ip = ip.Unmap()
		b.kind = "ip"
		b.width = ip.BitLen()
		b.value.SetBytes(ip.AsSlice())
		if masked {
			if m, e := netip.ParseAddr(mask); e == nil && m.Unmap().BitLen() == b.width {
				b.mask.SetBytes(m.Unmap().AsSlice())
			} else if n, e := strconv.Atoi(mask); e == nil && n >= 0 && n <= b.width {
				b.mask.Sub(new(big.Int).Lsh(big.NewInt(1), uint(n)), big.NewInt(1))
				b.mask.Lsh(b.mask, uint(b.width-n))
			} else {
				return b, false
			}
		}
	} else if strings.Count(value, ":") == 5 {
		b.kind = "mac"
		b.width = 48
		if _, ok := b.value.SetString(strings.ReplaceAll(value, ":", ""), 16); !ok {
			return b, false
		}
		if masked {
			if _, ok := b.mask.SetString(strings.ReplaceAll(mask, ":", ""), 16); !ok {
				return b, false
			}
		}
	} else {
		if key == "ct_label" {
			b.width = 128
		}
		if key == "tcp.src" || key == "tcp.dst" || key == "udp.src" || key == "udp.dst" || key == "sctp.src" || key == "sctp.dst" || key == "ct_zone" || key == "eth_type" {
			b.width = 16
		}
		if key == "ipv4.proto" || key == "ipv6.proto" {
			b.width = 8
		}
		if _, ok := b.value.SetString(value, 0); !ok {
			if _, ok = b.value.SetString(value, 10); !ok {
				return b, false
			}
		}
		if masked {
			if _, ok := b.mask.SetString(mask, 0); !ok {
				if _, ok = b.mask.SetString(mask, 10); !ok {
					return b, false
				}
			}
		}
	}
	if !masked {
		b.mask.Sub(new(big.Int).Lsh(big.NewInt(1), uint(b.width)), big.NewInt(1))
	}
	if b.value.Sign() < 0 || b.mask.Sign() < 0 || b.value.BitLen() > b.width || b.mask.BitLen() > b.width {
		return b, false
	}
	b.value.And(b.value, b.mask)
	return b, true
}

func formatBits(b bits) string {
	full := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(b.width)), big.NewInt(1))
	format := func(n *big.Int) string {
		if b.kind == "ip" {
			data := n.FillBytes(make([]byte, b.width/8))
			ip, _ := netip.AddrFromSlice(data)
			return ip.String()
		}
		if b.kind == "mac" {
			h := fmt.Sprintf("%012x", n)
			return h[:2] + ":" + h[2:4] + ":" + h[4:6] + ":" + h[6:8] + ":" + h[8:10] + ":" + h[10:]
		}
		return n.String()
	}
	if b.mask.Cmp(full) == 0 {
		return format(b.value)
	}
	return format(b.value) + "/" + format(b.mask)
}

// Intersect preserves wildcard masks: zero bits never become packet evidence.
func Intersect(key, a, b string) (string, bool) {
	if a == b {
		return a, true
	}
	x, ok := parseBits(key, a)
	y, ok2 := parseBits(key, b)
	if !ok || !ok2 || x.width != y.width {
		return "", false
	}
	common := new(big.Int).And(x.mask, y.mask)
	diff := new(big.Int).Xor(x.value, y.value)
	diff.And(diff, common)
	if diff.Sign() != 0 {
		return "", false
	}
	x.value.Or(x.value, y.value)
	x.mask.Or(x.mask, y.mask)
	return formatBits(x), true
}

func Exact(key, value string) string {
	b, ok := parseBits(key, value)
	if !ok {
		if !strings.Contains(value, "/") {
			return strings.Trim(value, "\"")
		}
		return ""
	}
	full := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(b.width)), big.NewInt(1))
	if b.mask.Cmp(full) != 0 {
		return ""
	}
	return formatBits(b)
}

func Merge(a, b map[string]string) (map[string]string, bool) {
	out := clone(a)
	for k, v := range b {
		if k == "recirc_id" {
			continue
		}
		if old, ok := out[k]; ok {
			m, compatible := Intersect(k, old, v)
			if !compatible {
				return nil, false
			}
			out[k] = m
		} else {
			out[k] = v
		}
	}
	return out, true
}
