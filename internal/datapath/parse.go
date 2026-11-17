// SPDX-License-Identifier: Apache-2.0
package datapath

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
)

type Flow struct {
	ID        string
	Match     map[string]string
	Recirc    string
	InPort    string
	Actions   string
	Packets   uint64
	Bytes     uint64
	Offloaded bool
	Raw       string
}

// Split separates OVS lists while preserving nested actions and quoted names.
func Split(s string) []string {
	var out []string
	depth, start := 0, 0
	quoted, escape := false, false
	for i, c := range s {
		if escape {
			escape = false
			continue
		}
		if c == '\\' && quoted {
			escape = true
			continue
		}
		if c == '"' {
			quoted = !quoted
			continue
		}
		if quoted {
			continue
		}
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if tail := strings.TrimSpace(s[start:]); tail != "" {
		out = append(out, tail)
	}
	return out
}

func Parse(text string) ([]Flow, []string) {
	var flows []Flow
	var errs []string
	s := bufio.NewScanner(strings.NewReader(text))
	s.Buffer(make([]byte, 4096), 4<<20)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.Contains(line, "actions:") {
			continue
		}
		f, err := ParseFlow(line)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		flows = append(flows, f)
	}
	if err := s.Err(); err != nil {
		errs = append(errs, err.Error())
	}
	return flows, errs
}

func ParseFlow(line string) (Flow, error) {
	before, actions, ok := strings.Cut(line, "actions:")
	if !ok {
		return Flow{}, fmt.Errorf("flow has no actions: %.100s", line)
	}
	f := Flow{Match: map[string]string{}, Actions: strings.TrimSpace(actions), Raw: line, Recirc: "0"}
	for _, item := range Split(before) {
		switch {
		case strings.HasPrefix(item, "ufid:"):
			f.ID = strings.TrimPrefix(item, "ufid:")
		case strings.HasPrefix(item, "packets:"):
			f.Packets, _ = strconv.ParseUint(strings.TrimPrefix(item, "packets:"), 10, 64)
		case strings.HasPrefix(item, "bytes:"):
			f.Bytes, _ = strconv.ParseUint(strings.TrimPrefix(item, "bytes:"), 10, 64)
		case strings.HasPrefix(item, "offloaded:"):
			f.Offloaded = strings.TrimSpace(strings.TrimPrefix(item, "offloaded:")) == "yes"
		case strings.HasPrefix(item, "dp:"):
			// A userspace DPDK datapath does not imply hardware offload.
		default:
			if strings.Contains(item, "(") {
				flatten("", item, f.Match)
			}
		}
	}
	if v, ok := f.Match["recirc_id"]; ok {
		f.Recirc = NormalizeNumber(v)
	}
	f.InPort = strings.Trim(f.Match["in_port"], "\"")
	if f.InPort == "" {
		return f, fmt.Errorf("flow has no ingress port: %.100s", line)
	}
	if f.ID == "" {
		f.ID = fmt.Sprintf("synthetic-%x", sha256.Sum256([]byte(before+actions)))[:26]
	}
	return f, nil
}

func flatten(prefix, text string, dst map[string]string) {
	name, rest, ok := strings.Cut(text, "(")
	if !ok || !strings.HasSuffix(rest, ")") {
		return
	}
	name = strings.TrimSpace(name)
	inner := rest[:len(rest)-1]
	key := prefix + name
	if name == "encap" {
		for _, c := range Split(inner) {
			flatten(prefix, c, dst)
		}
		return
	}
	children := Split(inner)
	if len(children) == 1 && !strings.Contains(children[0], "=") && !strings.Contains(children[0], "(") {
		dst[key] = inner
		return
	}
	for _, child := range children {
		if k, v, ok := strings.Cut(child, "="); ok && !strings.Contains(k, "(") {
			dst[key+"."+strings.TrimSpace(k)] = strings.TrimSpace(v)
		} else if strings.Contains(child, "(") {
			flatten(key+".", child, dst)
		} else {
			dst[key+"."+child] = "true"
		}
	}
}

func NormalizeNumber(s string) string {
	v, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return s
	}
	return strconv.FormatUint(v, 10)
}

func clone(m map[string]string) map[string]string {
	n := make(map[string]string, len(m))
	for k, v := range m {
		n[k] = v
	}
	return n
}

func Recircs(actions string) []string {
	var ids []string
	for _, a := range Split(actions) {
		if strings.HasPrefix(a, "recirc(") && strings.HasSuffix(a, ")") {
			ids = append(ids, NormalizeNumber(a[7:len(a)-1]))
		}
		if strings.HasPrefix(a, "clone(") {
			ids = append(ids, Recircs(a[6:len(a)-1])...)
		}
	}
	return ids
}

// Terminal classifies only unconditional terminal actions. Nested branches are
// intentionally excluded until their predicates are modeled.
func Terminal(actions string) string {
	if actions == "" || actions == "drop" || strings.HasPrefix(actions, "drop(") {
		return "drop"
	}
	return ""
}
