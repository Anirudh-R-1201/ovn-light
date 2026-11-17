// SPDX-License-Identifier: Apache-2.0
package ovn

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/trozet/ovn-light/internal/model"
)

func DecodeTable(data string) ([]model.Row, error) {
	var table struct {
		Headings []string `json:"headings"`
		Data     [][]any  `json:"data"`
	}
	if err := json.Unmarshal([]byte(data), &table); err != nil {
		return nil, err
	}
	if len(table.Headings) == 0 {
		return nil, fmt.Errorf("OVSDB result has no headings")
	}
	rows := make([]model.Row, 0, len(table.Data))
	for _, values := range table.Data {
		if len(values) != len(table.Headings) {
			return nil, fmt.Errorf("OVSDB column count mismatch")
		}
		row := model.Row{}
		for i, v := range values {
			row[table.Headings[i]] = normalize(v)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func normalize(v any) any {
	a, ok := v.([]any)
	if !ok || len(a) != 2 {
		return v
	}
	tag, ok := a[0].(string)
	if !ok {
		return v
	}
	switch tag {
	case "uuid", "named-uuid":
		return a[1]
	case "set":
		items, _ := a[1].([]any)
		out := make([]any, 0, len(items))
		for _, x := range items {
			out = append(out, normalize(x))
		}
		return out
	case "map":
		pairs, _ := a[1].([]any)
		out := map[string]any{}
		for _, p := range pairs {
			if kv, ok := p.([]any); ok && len(kv) == 2 {
				out[fmt.Sprint(kv[0])] = normalize(kv[1])
			}
		}
		return out
	}
	return v
}

func Str(v any) string {
	if v == nil {
		return ""
	}
	if a, ok := v.([]any); ok {
		if len(a) == 1 {
			return Str(a[0])
		}
		return ""
	}
	if n, ok := v.(float64); ok {
		return strconv.FormatFloat(n, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}
func Map(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}
func Strings(v any) []string {
	a, ok := v.([]any)
	if !ok {
		if s := Str(v); s != "" {
			return []string{s}
		}
		return nil
	}
	var out []string
	for _, x := range a {
		out = append(out, Str(x))
	}
	return out
}
