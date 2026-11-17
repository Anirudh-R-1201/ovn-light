// SPDX-License-Identifier: Apache-2.0
package trace

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
)

const MaxBackends = 4
const MaxLookups = 32

func Validate(r *Request) error {
	r.Protocol = strings.ToUpper(r.Protocol)
	if r.Protocol != "TCP" && r.Protocol != "UDP" {
		return fmt.Errorf("choose TCP or UDP")
	}
	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("choose a destination port between 1 and 65535")
	}
	if r.SourcePort == 0 {
		r.SourcePort = 49152
	}
	if r.SourcePort < 1 || r.SourcePort > 65535 {
		return fmt.Errorf("invalid source port")
	}
	if r.State == "" {
		r.State = "new"
	}
	if r.State != "new" && r.State != "established" && r.State != "reply" {
		return fmt.Errorf("invalid connection state")
	}
	return nil
}

// Resolve requires the selected attachment to still belong to the same pod.
// IP alone is insufficient when networks overlap or a pod has been replaced.
func Resolve(inv model.Inventory, e model.Endpoint) (ovn.Attachment, error) {
	if e.UID == "" || e.Network == "" || e.IP == "" {
		return ovn.Attachment{}, fmt.Errorf("select a pod attachment with its network, address and UID")
	}
	var matches []ovn.Attachment
	for _, a := range ovn.Attachments(inv) {
		p := a.Endpoint
		if p.UID == e.UID && p.Namespace == e.Namespace && p.Pod == e.Pod && p.Network == e.Network && p.IP == e.IP && p.NAD == e.NAD {
			for _, pod := range inv.Pods {
				if string(pod.UID) == e.UID && pod.DeletionTimestamp == nil && pod.Status.Phase == core.PodRunning {
					matches = append(matches, a)
				}
			}
		}
	}
	if len(matches) != 1 || matches[0].Node == "" {
		return ovn.Attachment{}, fmt.Errorf("pod attachment changed or is not running; refresh and select it again")
	}
	a := matches[0]
	if addr, err := netip.ParseAddr(a.Endpoint.IP); err != nil || addr.Zone() != "" || !addr.IsGlobalUnicast() {
		return a, fmt.Errorf("attachment has no valid IP")
	}
	if mac, err := net.ParseMAC(a.MAC); err != nil || len(mac) != 6 {
		return a, fmt.Errorf("OVN attachment MAC is unavailable")
	}
	return a, nil
}

func FindService(inv model.Inventory, ref ServiceRef) (core.Service, error) {
	for _, s := range inv.Services {
		if s.Namespace == ref.Namespace && s.Name == ref.Name && ref.UID != "" && string(s.UID) == ref.UID {
			return s, nil
		}
	}
	return core.Service{}, fmt.Errorf("Service changed; refresh and select it again")
}

func ServiceBackends(inv model.Inventory, s core.Service, slices []discovery.EndpointSlice, r Request) (Service, error) {
	result := Service{Ref: ServiceRef{s.Namespace, s.Name, string(s.UID)}, Type: s.Spec.Type, IPs: s.Spec.ClusterIPs, Ports: s.Spec.Ports}
	if r.Source.Network != "default" || r.Source.Role != "primary" {
		return result, fmt.Errorf("Service VIP simulation currently supports the primary cluster default network; select a pod attachment for UDN tracing")
	}
	if s.Spec.Type == core.ServiceTypeExternalName || s.Spec.ClusterIP == "None" || s.Spec.ClusterIP == "" {
		return result, fmt.Errorf("this Service has no ClusterIP; select a resolved pod or IP instead")
	}
	var port *core.ServicePort
	for _, p := range s.Spec.Ports {
		if p.Port == int32(r.Port) && string(p.Protocol) == r.Protocol {
			cp := p
			port = &cp
		}
	}
	if port == nil {
		return result, fmt.Errorf("Service does not expose %s/%d", r.Protocol, r.Port)
	}
	family, _ := netip.ParseAddr(r.Source.IP)
	running := map[string]bool{}
	for _, p := range inv.Pods {
		running[string(p.UID)] = p.DeletionTimestamp == nil && p.Status.Phase == core.PodRunning && p.Spec.NodeName != ""
	}
	attachments := map[string][]model.Endpoint{}
	for _, a := range ovn.Attachments(inv) {
		e := a.Endpoint
		mac, err := net.ParseMAC(a.MAC)
		if running[e.UID] && e.Network == "default" && e.Role == "primary" && err == nil && len(mac) == 6 {
			attachments[e.UID+"/"+e.IP] = append(attachments[e.UID+"/"+e.IP], e)
		}
	}
	seen := map[string]bool{}
	for _, slice := range slices {
		if slice.Namespace != s.Namespace || slice.Labels[discovery.LabelServiceName] != s.Name {
			continue
		}
		ownerOK := false
		for _, o := range slice.OwnerReferences {
			if o.Kind == "Service" && o.UID == s.UID {
				ownerOK = true
			}
		}
		if !ownerOK {
			continue
		}
		for _, p := range slice.Ports {
			name := ""
			if p.Name != nil {
				name = *p.Name
			}
			if name != port.Name || p.Protocol == nil || string(*p.Protocol) != r.Protocol || p.Port == nil || *p.Port < 1 || *p.Port > 65535 {
				continue
			}
			for _, ep := range slice.Endpoints {
				if ep.Conditions.Ready != nil && !*ep.Conditions.Ready || ep.Conditions.Terminating != nil && *ep.Conditions.Terminating {
					continue
				}
				for _, ip := range ep.Addresses {
					addr, err := netip.ParseAddr(ip)
					if err != nil || addr.Is4() != family.Is4() {
						continue
					}
					if ep.TargetRef == nil {
						continue
					}
					matches := attachments[string(ep.TargetRef.UID)+"/"+ip]
					if len(matches) != 1 {
						continue
					}
					for _, e := range matches {
						if ep.TargetRef.Kind != "Pod" || string(ep.TargetRef.UID) != e.UID || ep.TargetRef.Namespace != e.Namespace || ep.TargetRef.Name != e.Pod || e.Network != "default" || e.Role != "primary" || e.IP != ip {
							continue
						}
						key := e.UID + "/" + ip + "/" + strconv.Itoa(int(*p.Port))
						if !seen[key] {
							seen[key] = true
							e.Port = int(*p.Port)
							result.Backends = append(result.Backends, Backend{Endpoint: e, Port: int(*p.Port), Ready: true})
						}
					}
				}
			}
		}
	}
	sort.Slice(result.Backends, func(i, j int) bool {
		a, b := result.Backends[i], result.Backends[j]
		return a.Endpoint.Namespace+"/"+a.Endpoint.Pod+"/"+a.Endpoint.IP < b.Endpoint.Namespace+"/"+b.Endpoint.Pod+"/"+b.Endpoint.IP
	})
	if len(result.Backends) == 0 {
		result.Warnings = append(result.Warnings, "No ready pod backends could be resolved for this port and IP family. Check EndpointSlices, readiness and selectors.")
	}
	if s.Spec.InternalTrafficPolicy != nil && *s.Spec.InternalTrafficPolicy == core.ServiceInternalTrafficPolicyLocal {
		result.Warnings = append(result.Warnings, "internalTrafficPolicy is Local; only source-node backends are eligible.")
		filtered := result.Backends[:0]
		for _, b := range result.Backends {
			if b.Endpoint.Node == r.Source.Node {
				filtered = append(filtered, b)
			}
		}
		result.Backends = filtered
	}
	return result, nil
}

func binding(rows []model.Row, port string) (model.Row, error) {
	var matches []model.Row
	for _, b := range rows {
		if ovn.Str(b["logical_port"]) == port {
			matches = append(matches, b)
		}
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("logical port %s is unavailable or ambiguous in this zone", port)
	}
	return matches[0], nil
}

// NextHopMAC uses the pod's route annotation and the router peer of its switch.
// Looking up a gateway IP globally would mix gateways on overlapping UDNs.
func NextHopMAC(inv model.Inventory, src ovn.Attachment, dst model.Endpoint, rows []model.Row) (string, error) {
	b, err := binding(rows, src.LogicalPort)
	if err != nil {
		return "", err
	}
	type route struct {
		Dest    string `json:"dest"`
		NextHop string `json:"nextHop"`
	}
	type network struct {
		Gateways []string `json:"gateway_ips"`
		Routes   []route  `json:"routes"`
	}
	var networks map[string]network
	for _, p := range inv.Pods {
		if string(p.UID) == src.Endpoint.UID {
			if err = json.Unmarshal([]byte(p.Annotations["k8s.ovn.org/pod-networks"]), &networks); err != nil {
				return "", err
			}
		}
	}
	key := src.Endpoint.NAD
	if key == "" {
		key = "default"
	}
	n := networks[key]
	dest, err := netip.ParseAddr(dst.IP)
	if err != nil {
		return "", fmt.Errorf("invalid destination IP")
	}
	gateway := ""
	bits := -1
	for _, r := range n.Routes {
		prefix, e := netip.ParsePrefix(r.Dest)
		if e == nil && prefix.Contains(dest) && prefix.Bits() > bits {
			gateway = r.NextHop
			bits = prefix.Bits()
		}
	}
	if gateway == "" {
		for _, g := range n.Gateways {
			ip, e := netip.ParseAddr(g)
			if e == nil && ip.Is4() == dest.Is4() {
				gateway = g
				break
			}
		}
	}
	if gateway != "" {
		for _, p := range rows {
			if ovn.Str(p["datapath"]) != ovn.Str(b["datapath"]) {
				continue
			}
			peer := ovn.Str(ovn.Map(p["options"])["peer"])
			if peer == "" {
				continue
			}
			rp, e := binding(rows, peer)
			if e != nil {
				continue
			}
			for _, mac := range ovn.Strings(rp["mac"]) {
				parts := strings.Fields(mac)
				if len(parts) < 2 {
					continue
				}
				for _, address := range parts[1:] {
					ip := strings.Split(address, "/")[0]
					if ip == gateway && len(parts) > 0 {
						if m, e := net.ParseMAC(parts[0]); e == nil && len(m) == 6 {
							return m.String(), nil
						}
					}
				}
			}
		}
		return "", fmt.Errorf("gateway %s has no router MAC on the selected network", gateway)
	}
	for _, a := range ovn.Attachments(inv) {
		if a.Endpoint.Network == src.Endpoint.Network && a.Endpoint.UID == dst.UID && a.Endpoint.IP == dst.IP {
			db, e := binding(rows, a.LogicalPort)
			if e == nil && ovn.Str(db["datapath"]) == ovn.Str(b["datapath"]) {
				if m, e := net.ParseMAC(a.MAC); e == nil && len(m) == 6 {
					return m.String(), nil
				}
			}
		}
	}
	return "", fmt.Errorf("no gateway or directly connected destination MAC could be resolved")
}

func CTState(state string) string {
	switch state {
	case "established":
		return "trk,est"
	case "reply":
		return "trk,est,rpl"
	default:
		return "trk,new"
	}
}
func LogicalFlow(r Request, port, mac, destinationMAC string) string {
	ip := "ip4"
	if addr, _ := netip.ParseAddr(r.Source.IP); addr.Is6() {
		ip = "ip6"
	}
	proto := strings.ToLower(r.Protocol)
	f := fmt.Sprintf("inport == %s && eth.src == %s && eth.dst == %s && %s.src == %s && %s.dst == %s && ip.ttl == 64 && %s.src == %d && %s.dst == %d", strconv.Quote(port), mac, destinationMAC, ip, r.Source.IP, ip, r.Destination.IP, proto, r.SourcePort, proto, r.Port)
	if r.Protocol == "TCP" {
		flags := 16
		if r.State == "new" {
			flags = 2
		}
		f += fmt.Sprintf(" && tcp.flags == %d", flags)
	}
	return f
}
func LogicalArgs(db, flow, state, backend string) []string {
	args := []string{"ovn-trace", "--db=" + db, "--detailed"}
	for j := 0; j < MaxLookups; j++ {
		args = append(args, "--ct="+CTState(state))
	}
	if backend != "" {
		args = append(args, "--lb-dst="+backend)
	}
	return append(args, flow)
}
func OVSArgs(r Request, ofport int, mac, destinationMAC string) []string {
	proto := strings.ToLower(r.Protocol)
	src, dst := "nw_src", "nw_dst"
	if ip, _ := netip.ParseAddr(r.Source.IP); ip.Is6() {
		proto += "6"
		src, dst = "ipv6_src", "ipv6_dst"
	}
	flow := fmt.Sprintf("in_port=%d,%s,dl_src=%s,dl_dst=%s,%s=%s,%s=%s,nw_ttl=64,tp_src=%d,tp_dst=%d", ofport, proto, mac, destinationMAC, src, r.Source.IP, dst, r.Destination.IP, r.SourcePort, r.Port)
	if r.Protocol == "TCP" {
		flags := 16
		if r.State == "new" {
			flags = 2
		}
		flow += fmt.Sprintf(",tcp_flags=%d", flags)
	}
	args := []string{"ovs-appctl", "ofproto/trace", "br-int", flow}
	for j := 0; j < MaxLookups; j++ {
		args = append(args, "--ct-next", CTState(r.State))
	}
	return args
}
