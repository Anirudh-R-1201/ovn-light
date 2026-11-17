// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	"github.com/trozet/ovn-light/internal/policy"
	trace "github.com/trozet/ovn-light/internal/trace"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

type traceSession struct {
	remaining int
	collector *Collector
	inv       model.Inventory
	metadata  map[string]model.NodeSnapshot
}

func (s *traceSession) target(node string, ovs bool) (Target, error) {
	for _, p := range s.inv.Pods {
		if p.Namespace != s.collector.Namespace || p.Spec.NodeName != node || p.DeletionTimestamp != nil || p.Status.Phase != core.PodRunning {
			continue
		}
		for _, c := range p.Spec.Containers {
			if ovs && (c.Name == "ovs-daemons" || c.Name == "ovs-vswitchd") || !ovs && c.Name == "ovnkube-controller" {
				return Target{p.Namespace, p.Name, c.Name}, nil
			}
		}
	}
	return Target{}, fmt.Errorf("no running %s container found on %s", map[bool]string{true: "OVS", false: "OVN"}[ovs], node)
}
func (s *traceSession) exec(ctx context.Context, t Target, args []string, limit int) (string, error) {
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if s.remaining <= 0 {
		return "", fmt.Errorf("diagnostic output budget exhausted")
	}
	if limit > s.remaining {
		limit = s.remaining
	}
	var raw string
	var err error
	if s.collector.exec != nil {
		raw, err = s.collector.exec(call, t, args)
	} else {
		raw, err = s.collector.Client.execBounded(call, t, args, nil, limit)
	}
	s.remaining -= len(raw)
	if len(raw) > limit {
		return "", fmt.Errorf("diagnostic command exceeded its output limit")
	}
	return raw, err
}
func (s *traceSession) node(ctx context.Context, node string) (model.NodeSnapshot, error) {
	if n, ok := s.metadata[node]; ok {
		return n, nil
	}
	n := model.NodeSnapshot{Name: node, CapturedAt: time.Now().UTC()}
	t, err := s.target(node, false)
	if err != nil {
		return n, err
	}
	for _, query := range []struct {
		command, db, columns, table string
		dest                        *[]model.Row
	}{
		{"ovn-sbctl", s.collector.SBDB, "_uuid,logical_port,datapath,type,options,mac", "Port_Binding", &n.Bindings},
		{"ovn-sbctl", s.collector.SBDB, "_uuid,external_ids,match,actions", "Logical_Flow", &n.LogicalFlows},
		{"ovn-nbctl", s.collector.NBDB, "_uuid,external_ids,action,match,direction,priority", "ACL", &n.ACLs},
	} {
		raw, e := s.exec(ctx, t, []string{query.command, "--timeout=10", "--db=" + query.db, "--format=json", "--columns=" + query.columns, "list", query.table}, 16<<20)
		if e != nil {
			return n, e
		}
		*query.dest, e = ovn.DecodeTable(raw)
		if e != nil {
			return n, e
		}
	}
	s.metadata[node] = n
	return n, nil
}

func (c *Collector) Simulate(ctx context.Context, inv model.Inventory, r trace.Request) (trace.Report, error) {
	report := trace.Report{At: time.Now().UTC(), Mode: "live", Request: r, Warnings: []string{
		"Simulation uses current OVN logical configuration and explicit conntrack assumptions. It sends no packets and does not validate hardware offload, tunnel delivery, or an application listener.",
		"Each conntrack lookup assumes the selected state. NAT state, existing sessions, and return traffic can take a different path. The return direction is not automatically tested.",
	}}
	if err := trace.Validate(&r); err != nil {
		return report, err
	}
	src, err := trace.Resolve(inv, r.Source)
	if err != nil {
		return report, err
	}
	r.Source = src.Endpoint
	dests := []trace.Backend{}
	originalDest := r.Destination
	if r.Service != nil {
		svc, e := trace.FindService(inv, *r.Service)
		if e != nil {
			return report, e
		}
		slices, e := c.Client.Core.DiscoveryV1().EndpointSlices(svc.Namespace).List(ctx, meta.ListOptions{LabelSelector: "kubernetes.io/service-name=" + svc.Name})
		if e != nil {
			return report, fmt.Errorf("read Service backends: %w", e)
		}
		service, e := trace.ServiceBackends(inv, svc, slices.Items, r)
		report.Service = &service
		if e != nil {
			return report, e
		}
		dests = service.Backends
		if len(dests) == 0 {
			return report, fmt.Errorf("no eligible ready pod backends for this Service and source; inspect EndpointSlices and readiness")
		}
		if r.Destination.UID != "" {
			dests = nil
			for _, b := range service.Backends {
				if b.Endpoint.UID == r.Destination.UID && b.Endpoint.IP == r.Destination.IP {
					dests = append(dests, b)
				}
			}
			if len(dests) != 1 {
				return report, fmt.Errorf("selected backend is no longer eligible")
			}
		} else if !r.AllBackends {
			dests = dests[:1]
			report.Warnings = append(report.Warnings, "One ready backend was chosen deterministically by pod name. This does not predict the backend a live connection will select.")
		}
		if len(dests) > trace.MaxBackends {
			report.Warnings = append(report.Warnings, fmt.Sprintf("Showing the first %d of %d eligible backends.", trace.MaxBackends, len(dests)))
			dests = dests[:trace.MaxBackends]
		}
		family, _ := netip.ParseAddr(src.Endpoint.IP)
		vip := ""
		for _, ip := range service.IPs {
			a, e := netip.ParseAddr(ip)
			if e == nil && a.Is4() == family.Is4() {
				vip = ip
				break
			}
		}
		if vip == "" {
			return report, fmt.Errorf("Service has no VIP in the source IP family")
		}
		r.Destination = model.Endpoint{IP: vip, Network: src.Endpoint.Network, Port: r.Port}
	} else if r.Destination.UID != "" {
		dst, e := trace.Resolve(inv, r.Destination)
		if e != nil {
			return report, e
		}
		if dst.Endpoint.Network != src.Endpoint.Network {
			return report, fmt.Errorf("select endpoints on the same network; connected-network tracing is not supported yet")
		}
		dst.Endpoint.Port = r.Port
		r.Destination = dst.Endpoint
		dests = append(dests, trace.Backend{Endpoint: dst.Endpoint, Port: r.Port})
	} else {
		ip, e := netip.ParseAddr(r.Destination.IP)
		if e != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() {
			return report, fmt.Errorf("enter a unicast destination IP or select a pod")
		}
		r.Destination = model.Endpoint{IP: ip.String(), Network: src.Endpoint.Network, Port: r.Port}
		dests = append(dests, trace.Backend{Endpoint: r.Destination, Port: r.Port})
	}
	from, _ := netip.ParseAddr(r.Source.IP)
	to, _ := netip.ParseAddr(r.Destination.IP)
	if from.Is4() != to.Is4() {
		return report, fmt.Errorf("source and destination must use the same IP family")
	}
	report.Request = r
	session := &traceSession{remaining: 32 << 20, collector: c, inv: inv, metadata: map[string]model.NodeSnapshot{}}
	n, err := session.node(ctx, src.Node)
	if err != nil {
		return report, err
	}
	mac, err := trace.NextHopMAC(inv, src, r.Destination, n.Bindings)
	if err != nil {
		return report, err
	}
	t, _ := session.target(src.Node, false)
	for _, b := range dests {
		result := trace.Result{Destination: b.Endpoint}
		target := ""
		if b.Endpoint.UID != "" {
			a, e := trace.Resolve(inv, b.Endpoint)
			if e != nil {
				return report, e
			}
			target = a.LogicalPort
		}
		backend := ""
		if r.Service != nil {
			backend = net.JoinHostPort(b.Endpoint.IP, strconv.Itoa(b.Port))
		}
		raw, e := session.exec(ctx, t, trace.LogicalArgs(c.SBDB, trace.LogicalFlow(r, src.LogicalPort, src.MAC, mac), r.State, backend), 2<<20)
		if e != nil {
			result.Status = "unknown"
			result.Warnings = append(result.Warnings, e.Error())
			report.Results = append(report.Results, result)
			continue
		}
		segment := trace.Parse(raw, target, n, inv)
		if r.OVS {
			ovsTarget, e := session.target(src.Node, true)
			if e == nil {
				var rawInterfaces string
				rawInterfaces, e = session.exec(ctx, ovsTarget, []string{"ovs-vsctl", "--timeout=10", "--format=json", "--columns=ofport,external_ids", "list", "Interface"}, 2<<20)
				if e == nil {
					var rows []model.Row
					rows, e = ovn.DecodeTable(rawInterfaces)
					port := 0
					for _, row := range rows {
						ext := ovn.Map(row["external_ids"])
						if ovn.Str(ext["iface-id"]) == src.LogicalPort {
							port, _ = strconv.Atoi(ovn.Str(row["ofport"]))
						}
					}
					if e == nil && port > 0 {
						segment.OVS, e = session.exec(ctx, ovsTarget, trace.OVSArgs(r, port, src.MAC, mac), 2<<20)
					} else if e == nil {
						e = fmt.Errorf("source OpenFlow port is unavailable")
					}
				}
			}
			if e != nil {
				segment.Warnings = append(segment.Warnings, "OVS evidence: "+e.Error())
			}
			if r.Service != nil {
				segment.Warnings = append(segment.Warnings, "OVS evidence uses the Service VIP but does not pin its backend; compare it independently of the selected logical backend.")
			}
		}
		result.Segments = append(result.Segments, segment)
		result.Status = segment.Status
		if segment.Status == "handoff" && b.Endpoint.Node != "" && b.Endpoint.Node != src.Node {
			remote, remoteErr := session.node(ctx, b.Endpoint.Node)
			if remoteErr == nil {
				var flow string
				flow, remoteErr = trace.ContinueFlow(r, src, segment, remote)
				if remoteErr == nil {
					remoteTarget, targetErr := session.target(b.Endpoint.Node, false)
					remoteErr = targetErr
					if remoteErr == nil {
						var remoteRaw string
						remoteRaw, remoteErr = session.exec(ctx, remoteTarget, trace.LogicalArgs(c.SBDB, flow, r.State, ""), 2<<20)
						if remoteErr == nil {
							receiving := trace.Parse(remoteRaw, target, remote, inv)
							receiving.Warnings = append(receiving.Warnings, "This segment assumes the source packet reaches the remote zone unchanged. Tunnel delivery has not been tested.")
							result.Segments = append(result.Segments, receiving)
							result.Status = receiving.Status
						}
					}
				}
			}
			if remoteErr != nil {
				result.Warnings = append(result.Warnings, "Remote path incomplete: "+remoteErr.Error())
			}
		}
		report.Results = append(report.Results, result)
	}
	if originalDest.UID != "" && r.Service != nil {
		report.Request.Destination = originalDest
	}
	return report, nil
}

func (c *Client) TraceProbe(ctx context.Context, inv model.Inventory, r trace.Request) (trace.CheckResult, error) {
	result := trace.CheckResult{At: time.Now().UTC()}
	if err := trace.Validate(&r); err != nil {
		return result, err
	}
	if r.Protocol != "TCP" || r.State != "new" {
		return result, fmt.Errorf("a real TCP test opens a new connection; select New and TCP")
	}
	src, err := trace.Resolve(inv, r.Source)
	if err != nil {
		return result, err
	}
	if !src.Primary {
		return result, fmt.Errorf("real tests currently use the pod's primary network only")
	}
	dest := r.Destination
	kind := "EgressFirewall"
	if r.Service != nil {
		if src.Endpoint.Network != "default" {
			return result, fmt.Errorf("Service tests currently support the primary cluster default network")
		}
		svc, e := trace.FindService(inv, *r.Service)
		if e != nil {
			return result, e
		}
		found := false
		for _, p := range svc.Spec.Ports {
			if int(p.Port) == r.Port && p.Protocol == core.ProtocolTCP {
				found = true
			}
		}
		if !found {
			return result, fmt.Errorf("Service does not expose this TCP port")
		}
		dest = model.Endpoint{IP: svc.Spec.ClusterIP}
		family, _ := netip.ParseAddr(src.Endpoint.IP)
		for _, ip := range svc.Spec.ClusterIPs {
			a, e := netip.ParseAddr(ip)
			if e == nil && a.Is4() == family.Is4() {
				dest.IP = ip
				break
			}
		}
	} else if dest.UID != "" {
		d, e := trace.Resolve(inv, dest)
		if e != nil {
			return result, e
		}
		if d.Endpoint.Network != src.Endpoint.Network {
			return result, fmt.Errorf("source and destination networks differ")
		}
		dest = d.Endpoint
		kind = "NetworkPolicy"
	}
	ip, e := netip.ParseAddr(dest.IP)
	from, _ := netip.ParseAddr(src.Endpoint.IP)
	if e != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.Is4() != from.Is4() {
		return result, fmt.Errorf("choose a destination IP in the source address family")
	}
	message, err := c.Probe(ctx, policy.Intent{Kind: kind, Source: src.Endpoint, Destination: dest, Protocol: "TCP", Port: r.Port})
	result.Success = err == nil
	result.Summary = message
	if err != nil {
		result.Summary = "TCP connection failed: " + err.Error()
	}
	return result, nil
}

func (c *Client) TraceDNS(ctx context.Context, inv model.Inventory, r trace.Check) (trace.CheckResult, error) {
	result := trace.CheckResult{At: time.Now().UTC()}
	src, err := trace.Resolve(inv, r.Source)
	if err != nil {
		return result, err
	}
	if !src.Primary {
		return result, fmt.Errorf("DNS checks currently use the pod's primary network only")
	}
	name := strings.TrimSuffix(r.Name, ".")
	if r.Service != nil {
		svc, e := trace.FindService(inv, *r.Service)
		if e != nil {
			return result, e
		}
		name = svc.Name + "." + svc.Namespace + ".svc"
	}
	if name == "" || len(validation.IsDNS1123Subdomain(name)) != 0 {
		return result, fmt.Errorf("enter a valid DNS hostname")
	}
	pod, e := c.Core.CoreV1().Pods(src.Endpoint.Namespace).Get(ctx, src.Endpoint.Pod, meta.GetOptions{})
	if e != nil {
		return result, e
	}
	if string(pod.UID) != src.Endpoint.UID || len(pod.Spec.Containers) == 0 {
		return result, fmt.Errorf("source pod changed")
	}
	t := Target{pod.Namespace, pod.Name, pod.Spec.Containers[0].Name}
	call, cancel := context.WithTimeout(ctx, 8*time.Second)
	resolv, e := c.execBounded(call, t, []string{"cat", "/etc/resolv.conf"}, nil, 64<<10)
	cancel()
	if e != nil {
		return result, fmt.Errorf("read source pod DNS configuration: %w", e)
	}
	if r.Service != nil {
		domain := ""
		for _, line := range strings.Split(resolv, "\n") {
			f := strings.Fields(line)
			if len(f) > 1 && f[0] == "search" {
				for _, suffix := range f[1:] {
					if _, d, ok := strings.Cut(suffix, "svc."); ok && (strings.HasPrefix(suffix, "svc.") || strings.Contains(suffix, ".svc.")) {
						domain = d
						break
					}
				}
			}
		}
		if domain == "" || len(validation.IsDNS1123Subdomain(domain)) != 0 {
			return result, fmt.Errorf("cannot infer the cluster DNS domain from the source pod")
		}
		name += "." + domain
	}
	name += "."
	result.Output = "Source /etc/resolv.conf:\n" + resolv + "\nQuery: " + name + "\n"
	commands := [][]string{{"getent", "ahosts", name}, {"nslookup", name}, {"python3", "-c", "import socket,sys; print('\\n'.join(sorted({x[4][0] for x in socket.getaddrinfo(sys.argv[1],None)})))", name}}
	for _, args := range commands {
		call, cancel := context.WithTimeout(ctx, 8*time.Second)
		out, e := c.execBounded(call, t, args, nil, 64<<10)
		cancel()
		if e != nil && missingExecutable(e) {
			continue
		}
		result.Success = e == nil && strings.TrimSpace(out) != ""
		result.Output += out
		if result.Success {
			result.Summary = "DNS lookup succeeded from the selected source pod."
		} else {
			result.Summary = "DNS lookup failed from the selected source pod."
			if e != nil {
				result.Output += e.Error()
			}
		}
		return result, nil
	}
	return result, fmt.Errorf("the source container has none of getent, nslookup or python3; no tools were installed")
}
func missingExecutable(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "executable file not found") || strings.Contains(s, "no such file or directory") || strings.Contains(s, "executable not found")
}
