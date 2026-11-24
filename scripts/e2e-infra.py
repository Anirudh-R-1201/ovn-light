#!/usr/bin/env python3
"""Validate routing evidence against real OVN/FRR state in disposable KIND."""
import argparse
import json
import subprocess
import time
from e2e import Harness
from history_e2e import check_history


class Infra(Harness):
    namespace = 'ovn-light-infra'

    def apply(self, obj):
        result = subprocess.run(self.command + ['apply', '-f', '-'], input=json.dumps(obj),
                                capture_output=True, text=True, timeout=45)
        assert result.returncode == 0, result.stderr

    def checked(self, *args):
        result = self.kubectl(*args)
        assert result.returncode == 0, result.stderr
        return result.stdout

    def setup(self, *, same_node=False):
        nodes = sorted(n['metadata']['name'] for n in self.get('nodes')['items'])
        assert len(nodes) >= 2, 'Requires two nodes'
        self.nodes = nodes
        self.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': self.namespace}})
        for name, node in [('client', nodes[0]), ('server', nodes[0] if same_node else nodes[1])]:
            container = {'name': name, 'image': 'registry.k8s.io/e2e-test-images/agnhost:2.45'}
            if name == 'server':
                container['args'] = ['netexec', '--http-port=8080', '--udp-port=-1']
            else:
                container.update(command=['/bin/sh', '-c'], args=['sleep 3600'])
            self.apply({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name,
                        'namespace': self.namespace, 'labels': {'app': name}},
                        'spec': {'nodeName': node, 'tolerations': [{'operator': 'Exists'}], 'containers': [container]}})
        self.checked('-n', self.namespace, 'wait', 'pods', '--all', '--for=condition=Ready', '--timeout=120s')
        self.source, self.dest = self.eventually(lambda: self.endpoints(self.namespace, 'primary'))

    def admin_policy(self, kind):
        spec = {'subject': {'namespaces': {'matchLabels': {'kubernetes.io/metadata.name': self.namespace}}},
                'ingress': [{'name': 'block-client', 'action': 'Deny', 'from': [{'namespaces': {}}]}]}
        if kind == 'AdminNetworkPolicy':
            spec['priority'] = 7
        return {'apiVersion': 'policy.networking.k8s.io/v1alpha1', 'kind': kind,
                'metadata': {'name': 'ovn-light-guard' if kind == 'AdminNetworkPolicy' else 'default'}, 'spec': spec}

    def allow_policy(self):
        return {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                'metadata': {'name': 'allow-client', 'namespace': self.namespace},
                'spec': {'podSelector': {'matchLabels': {'app': 'server'}}, 'policyTypes': ['Ingress'],
                         'ingress': [{'from': [{'podSelector': {'matchLabels': {'app': 'client'}}}]}]}}

    def admin_drop(self, kind):
        self.connection(self.source, self.dest, False)
        state = self.api('refresh', {})
        found = [f for f in state['findings'] if any(c.get('type') == kind and c.get('admin', {}).get('ruleName') == 'block-client' for c in f.get('causes') or [])]
        assert found, f'No {kind} rule attribution'
        f = found[0]
        cause = next(c['admin'] for c in f['causes'] if c.get('type') == kind)
        assert cause['direction'] == 'Ingress' and cause['ruleIndex'] == 0 and not f['canRecommend'], f
        if kind == 'AdminNetworkPolicy':
            assert cause['priority'] == 7 and 'cannot override' in cause['explanation']
        return cause

    def admin(self):
        self.setup()
        self.eventually(lambda: self.connection(self.source, self.dest, True))
        policy = self.admin_policy('AdminNetworkPolicy')
        self.apply(policy)
        self.eventually(lambda: self.admin_drop('AdminNetworkPolicy'), timeout=180)
        self.apply(self.allow_policy())
        self.eventually(lambda: self.admin_drop('AdminNetworkPolicy'))
        policy['spec']['ingress'][0]['action'] = 'Pass'
        self.apply(policy)
        self.eventually(lambda: self.connection(self.source, self.dest, True))
        self.checked('delete', 'adminnetworkpolicy', 'ovn-light-guard')
        self.checked('-n', self.namespace, 'delete', 'networkpolicy', 'allow-client')
        self.apply(self.admin_policy('BaselineAdminNetworkPolicy'))
        self.eventually(lambda: self.admin_drop('BaselineAdminNetworkPolicy'), timeout=180)
        self.apply(self.allow_policy())
        self.eventually(lambda: self.connection(self.source, self.dest, True))
        self.checked('delete', 'baselineadminnetworkpolicy', 'default')
        print('ANP/BANP: exact denying rule attributed; ANP overrides NP allow; Pass and BANP precedence verified.', flush=True)

    def history(self):
        check_history(self)

    def assign_egress(self):
        for node in self.nodes[:-1]:
            self.checked('label', 'node', node, 'k8s.ovn.org/egress-assignable-')
        self.checked('label', 'node', self.nodes[1], 'k8s.ovn.org/egress-assignable=', '--overwrite')
        self.apply({'apiVersion': 'k8s.ovn.org/v1', 'kind': 'EgressIP', 'metadata': {'name': 'ovn-light-egress'},
                    'spec': {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': self.namespace}},
                             'podSelector': {'matchLabels': {'app': 'client'}}, 'egressIPs': [self.args.egress_ip]}})
        self.eventually(lambda: self.assignment(self.nodes[1]), timeout=180)

    def assignment(self, node):
        items = self.get('egressip', 'ovn-light-egress').get('status', {}).get('items', [])
        assert items == [{'node': node, 'egressIP': self.args.egress_ip}], items

    def egress_evidence(self, node):
        self.api('refresh', {})
        report = self.api('routing?network=default')
        e = next(e for e in report['egress'] if e['name'] == 'ovn-light-egress')
        assert e['podCount'] == 1 and len(e['paths']) == 1, e
        path = e['paths'][0]
        assert path['assignment']['node'] == node and path['programmed'], path
        assert path['source']['uid'] == self.source['uid'], path
        return e

    def external_source(self):
        result = self.checked('-n', self.namespace, 'exec', 'client', '--', 'wget', '-q', '-T', '3', '-O', '-',
                              f'http://{self.args.external_ip}:8080/clientip')
        assert result.strip().split(':')[0] == self.args.egress_ip, result

    def egressip(self):
        self.setup()
        self.assign_egress()
        self.eventually(self.external_source, timeout=180)
        self.eventually(lambda: self.egress_evidence(self.nodes[1]), timeout=180)
        self.checked('label', 'node', self.nodes[0], 'k8s.ovn.org/egress-assignable=', '--overwrite')
        self.checked('label', 'node', self.nodes[1], 'k8s.ovn.org/egress-assignable-')
        self.eventually(lambda: self.assignment(self.nodes[0]), timeout=180)
        self.eventually(self.external_source, timeout=180)
        self.eventually(lambda: self.egress_evidence(self.nodes[0]), timeout=180)
        print('EgressIP: selectors, assigned node and programmed SNAT match actual external source IP, before and after failover.', flush=True)

    def routing(self):
        self.setup()
        self.assign_egress()
        self.apply({'apiVersion': 'frrk8s.metallb.io/v1beta1', 'kind': 'FRRConfiguration',
                    'metadata': {'name': 'ovn-light-template', 'namespace': 'frr-k8s-system', 'labels': {'ovn-light-test': 'true'}},
                    'spec': {'bgp': {'routers': [{'asn': 64512, 'neighbors': [{'asn': 64513,
                            'address': self.args.peer_ip, 'disableMP': True, 'toAdvertise': {'allowed': {'mode': 'all'}},
                            'toReceive': {'allowed': {'mode': 'all'}}}]}]}}})
        self.apply({'apiVersion': 'k8s.ovn.org/v1', 'kind': 'RouteAdvertisements',
                    'metadata': {'name': 'ovn-light-advertisements'},
                    'spec': {'nodeSelector': {}, 'networkSelectors': [{'networkSelectionType': 'DefaultNetwork'}],
                             'frrConfigurationSelector': {'matchLabels': {'ovn-light-test': 'true'}},
                             'advertisements': ['PodNetwork', 'EgressIP']}})
        def advertised():
            self.api('refresh', {})
            r = self.api('routing?network=default')
            peers = [p for p in r['peers'] if p['address'] == self.args.peer_ip]
            assert len(peers) == len(self.nodes), peers
            assert all(p['bgp'] == 'Established' and p['uplinks'] and p['stateSource'] == 'FRR runtime' for p in peers), peers
            prefixes = [prefix for p in peers for prefix in p['prefixes']]
            assert any(p['kind'] == 'PodNetwork' and p['state'] == 'Locally advertised' for p in prefixes), prefixes
            assert any(p['kind'] == 'EgressIP' and p['cidr'] == self.args.egress_ip + '/32' and p['state'] == 'Locally advertised' for p in prefixes), prefixes
            return peers
        peers = self.eventually(advertised, timeout=240)
        result = subprocess.run(['docker', 'exec', self.args.peer_container, 'vtysh', '-c', 'show bgp ipv4 unicast json'], capture_output=True, text=True, check=True)
        remote = json.loads(result.stdout)['routes']
        assert self.args.egress_ip + '/32' in remote, remote
        for p in peers:
            for prefix in p['prefixes']:
                if prefix['kind'] == 'PodNetwork':
                    assert prefix['cidr'] in remote, (prefix, remote)
        if self.api('routing')['capabilities']['uplinks'] == 'Available':
            self.apply({'apiVersion': 'k8s.ovn.org/v1alpha1', 'kind': 'Uplink', 'metadata': {'name': 'ovn-light-missing'},
                        'spec': {'nodeConfigs': [{'type': 'OVSBridge', 'nodeSelector': {}, 'hostInterfaceName': 'missing-uplink'}]}})
            def unresolved():
                self.api('refresh', {})
                r = self.api('routing')
                uplinks = [u for u in r['uplinks'] if u['name'] == 'ovn-light-missing']
                assert len(uplinks) == len(self.nodes) and all(u['ready'] == 'Not ready' for u in uplinks), uplinks
                assert any(i['kind'] == 'Uplink' for i in r['issues']), r['issues']
            self.eventually(unresolved, timeout=180)
        else:
            assert self.api('routing')['capabilities']['uplinks'] == 'API not available'
            print('Pinned OVN has no Uplink CRD; default gateway mapping tested, optional API absence reported.', flush=True)
        subprocess.run(['docker', 'stop', self.args.peer_container], check=True, capture_output=True)
        def down():
            self.api('refresh', {})
            r = self.api('routing')
            assert any(i['kind'] == 'BGP' and i['name'] == self.args.peer_ip for i in r['issues']), r['issues']
        self.eventually(down, timeout=180)
        print('Routing: live BGP sessions and default uplinks; PodNetwork/EgressIP prefixes received by external FRR; stopped peer reported.', flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lane', required=True, choices=['admin', 'egressip', 'routing', 'history'])
    p.add_argument('--url', required=True)
    p.add_argument('--context', required=True)
    p.add_argument('--token-file', required=True)
    p.add_argument('--artifacts')
    p.add_argument('--loki-url')
    p.add_argument('--egress-ip')
    p.add_argument('--external-ip')
    p.add_argument('--peer-ip')
    p.add_argument('--peer-container')
    args = p.parse_args()
    args.kubeconfig = None
    h = Infra(args)
    try:
        getattr(h, args.lane)()
    finally:
        h.artifacts()


if __name__ == '__main__':
    main()
