#!/usr/bin/env python3
"""Exercise OVN-Light's API against the disposable example workloads."""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request
import urllib.parse


class Harness:
    def __init__(self, args):
        self.args = args
        self.token = Path(args.token_file).read_text().strip()
        self.command = ['kubectl']
        if args.kubeconfig:
            self.command += ['--kubeconfig', args.kubeconfig]
        if args.context:
            self.command += ['--context', args.context]

    def api(self, path, data=None):
        request = urllib.request.Request(self.args.url + '/api/' + path,
            data=None if data is None else json.dumps(data).encode(),
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError(json.load(error).get('error', str(error))) from error

    def kubectl(self, *args):
        return subprocess.run(self.command + list(args), capture_output=True, text=True, timeout=45)

    def get(self, *args):
        result = self.kubectl('get', *args, '-o', 'json')
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def probe(self, source, dest, port=8080):
        return self.kubectl('-n', source['namespace'], 'exec', source['pod'], '--',
                            '/agnhost', 'connect', f"{dest['ip']}:{port}", '--timeout=2s')

    def connection(self, source, dest, allowed, routed=True, port=8080):
        result = self.probe(source, dest, port)
        if allowed:
            assert result.returncode == 0, (result.stdout, result.stderr)
        else:
            errors = ['timeout'] if routed else ['timeout', 'no route to host', 'network is unreachable']
            assert result.returncode != 0 and any(e in result.stderr.lower() for e in errors), (
                'Expected network denial, not a broken probe or a refused TCP listener', result.stdout, result.stderr)

    def eventually(self, check, timeout=90):
        deadline = time.monotonic() + timeout
        while True:
            try:
                return check()
            except (AssertionError, RuntimeError) as error:
                if time.monotonic() >= deadline:
                    raise AssertionError(f'Timed out waiting for convergence: {error}') from error
                time.sleep(2)

    def endpoints(self, namespace, role):
        state = self.api('refresh', {})
        assert state['mode'] == 'live' and state['writesEnabled'], 'Requires a live writable test deployment'
        pods = [p for p in state['pods'] if p['namespace'] == namespace and p.get('role') == role]
        sources = [p for p in pods if p['pod'] == 'client' or p['pod'].startswith('client-')]
        destinations = [p for p in pods if p['pod'] == 'server' or p['pod'].startswith('server-')]
        assert len(sources) == len(destinations) == 1, ('Missing or ambiguous test attachments', pods)
        return sources[0], destinations[0]

    def finding(self, source, dest):
        # Datapath entries expire; produce traffic immediately before each poll.
        self.connection(source, dest, False)
        state = self.api('refresh', {})
        matches = [f for f in state['findings']
                   if (f['source'].get('uid') == source['uid'] or self.args.lane == 'topology' and not f['source'].get('uid') and f['destination'].get('uid') == dest['uid'])
                   and (f['source'].get('network') == source['network'] or self.args.lane == 'topology' and f['destination'].get('network') == source['network'])
                   and f['destination'].get('uid') in (None, '', dest['uid'])
                   and any(c['type'] == 'NetpolNamespace' for c in (f['causes'] or []))]
        assert matches, 'No attributed policy drop for the selected source and network'
        return matches[0]

    def baseline(self, namespace):
        objects = self.get('networkpolicy,multi-networkpolicy', '-n', namespace)['items']
        return {o['metadata']['uid']: (o['kind'], o['metadata']['name'],
                o['metadata'].get('annotations', {}), o['spec']) for o in objects}

    def absent(self, obj):
        resource = {'NetworkPolicy': 'networkpolicy', 'MultiNetworkPolicy': 'multi-networkpolicy',
                    'ClusterNetworkConnect': 'clusternetworkconnect'}[obj['kind']]
        args = [resource, obj['metadata']['name'], '--ignore-not-found', '-o', 'name']
        if obj['metadata'].get('namespace'):
            args += ['-n', obj['metadata']['namespace']]
        result = self.kubectl('get', *args)
        assert result.returncode == 0 and not result.stdout.strip(), ('Unexpected object', result.stdout, result.stderr)

    @contextmanager
    def applied(self, plan):
        for obj in plan['objects']:
            self.absent(obj)
        try:
            assert self.api(f"plans/{plan['id']}/apply", {})['status'] == 'applied'
            yield
        finally:
            current = next(p for p in self.api('plans') if p['id'] == plan['id'])
            if current.get('applied'):
                assert self.api(f"plans/{plan['id']}/rollback", {})['status'] == 'rolled-back'
        for obj in plan['objects']:
            self.absent(obj)

    def policy(self, namespace, role):
        source, dest = self.eventually(lambda: self.endpoints(namespace, role))
        before = self.baseline(namespace)
        finding = self.eventually(lambda: self.finding(source, dest))
        plan = self.api('plans', {'kind': 'Policy', 'findingID': finding['id'], 'source': source,
                                'destination': dest, 'protocol': 'TCP', 'port': 8080})
        kind = 'MultiNetworkPolicy' if role == 'secondary' else 'NetworkPolicy'
        assert plan['kind'] == kind and plan['scope']['role'] == role
        assert plan['scope']['network'] == source['network'] == dest['network']
        assert len(plan['objects']) == 1, 'Expected only the missing ingress allowance'
        obj = plan['objects'][0]
        assert obj['kind'] == kind and obj['metadata']['namespace'] == namespace
        rule = obj['spec']['ingress'][0]
        assert rule['ports'] == [{'protocol': 'TCP', 'port': 8080}]
        assert rule['from'][0]['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'] == namespace
        assert rule['from'][0]['podSelector']['matchLabels']['app'] == 'client'
        assert obj['spec']['podSelector']['matchLabels']['app'] == 'server'
        primary = None
        if role == 'secondary':
            assert obj['metadata']['annotations']['k8s.v1.cni.cncf.io/policy-for'] == dest['nad']
            _, primary = self.endpoints(namespace, 'primary')
            self.connection(source, primary, False)
        else:
            assert 'k8s.v1.cni.cncf.io/policy-for' not in obj['metadata']['annotations']
        print(f'{namespace}: observed policy drop → inferred {kind} on {source["network"]}; dry-run left no object.', flush=True)
        with self.applied(plan):
            self.eventually(lambda: self.connection(source, dest, True))
            # An overbroad allowance would reach the closed listener and receive
            # RST. Timeout proves this other port still encounters policy denial.
            self.connection(source, dest, False, port=8081)
            if primary:
                self.connection(source, primary, False)
            else:
                verified = self.api(f"plans/{plan['id']}/verify", {})
                assert verified['status'] == 'verified'
            if self.args.lane == 'topology':
                self.topology(source, dest)
            print(f'{namespace}: API apply opened TCP/8080; other ports' +
                  (' and the primary network' if primary else '') + ' remain denied.', flush=True)
        self.eventually(lambda: self.connection(source, dest, False))
        assert self.baseline(namespace) == before, 'Rollback changed a pre-existing policy or left an allowance'
        print(f'{namespace}: API rollback restored denial and preserved the original policies.', flush=True)

    def topology(self, source, dest):
        assert source['node'] != dest['node'], 'Topology fixture must exercise two nodes'
        query = urllib.parse.urlencode({'network': source['network'], 'level': 'pods', 'limit': 100})
        def observed():
            self.api('refresh', {})
            graph = self.api('topology?' + query)
            members = []
            for edge in graph['edges']:
                nodes = {n['id']: n for n in graph['nodes']}
                a, b = nodes[edge['source']].get('endpoint', {}), nodes[edge['destination']].get('endpoint', {})
                if a.get('uid') == source['uid'] and b.get('uid') == dest['uid']:
                    details = self.api('topology?' + query + '&edge=' + edge['id'])
                    members.extend(details['edges'][0]['members'])
            assert members, 'No cross-node pod traffic in topology'
            node_graph = self.api('topology?' + urllib.parse.urlencode({'network': source['network'], 'level': 'nodes', 'limit': 100}))
            node_map = {n['id']: n for n in node_graph['nodes']}
            links = [e for e in node_graph['edges'] if node_map[e['source']]['node'] == source['node'] and node_map[e['destination']]['node'] == dest['node']]
            assert any(e.get('sourceBytesPerSecond', 0) > 0 and e.get('receiverBytesPerSecond', 0) > 0 for e in links), 'Node-level source/receiver rates are not ready'
            assert any(c['received']['packets'] > 0 for c in members), 'Receiver observation is missing'
            counters = [o['counterID'] for c in members for o in c.get('observations', [])]
            assert len(counters) == len(set(counters)), 'A recirculation counter was duplicated'
            return graph
        graph = self.eventually(observed)
        other = self.api('topology?network=nonexistent-network')
        assert not other['edges'], 'Network filter leaked traffic'
        assert graph['hiddenEdges'] == 0, 'Small fixture unexpectedly truncated'
        print('Topology: cross-node rates, resolved receiver pod identities, counter deduplication, and network filtering verified.', flush=True)

    def connect(self):
        source, _ = self.endpoints('ovn-light-red', 'primary')
        destinations = [p for p in self.api('refresh', {})['pods'] if p['namespace'] == 'ovn-light-blue'
                        and p['pod'] == 'server' and p.get('role') == 'primary']
        assert len(destinations) == 1, 'Missing or ambiguous blue primary attachment'
        dest = destinations[0]
        self.connection(source, dest, False, routed=False)
        plan = self.api('plans', {'kind': 'ClusterNetworkConnect',
            'networks': [source['network'], dest['network']], 'connectCIDR': '100.100.0.0/16', 'networkPrefix': 24})
        assert len(plan['objects']) == 1 and plan['objects'][0]['kind'] == 'ClusterNetworkConnect'
        with self.applied(plan):
            def accepted():
                obj = self.get('clusternetworkconnect', plan['objects'][0]['metadata']['name'])
                assert any(c['type'] == 'Accepted' and c['status'] == 'True'
                           for c in obj.get('status', {}).get('conditions', [])), obj.get('status')
            self.eventually(accepted)
            self.eventually(lambda: self.connection(source, dest, True))
            print('UDN connect: API proposal/apply accepted; actual cross-UDN TCP/8080 succeeded.', flush=True)
        self.eventually(lambda: self.connection(source, dest, False, routed=False))
        print('UDN connect: API rollback restored network separation.', flush=True)

    def firewall(self):
        namespace = 'ovn-light-egress'
        state = self.api('refresh', {})
        assert state['mode'] == 'live' and state['writesEnabled']
        source = next(p for p in state['pods'] if p['namespace'] == namespace and p['pod'] == 'client' and p['network'] == 'default')
        assert self.args.external_ip, 'Provide the disposable external listener IP'
        dest = {'ip': self.args.external_ip, 'network': 'default'}
        before = self.get('egressfirewall', 'default', '-n', namespace)
        def observed():
            self.connection(source, dest, False)
            state = self.api('refresh', {})
            matches = [f for f in state['findings'] if f['source'].get('uid') == source['uid']
                       and any(c['type'] == 'EgressFirewall' and c['namespace'] == namespace and c['rule'] == '1' for c in (f['causes'] or []))]
            assert matches, 'No drop attributed to the existing EgressFirewall deny rule'
            return matches[0]
        finding = self.eventually(observed)
        plan = self.api('plans', {'kind': 'EgressFirewall', 'findingID': finding['id'], 'source': source,
                    'destination': dest, 'protocol': 'TCP', 'port': 8080})
        assert plan['firewallChange']['index'] == 1 and plan['firewallChange']['uid'] == before['metadata']['uid']
        assert plan['scope']['policyKind'] == 'EgressFirewall'
        expected = {'type': 'Allow', 'to': {'cidrSelector': dest['ip'] + '/32'}, 'ports': [{'protocol': 'TCP', 'port': 8080}]}
        assert plan['objects'][0]['spec']['egress'] == [before['spec']['egress'][0], expected, before['spec']['egress'][1]]
        assert self.get('egressfirewall', 'default', '-n', namespace)['spec'] == before['spec'], 'Dry-run changed the firewall'
        print('EgressFirewall: observed deny ACL and rule index → reviewed namespace-wide /32 TCP exception.', flush=True)
        try:
            assert self.api(f"plans/{plan['id']}/apply", {})['status'] == 'applied'
            self.eventually(lambda: self.connection(source, dest, True))
            assert self.api(f"plans/{plan['id']}/verify", {})['status'] == 'verified'
            self.connection(source, dest, False, port=8081)
            print('EgressFirewall: inserted Allow before Deny; external TCP/8080 and API Verify succeed; TCP/8081 remains denied.', flush=True)
        finally:
            current = next(p for p in self.api('plans') if p['id'] == plan['id'])
            if current.get('applied'):
                assert self.api(f"plans/{plan['id']}/rollback", {})['status'] == 'rolled-back'
        self.eventually(lambda: self.connection(source, dest, False))
        restored = self.get('egressfirewall', 'default', '-n', namespace)
        assert restored['metadata']['uid'] == before['metadata']['uid'] and restored['spec'] == before['spec']
        print('EgressFirewall: rollback restored denial and preserved the existing firewall UID and ordered rules.', flush=True)

    def artifacts(self):
        if self.args.artifacts:
            directory = Path(self.args.artifacts)
            directory.mkdir(parents=True, exist_ok=True)
            for path in ['state', 'plans', 'topology']:
                try:
                    (directory / f'{path}.json').write_text(json.dumps(self.api(path), indent=2) + '\n')
                except Exception as error:
                    print(f'Could not save {path} diagnostics: {error}', flush=True)


def main(default_lane='cdn'):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=['cdn', 'udn', 'secondary', 'egress', 'topology'], default=default_lane)
    parser.add_argument('--url', default='http://127.0.0.1:8080')
    parser.add_argument('--token-file', required=True)
    parser.add_argument('--kubeconfig')
    parser.add_argument('--context')
    parser.add_argument('--artifacts')
    parser.add_argument('--external-ip', help='Disposable external listener for the EgressFirewall lane')
    args = parser.parse_args()
    harness = Harness(args)
    try:
        if args.lane == 'topology':
            harness.policy('ovn-light-topology', 'primary')
        elif args.lane == 'cdn':
            harness.policy('ovn-light-demo', 'primary')
        elif args.lane == 'udn':
            harness.policy('ovn-light-red', 'primary')
            harness.connect()
        elif args.lane == 'secondary':
            harness.policy('ovn-light-secondary', 'secondary')
        else:
            harness.firewall()
    finally:
        harness.artifacts()


if __name__ == '__main__':
    main()
