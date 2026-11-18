#!/usr/bin/env python3
"""Check QoS discovery, guarded value changes, OVN convergence and rollback."""
import argparse
import json
from pathlib import Path
from e2e import Harness


def run(h):
    namespace = 'ovn-light-qos'
    result = h.kubectl('apply', '-f', 'examples/qos.yaml')
    assert result.returncode == 0, result.stderr
    result = h.kubectl('-n', namespace, 'wait', 'pods', '--all', '--for=condition=Ready', '--timeout=180s')
    assert result.returncode == 0, result.stderr

    def inspect(kind, dscp):
        h.api('refresh', {})
        report = h.api('qos?namespace=' + namespace)
        matches = [p for p in report['policies'] if p['kind'] == kind]
        assert matches, report
        policy = matches[0]
        assert policy['targetCount'] == 1, policy
        assert policy['rules'][0]['dscp'] == dscp, policy
        assert policy['programs'], policy
        assert all(p['action']['dscp'] == dscp and p['state'] == 'OVN row observed'
                   for p in policy['programs']), policy
        return policy

    for kind, original, changed in [('NetworkQoS', 20, 24), ('EgressQoS', 10, 12)]:
        policy = h.eventually(lambda: inspect(kind, original), timeout=180)
        plan = h.api('qos/plans', {'kind': kind, 'namespace': namespace,
                                 'name': policy['name'], 'uid': policy['uid'], 'rule': 0, 'dscp': changed})
        assert plan['qosChange']['beforeSpec']['egress'][0]['dscp'] == original
        applied = False
        try:
            result = h.api('plans/' + plan['id'] + '/apply', {})
            applied = True
            assert result['status'] == 'applied', result
            h.eventually(lambda: inspect(kind, changed), timeout=180)
            # This checks ordinary delivery, not DSCP on the wire or policing loss.
            probe = h.kubectl('-n', namespace, 'exec', 'client', '--', '/agnhost',
                              'connect', 'server:8080', '--timeout=3s')
            assert probe.returncode == 0, probe.stderr
        finally:
            if applied:
                assert h.api('plans/' + plan['id'] + '/rollback', {})['status'] == 'rolled-back'
        h.eventually(lambda: inspect(kind, original), timeout=180)
        try:
            h.api('plans/' + plan['id'] + '/apply', {})
            raise AssertionError('Reused QoS proposal was accepted')
        except RuntimeError:
            pass
    assert h.api('qos?namespace=not-a-namespace')['policies'] == []
    report = h.api('qos?namespace=' + namespace)
    assert len(report['bandwidth']) == 2 and all(b['state'] == 'Configured rate observed' for b in report['bandwidth']), report['bandwidth']
    if h.args.artifacts:
        Path(h.args.artifacts).mkdir(parents=True, exist_ok=True)
        Path(h.args.artifacts, 'qos.json').write_text(json.dumps(report, indent=2))
    print('QoS passed: NetworkQoS/EgressQoS discovery, scoped review, apply, OVN values, delivery, rollback and bandwidth annotations')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ['url', 'token-file', 'context', 'kubeconfig', 'artifacts']:
        parser.add_argument('--' + name, required=name in ('url', 'token-file'))
    run(Harness(parser.parse_args()))
