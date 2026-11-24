#!/usr/bin/env python3
"""Run paced TCP checks and reopen them through the dashboard API after restart."""
import argparse
from datetime import datetime
import json
from pathlib import Path

from e2e import Harness


CASE = 'POD_TO_POD_DIFF_NODE'
# Each run sends at 1 Mbit/s. The evaluator accepts its minimum in Gbit/s.
CHECKS = [('pass', 0.0005, True), ('below-minimum', 0.002, False)]


def run_checks(h, directory):
    h.eventually(h.daemonset_reports, timeout=240)
    nodes = [n['name'] for n in h.api('traffic-test/options')['nodes']]
    assert len(set(nodes)) == len(nodes) == 2, f'Expected two eligible KIND nodes, got {nodes}'
    for name, minimum, passed in CHECKS:
        source, destination = nodes if passed else reversed(nodes)
        request = dict(test='iperf-tcp', case=CASE, network='default', senderMbps=1,
                       sourceNode=source, destinationNode=destination, minimumGbps=minimum)
        run_id = h.api('traffic-test', request)['run']['id']
        print(f'Started {run_id}: {source} → {destination}, minimum {minimum} Gbit/s', flush=True)

        def finished():
            run = h.api(f'traffic-test/runs/{run_id}')
            assert run.get('finished'), f'{run_id} is {run["phase"]}'
            return run

        run = h.eventually(finished, timeout=400)
        (directory / f'traffic-{name}.json').write_text(json.dumps(run, indent=2) + '\n')
        assert run['source']['node'] == source and run['destination']['node'] == destination, request
        check_result(run, minimum, passed)

        def cleaned_up():
            resources = h.get('-n', 'ovn-light-tests', 'jobs,pods', '-l', f'ovn-light.io/run={run_id}')
            assert not resources['items'], f'Waiting for {run_id} test resources to be removed'

        h.eventually(cleaned_up, timeout=90)


def check_result(run, minimum, passed):
    run_id = run['id']
    assert run['test'] == 'iperf-tcp' and run['case'] == CASE and run['senderMbps'] == 1, run_id
    traffic = run['traffic']
    assert traffic['delivered'] and traffic['bytes'] > 0, (run_id, traffic)
    evaluation = traffic['evaluation']
    assert evaluation['minimumGbps'] == run['minimumGbps'] == minimum, evaluation
    assert evaluation['passed'] is passed and run['phase'] == ('completed' if passed else 'failed'), evaluation
    measured = min(evaluation['rxGbps'], evaluation['txGbps'])
    assert measured > 0 and (measured >= minimum) == passed, evaluation

    expected = {run['source']['node'], run['destination']['node']}
    assert len(expected) == 2 and {n['node'] for n in run['nodes']} == expected, (run_id, expected)
    started, finished = (datetime.fromisoformat(run[key]) for key in ('started', 'finished'))
    for n in run['nodes']:
        flows = n.get('flows') or []
        assert any(f['status'] == 'software' and f['id'] and f['inPort'] and f['packets'] > 0
                   and 'actions:' in f['raw'] and started <= datetime.fromisoformat(f['at']) <= finished
                   for f in flows), f'{run_id}: missing captured software datapath flow on {n["node"]}'
        print(f'{run_id}: {run["phase"]}, {measured} Gbit/s; {n["node"]} has {len(flows)} flows', flush=True)


def verify_saved(h, directory):
    history = {r['id']: r for r in h.api('traffic-test/runs')}
    ids = set()
    for name, minimum, passed in CHECKS:
        original = json.loads((directory / f'traffic-{name}.json').read_text())
        run_id = original['id']
        assert run_id in history and run_id not in ids, f'Missing or duplicate saved run {run_id}'
        ids.add(run_id)
        saved = h.api(f'traffic-test/runs/{run_id}')
        check_result(saved, minimum, passed)
        assert history[run_id]['phase'] == saved['phase'] and saved == original, f'Run {run_id} changed after restart'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['run', 'verify'])
    parser.add_argument('--url', required=True)
    parser.add_argument('--token-file', required=True)
    parser.add_argument('--context', required=True)
    parser.add_argument('--kubeconfig')
    parser.add_argument('--artifacts', required=True, type=Path)
    args = parser.parse_args()
    if args.phase == 'run':
        run_checks(Harness(args), args.artifacts)
    else:
        verify_saved(Harness(args), args.artifacts)


if __name__ == '__main__':
    main()
