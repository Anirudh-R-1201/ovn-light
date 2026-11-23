"""Budget checks use mocked Docker; these tests never start a cluster."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import call, patch

spec = importlib.util.spec_from_file_location('budget', Path(__file__).with_name('local-kind-budget.py'))
budget = importlib.util.module_from_spec(spec)
spec.loader.exec_module(budget)


class LocalBudgetTest(unittest.TestCase):
    def test_existing_nodes_block_creation_without_checking_memory(self):
        with patch.object(budget, 'docker', return_value='old-control-plane') as docker, \
                patch.object(budget, 'require_memory') as memory:
            with self.assertRaisesRegex(RuntimeError, 'already exist'):
                budget.check_create()
            self.assertIn('-a', docker.call_args.args)
            memory.assert_not_called()

    def test_creation_requires_headroom(self):
        with patch.object(budget, 'docker', return_value=''), \
                patch.object(budget, 'require_memory') as memory:
            budget.check_create()
            memory.assert_called_once_with(12 * budget.GIB)

    def test_low_available_memory_refuses_work(self):
        with patch.object(Path, 'read_text', return_value='MemTotal: 67108864 kB\nMemAvailable: 1048576 kB\n'):
            with self.assertRaisesRegex(RuntimeError, 'Only 1.0 GiB available'):
                budget.require_memory(4 * budget.GIB)

    def test_more_than_two_nodes_are_not_modified(self):
        with patch.object(budget, 'require_memory'), patch.object(budget, 'docker', return_value='a\nb\nc') as docker:
            with self.assertRaisesRegex(RuntimeError, 'has 3'):
                budget.limit_cluster('demo')
            self.assertEqual(docker.call_count, 1)

    def test_caps_selected_nodes_and_preserves_lower_limit(self):
        nodes = [{'Id': ident, 'HostConfig': {'Memory': memory},
                  'Config': {'Labels': {'io.x-k8s.kind.cluster': 'demo'}}}
                 for ident, memory in [('a', 0), ('b', 2 * budget.GIB)]]
        with patch.object(budget, 'require_memory'), \
                patch.object(budget, 'docker', side_effect=['a\nb', json.dumps(nodes), '', '']) as docker:
            budget.limit_cluster('demo')
            self.assertEqual(docker.call_args_list[-2:], [
                call('update', '--memory=4294967296', '--memory-swap=4294967296', 'a'),
                call('update', '--memory=2147483648', '--memory-swap=2147483648', 'b')])

    def test_wrong_cluster_is_not_modified(self):
        nodes = [{'Config': {'Labels': {'io.x-k8s.kind.cluster': 'other'}}}]
        with patch.object(budget, 'require_memory'), \
                patch.object(budget, 'docker', side_effect=['a', json.dumps(nodes)]) as docker:
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                budget.limit_cluster('demo')
            self.assertEqual(docker.call_count, 2)

    def test_only_github_hosted_runners_skip_guard(self):
        with patch('sys.argv', ['budget', 'check-create']), \
                patch.dict('os.environ', {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted'}), \
                patch.object(budget, 'check_create') as check:
            budget.main()
            check.assert_called_once()
        with patch('sys.argv', ['budget', 'check-create']), \
                patch.dict('os.environ', {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted'}), \
                patch.object(budget, 'check_create') as check:
            budget.main()
            check.assert_not_called()


if __name__ == '__main__':
    unittest.main()
