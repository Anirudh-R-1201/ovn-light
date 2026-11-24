"""Run only TFT's cross-node pod IP case. Kubernetes owns the lifetime of its two pods."""
import ipaddress
import json
import re
import os
from pathlib import Path
import subprocess
import sys

from testConfig import ConfigDescriptor, TestConfig
from testSettings import TestSettings
from tftbase import TargetAccessMode
from trafficFlowTests import TrafficFlowTests

NS = "ovn-light-tests"
SA = "/var/run/secrets/kubernetes.io/serviceaccount"
RUN = os.environ["RUN_ID"]
IMAGE = os.environ["TEST_IMAGE"]


def kubectl(*args, obj=None):
    out = subprocess.run(["kubectl", "-n", NS, *args], input=json.dumps(obj) if obj else None,
                         text=True, capture_output=True, timeout=100)
    if out.returncode:
        raise RuntimeError(out.stderr.strip()[-500:])
    return out.stdout


def start_pod(name, role, node):
    owner = {"apiVersion": "batch/v1", "kind": "Job", "name": "cross-node-tcp",
             "uid": os.environ["JOB_UID"], "controller": False}
    resources = {"requests": {"cpu": "10m", "memory": "8Mi"}, "limits": {"cpu": "200m", "memory": "48Mi"}}
    if device := os.environ.get("DEVICE_RESOURCE"):
        for size in resources.values():
            size[device] = "1"
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": name, "labels": {"ovn-light.io/run": RUN, "ovn-light.io/role": role},
                        "ownerReferences": [owner]},
           "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never", "activeDeadlineSeconds": 320,
                    "terminationGracePeriodSeconds": 1, "affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {
                        "nodeSelectorTerms": [{"matchFields": [{"key": "metadata.name", "operator": "In", "values": [node]}]}]}}},
                    "tolerations": [{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}],
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "8Mi"}}],
                    "containers": [{"volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}], "name": "tft", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                                    "command": ["sleep", "320"], "resources": resources,
                                    "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                                        "capabilities": {"drop": ["ALL"]}}}]}}
    kubectl("create", "-f", "-", obj=pod)


def execute():
    kubeconfig = {"apiVersion": "v1", "kind": "Config", "current-context": "run",
                  "contexts": [{"name": "run", "context": {"cluster": "cluster", "user": "runner", "namespace": NS}}],
                  "clusters": [{"name": "cluster", "cluster": {"server": "https://kubernetes.default.svc",
                                "certificate-authority": SA + "/ca.crt"}}],
                  "users": [{"name": "runner", "user": {"tokenFile": SA + "/token"}}]}
    path = "/tmp/kubeconfig"
    Path(path).write_text(json.dumps(kubeconfig))
    os.environ["KUBECONFIG"] = path
    src, dst = os.environ["SOURCE_NODE"], os.environ["DESTINATION_NODE"]
    connection = {"name": "tcp", "type": "iperf-tcp", "instances": 1, "reverse": False,
                  "client": [{"name": src, "args": "-b 1M -P 1 --cport 35201"}],
                  "server": [{"name": dst, "pod_port": 5201}]}
    cfg = {"tft": [{"name": "cross-node", "namespace": NS, "duration": 120, "pre_provision": True,
                    "test_cases": "POD_TO_POD_DIFF_NODE", "connections": [connection]}]}
    tc = TestConfig(full_config=cfg, kubeconfigs=(path, None))
    descriptor = next(next(next(ConfigDescriptor(tc).describe_all_tft()).describe_all_test_cases()).describe_all_connections())
    settings = TestSettings(cfg_descr=descriptor, instance_index=0, reverse=False, target_access_mode=TargetAccessMode.IP)
    server, client = settings.cfg_descr.get_connection().test_type_handler.create_server_client(settings)
    start_pod(server.pod_name, "server", dst)
    start_pod(client.pod_name, "client", src)
    kubectl("wait", "--for=condition=Ready", "pod/" + client.pod_name, "pod/" + server.pod_name, "--timeout=85s")
    expected_ips = []
    for name in [client.pod_name, server.pod_name]:
        pod = json.loads(kubectl("get", "pod", name, "-o", "json"))
        nets = json.loads(pod["metadata"]["annotations"]["k8s.ovn.org/pod-networks"])
        default = nets.get("default", {})
        addresses = [str(ipaddress.ip_interface(ip).ip) for ip in default.get("ip_addresses", [])]
        if (pod["status"]["podIP"] not in addresses or default.get("role", "primary") != "primary"
                or any(n.get("role") == "primary" for key, n in nets.items() if key != "default")):
            raise RuntimeError("Test namespace requires the OVN default network as its primary attachment.")
        expected_ips.append(ipaddress.ip_address(pod["status"]["podIP"]))
    # The full suite also provisions namespaces and cleans cluster-wide resources.
    # This entry point runs one case using only our two pre-provisioned pods.
    result = TrafficFlowTests()._run_test_case_instance(descriptor, 0, TargetAccessMode.IP).flow_test
    if not result.success:
        message = result.msg or "iperf failed"
        match = re.search(r'"error":(?:\s|\\t)*"([^"]+)"', message)
        raise RuntimeError(match.group(1) if match else message[:450])
    stats = result.result
    connected = stats["start"]["connected"]
    if len(connected) != 1 or connected[0]["local_port"] != 35201 or connected[0]["remote_port"] != 5201:
        raise RuntimeError("Unexpected data stream tuple in iperf output")
    actual_ips = [ipaddress.ip_address(connected[0][key]) for key in ("local_host", "remote_host")]
    if actual_ips != expected_ips:
        raise RuntimeError("The data stream addresses differ from the selected test pod addresses")
    received = stats["end"]["sum_received"]
    if received["bytes"] <= 0:
        raise RuntimeError("Receiver reported no data")
    return {"delivered": True, "bytes": received["bytes"], "bps": received["bits_per_second"],
            "sourceIP": connected[0]["local_host"], "destinationIP": connected[0]["remote_host"]}


if __name__ == "__main__":
    try:
        result = execute()
    except Exception as exc:
        import traceback
        traceback.print_exc()
        result = {"delivered": False, "error": str(exc)[-600:]}
    Path("/dev/termination-log").write_text(json.dumps(result))
    sys.exit(0 if result["delivered"] else 1)
