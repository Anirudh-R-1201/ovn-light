"""Run one selected TFT case in a namespace of Job-owned test resources."""
import ipaddress
import json
import math
import os
import re
from pathlib import Path
import subprocess
import sys

from evalConfig import Config as EvaluationConfig
from evaluator import Evaluator
from testConfig import ConfigDescriptor, TestConfig
from testSettings import TestSettings
from tftbase import TargetAccessMode, TftResultBuilder

NS = "ovn-light-tests"
SA = "/var/run/secrets/kubernetes.io/serviceaccount"
RUN = os.environ["RUN_ID"]
IMAGE = os.environ["TEST_IMAGE"]
TEST = os.environ.get("TEST_TYPE", "iperf-tcp")
CASE = os.environ.get("TEST_CASE", "POD_TO_POD_DIFF_NODE")
IPERF = {"iperf-tcp", "iperf-udp"}


def kubectl(*args, obj=None):
    out = subprocess.run(["kubectl", "-n", NS, *args], input=json.dumps(obj) if obj else None,
                         text=True, capture_output=True, timeout=100)
    if out.returncode:
        raise RuntimeError(out.stderr.strip()[-500:])
    return out.stdout


def owner_reference():
    return {"apiVersion": "batch/v1", "kind": "Job", "name": "cross-node-tcp",
            "uid": os.environ["JOB_UID"], "controller": False}


def create_service(name):
    service = {"apiVersion": "v1", "kind": "Service",
               "metadata": {"name": name, "labels": {"ovn-light.io/run": RUN}, "ownerReferences": [owner_reference()]},
               "spec": {"type": "ClusterIP", "selector": {"ovn-light.io/run": RUN, "ovn-light.io/role": "server"},
                        "ports": [{"name": proto.lower(), "protocol": proto, "port": 5201}
                                  for proto in (["TCP", "UDP"] if TEST == "iperf-udp" else ["TCP"])]}}
    if TEST.startswith("netperf-"):
        service["spec"]["ports"].append({"name": "netperf-data", "protocol": "TCP", "port": 5202})
    return json.loads(kubectl("create", "-f", "-", "-o", "json", obj=service))["spec"]["clusterIP"]


def start_pod(name, role, node):
    resources = {"requests": {"cpu": "10m", "memory": "8Mi"}, "limits": {"cpu": "200m", "memory": "48Mi"}}
    if device := os.environ.get("DEVICE_RESOURCE"):
        for size in resources.values():
            size[device] = "1"
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": name, "labels": {"ovn-light.io/run": RUN, "ovn-light.io/role": role},
                        "ownerReferences": [owner_reference()]},
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


def suite_config(src, dst):
    if CASE not in {"POD_TO_POD_DIFF_NODE", "POD_TO_POD_SAME_NODE", "POD_TO_CLUSTER_IP_TO_POD_DIFF_NODE", "POD_TO_CLUSTER_IP_TO_POD_SAME_NODE"}:
        raise ValueError("Unsupported test case")
    if CASE.endswith("SAME_NODE") != (src == dst):
        raise ValueError("Selected case does not match node placement")
    client_args = []
    server_args = []
    if TEST in IPERF:
        client_args = ["-b", os.environ.get("SENDER_MBPS", "1") + "M", "-P", "1", "--cport", "35201"]
    elif TEST == "simple":
        client_args = ["--bufsize", "1024", "--sleep", "0.02"]
    elif TEST == "ib-send-bw":
        client_args = server_args = ["-n", "1000"]
    elif TEST not in {"http", "netperf-tcp-stream", "netperf-tcp-rr", "ib-write-bw", "ib-read-bw"}:
        raise ValueError("Unsupported test type")
    connection = {"name": "test", "type": TEST, "instances": 1, "reverse": False,
                  "client": [{"name": src}], "server": [{"name": dst, "pod_port": 5201}]}
    if client_args:
        connection["client"][0]["args"] = client_args
    if server_args:
        connection["server"][0]["args"] = server_args
    return {"tft": [{"name": "ovn-light", "namespace": NS, "duration": int(os.environ.get("TEST_SECONDS", "120")), "pre_provision": True,
                    "test_cases": CASE, "connections": [connection]}]}


def run_tasks(settings, server, client):
    # A runner owns one pair. Use the same upstream task objects for pod
    # creation and execution so their OVN logical ports are unique to the run.
    settings.initialize_clmo_barrier(1)
    tasks = (server, client)
    for task in tasks:
        task.start_setup(skip_pod_setup=True)
    settings.event_server_alive.wait()
    for task in tasks:
        task.start_task()
    settings.event_client_finished.wait()
    for task in tasks:
        task.finish_task()
    for task in tasks:
        task.finish_setup()
    result = TftResultBuilder()
    for task in tasks:
        task.aggregate_output(result)
    return result.build().flow_test


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
    cfg = suite_config(src, dst)
    tc = TestConfig(full_config=cfg, kubeconfigs=(path, None))
    descriptor = next(next(next(ConfigDescriptor(tc).describe_all_tft()).describe_all_test_cases()).describe_all_connections())
    settings = TestSettings(cfg_descr=descriptor, instance_index=0, reverse=False, target_access_mode=TargetAccessMode.IP)
    server, client = settings.cfg_descr.get_connection().test_type_handler.create_server_client(settings)
    server.pod_name, client.pod_name = f"server-{RUN}", f"client-{RUN}"
    service_ip = create_service(server.get_cluster_ip_service_name()) if "CLUSTER_IP" in CASE else None
    start_pod(server.pod_name, "server", dst)
    start_pod(client.pod_name, "client", src)
    kubectl("wait", "--for=condition=Ready", "pod/" + client.pod_name, "pod/" + server.pod_name, "--timeout=85s")
    expected_ips = []
    for name, node in [(client.pod_name, src), (server.pod_name, dst)]:
        pod = json.loads(kubectl("get", "pod", name, "-o", "json"))
        if pod["spec"]["nodeName"] != node:
            raise RuntimeError("Test pod scheduled on an unexpected node")
        nets = json.loads(pod["metadata"]["annotations"]["k8s.ovn.org/pod-networks"])
        default = nets.get("default", {})
        addresses = [str(ipaddress.ip_interface(ip).ip) for ip in default.get("ip_addresses", [])]
        if (pod["status"]["podIP"] not in addresses or default.get("role", "primary") != "primary"
                or any(n.get("role") == "primary" for key, n in nets.items() if key != "default")):
            raise RuntimeError("Test namespace requires the OVN default network as its primary attachment.")
        expected_ips.append(ipaddress.ip_address(pod["status"]["podIP"]))
    target = ipaddress.ip_address(service_ip) if service_ip else expected_ips[1]
    if target.version != 4 and TEST in {"simple", "http"}:
        raise RuntimeError("This upstream test requires an IPv4 primary address")
    result = run_tasks(settings, server, client)
    if not result.success:
        message = result.msg or f"{TEST} did not produce a successful measurement"
        if TEST.startswith("netperf-"):
            error = kubectl("exec", client.pod_name, "--", "tail", "-c", "400", "/tmp/netperf.err").strip()
            message = error or message
        match = re.search(r'"error":(?:\s|\\t)*"([^"]+)"', message)
        raise RuntimeError(match.group(1) if match else message[:450])
    measured = {"delivered": True, "sourceIP": str(expected_ips[0]), "destinationIP": str(expected_ips[1]), "targetIP": str(target)}
    stats = result.result
    if TEST == "http":
        measured["bytes"] = len(stats["result"]["out"].encode())
    elif TEST == "simple":
        counts = re.findall(r"chunks send and received \((\d+) bytes\)", stats["result"]["out"])
        if not counts or int(counts[-1]) == 0:
            raise RuntimeError("Echo client did not confirm receiving data")
        measured["bytes"] = int(counts[-1])
    elif TEST == "netperf-tcp-rr":
        measured["transactionsPerSecond"] = stats["Transaction Rate Per Second"]
    elif TEST == "netperf-tcp-stream":
        measured["bps"] = stats["Throughput 10^6bits/sec"] * 1e6
    elif TEST.startswith("ib-"):
        measured["bps"] = stats["bandwidth_gbps"] * 1e9
    else:
        measured.update(iperf_metrics(stats, expected_ips[0], target))
    for key in ("bps", "transactionsPerSecond"):
        if key in measured and not (math.isfinite(measured[key]) and measured[key] > 0):
            raise RuntimeError(f"{TEST} did not report a positive {key} measurement")
    if threshold := os.environ.get("MINIMUM_GBPS"):
        minimum = float(threshold)
        config = EvaluationConfig.parse({result.tft_metadata.test_type.name: [
            {"id": CASE, "Normal": {"threshold": minimum}}
        ]})
        verdict = Evaluator(config).eval_flow_test_output(result).eval_result
        if result.bitrate_gbps.is_na or verdict is None:
            raise RuntimeError("The upstream suite returned no throughput evaluation")
        measured["evaluation"] = {"passed": verdict.success, "minimumGbps": minimum,
                                  "rxGbps": result.bitrate_gbps.rx, "txGbps": result.bitrate_gbps.tx,
                                  "reason": verdict.msg}
    return measured


def iperf_metrics(stats, client_ip, target):
    connected = stats["start"]["connected"]
    if len(connected) != 1 or connected[0]["local_port"] != 35201 or connected[0]["remote_port"] != 5201:
        raise RuntimeError("Unexpected data stream tuple in iperf output")
    actual_ips = [ipaddress.ip_address(connected[0][key]) for key in ("local_host", "remote_host")]
    if actual_ips != [client_ip, target]:
        raise RuntimeError("The data stream addresses differ from the selected test pod addresses")
    received = stats["end"]["sum_received"]
    if received["bytes"] <= 0:
        raise RuntimeError("Receiver reported no data")
    metrics = {"bytes": received["bytes"], "bps": received["bits_per_second"]}
    if TEST == "iperf-udp":
        metrics.update(lostPercent=received["lost_percent"], jitterMs=received["jitter_ms"])
    return metrics


if __name__ == "__main__":
    try:
        result = execute()
    except Exception as exc:
        import traceback
        traceback.print_exc()
        result = {"delivered": False, "error": str(exc)[-600:]}
    result.update(test=TEST, case=CASE)
    Path("/dev/termination-log").write_text(json.dumps(result))
    sys.exit(0 if result["delivered"] else 1)
