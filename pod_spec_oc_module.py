#!/usr/bin/env python3

from kubernetes import client, config
import argparse
import sys
from collections import defaultdict

# RDS thresholds
RDS_MAX_PODS = 15
RDS_MAX_CONTAINERS = 30
RDS_MAX_EXEC_PROBES = 9
RDS_MAX_EXEC_PROBE_FREQUENCY = 10

EXCLUDED_NAMESPACES = {"ocp", "acm"}

def extract_probe_details(probe):
    probe_details = {
        "check": "", "command": "", "periodSeconds": None,
        "failureThreshold": None, "timeoutSeconds": None,
        "initialDelaySeconds": None, "successThreshold": None
    }

    try:
        if hasattr(probe, '_exec') and probe._exec:
            probe_details['check'] = "exec"
            probe_details['command'] = ' '.join(probe._exec.command or [])
        elif probe.http_get:
            scheme = probe.http_get.scheme or "http"
            port = probe.http_get.port or ""
            path = probe.http_get.path or "/"
            probe_details['check'] = "httpGet"
            probe_details['command'] = f"{scheme}://:{port}{path}"
        elif probe.tcp_socket:
            probe_details['check'] = "tcpSocket"
            probe_details['command'] = str(probe.tcp_socket.port)

        for field in ['period_seconds', 'failure_threshold', 'timeout_seconds', 'initial_delay_seconds', 'success_threshold']:
            val = getattr(probe, field, None)
            probe_details[field.replace('_', '')] = val

    except Exception as e:
        print(f"[WARN] Failed to extract probe details: {e}", file=sys.stderr)

    return probe_details

def get_pod_data(namespace):
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace)
    pod_data = {}

    for pod in pods.items:
        pod_name = pod.metadata.name
        pod_data[pod_name] = {}
        for container in pod.spec.containers:
            cdata = {}
            cdata['image'] = container.image.split('/', 1)[-1] if '/' in container.image else container.image
            if container.liveness_probe:
                cdata['livenessProbe'] = extract_probe_details(container.liveness_probe)
            if container.readiness_probe:
                cdata['readinessProbe'] = extract_probe_details(container.readiness_probe)
            if container.startup_probe:
                cdata['startupProbe'] = extract_probe_details(container.startup_probe)
            pod_data[pod_name][container.name] = cdata
    return pod_data

def output_asciidoc(pods):
    print("[options=\"header\"]")
    print("[cols=3,]")
    print("|===")
    print("|Pod Name |Cardinality |Containers")
    for pod, containers in pods.items():
        print(f"|{pod}\n|{len(containers)}")
        names = " +\n".join(containers.keys())
        print(f"|{names}")
    print("|===")

def output_probes_csv(pods):
    print("Pod name,Container name,Image,Probe type,Check,Command,Period,FailThresh,Timeout,InitDelay,SuccessThresh")
    for pod, containers in pods.items():
        for cname, data in containers.items():
            image = data['image']
            for ptype in ['startupProbe', 'readinessProbe', 'livenessProbe']:
                probe = data.get(ptype)
                if probe:
                    print(f"{pod},{cname},{image},{ptype},{probe['check']},{probe['command']},"
                          f"{probe.get('periodSeconds','')},{probe.get('failureThreshold','')},"
                          f"{probe.get('timeoutSeconds','')},{probe.get('initialDelaySeconds','')},"
                          f"{probe.get('successThreshold','')}")

def output_rds_analysis(pods):
    pod_count = len(pods)
    container_count = 0
    exec_probe_total = 0
    exec_probe_fast = 0

    for containers in pods.values():
        for cdata in containers.values():
            container_count += 1
            for key in ['startupProbe', 'readinessProbe', 'livenessProbe']:
                probe = cdata.get(key)
                if probe and probe['check'] == 'exec':
                    exec_probe_total += 1
                    if probe['periodSeconds'] and probe['periodSeconds'] < RDS_MAX_EXEC_PROBE_FREQUENCY:
                        exec_probe_fast += 1

    print(f"{pod_count} pods / {container_count} containers in total.")
    print(f"{exec_probe_total} exec probes total. {exec_probe_fast} with periodSeconds < {RDS_MAX_EXEC_PROBE_FREQUENCY}")

    if pod_count > RDS_MAX_PODS:
        print(f"RDS deviation: > {RDS_MAX_PODS} pods")
    if container_count > RDS_MAX_CONTAINERS:
        print(f"RDS deviation: > {RDS_MAX_CONTAINERS} containers")
    if exec_probe_total > RDS_MAX_EXEC_PROBES:
        print(f"RDS deviation: > {RDS_MAX_EXEC_PROBES} exec probes")

def summarize_configmaps_and_secrets(namespace):
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace)
    configmaps = set()
    secrets = set()

    for pod in pods.items:
        for vol in pod.spec.volumes or []:
            if vol.config_map:
                configmaps.add(vol.config_map.name)
            if vol.secret:
                secrets.add(vol.secret.secret_name)

        for container in pod.spec.containers:
            for envfrom in container.env_from or []:
                if envfrom.config_map_ref and envfrom.config_map_ref.name:
                    configmaps.add(envfrom.config_map_ref.name)
                if envfrom.secret_ref and envfrom.secret_ref.name:
                    secrets.add(envfrom.secret_ref.name)

            for env in container.env or []:
                if env.value_from:
                    if env.value_from.config_map_key_ref:
                        configmaps.add(env.value_from.config_map_key_ref.name)
                    if env.value_from.secret_key_ref:
                        secrets.add(env.value_from.secret_key_ref.name)

    print("[ConfigMaps]")
    for cm in sorted(configmaps):
        print(f"- {cm}")
    print("\n[Secrets]")
    for s in sorted(secrets):
        print(f"- {s}")

def summarize_probe_frequencies(namespace):
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace)
    probe_rates = defaultdict(float)

    for pod in pods.items:
        for container in pod.spec.containers:
            for probe in [container.liveness_probe, container.readiness_probe, container.startup_probe]:
                if not probe:
                    continue
                typ = "exec" if probe._exec else "http" if probe.http_get else "tcp"
                period = probe.period_seconds or 10
                probe_rates[typ] += 1.0 / period

    total_rate = sum(probe_rates.values())
    print(f"\n[Probe Frequencies] for namespace: {namespace}")
    for typ, rate in probe_rates.items():
        print(f"- {typ.upper()}: {rate:.2f} probes/sec")
    print(f"=> Total: {total_rate:.2f} probes/sec")

def get_target_namespaces(args):
    v1 = client.CoreV1Api()
    if args.all_namespaces:
        all_ns = v1.list_namespace()
        return [ns.metadata.name for ns in all_ns.items if ns.metadata.name not in EXCLUDED_NAMESPACES]
    else:
        return [args.namespace]

def main():
    parser = argparse.ArgumentParser(description="Query pod specs in a namespace and generate summaries.")
    parser.add_argument("-n", "--namespace", help="Namespace to query (ignored if --all-namespaces is set)")
    parser.add_argument("--all-namespaces", action="store_true", help="Analyze all namespaces except ocp/acm")
    parser.add_argument("-o", "--output",
                        choices=["pod_table_asciidoc", "probes_csv", "rds_analysis", "configmap_summary", "probe_freq", "all"],
                        default="all")
    args = parser.parse_args()

    try:
        config.load_kube_config()
    except:
        config.load_incluster_config()

    try:
        namespaces = get_target_namespaces(args)
    except Exception as e:
        print(f"[ERROR] Failed to determine namespaces: {e}", file=sys.stderr)
        sys.exit(1)

    for ns in namespaces:
        print(f"\n=== Namespace: {ns} ===")
        try:
            pods = get_pod_data(ns)

            if args.output == "pod_table_asciidoc":
                output_asciidoc(pods)
            elif args.output == "probes_csv":
                output_probes_csv(pods)
            elif args.output == "rds_analysis":
                output_rds_analysis(pods)
            elif args.output == "configmap_summary":
                summarize_configmaps_and_secrets(ns)
            elif args.output == "probe_freq":
                summarize_probe_frequencies(ns)
            elif args.output == "all":
                output_asciidoc(pods)
                print("\n---\n")
                output_probes_csv(pods)
                print("\n---\n")
                output_rds_analysis(pods)
                print("\n---\n")
                summarize_configmaps_and_secrets(ns)
                print("\n---\n")
                summarize_probe_frequencies(ns)
        except Exception as e:
            print(f"[ERROR] Failed to process namespace {ns}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
