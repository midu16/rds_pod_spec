Here's everything you need to track, run, and maintain the `pod_spec_oc_module.py` project in a GitHub repository, including:

---

## ✅ `requirements.txt`

```txt
kubernetes>=27.2.0
pyyaml>=6.0
```

These versions are safe for both Python 3.9+ and OpenShift 4.x clusters.

---

## 📁 Suggested Project Structure

```
pod-spec-analyzer/
├── pod_spec_oc_module.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

## 🛠️ Pre-requisites

To run the script locally or in a GitHub Actions CI/CD pipeline:

### 1. Python

* Python 3.9 or later (Python 3.6+ works but newer versions preferred)

### 2. Kubernetes Access

* `~/.kube/config` must be present and point to an accessible OpenShift or Kubernetes cluster **OR**
* The script must be run **inside a pod or container** with `ServiceAccount` permissions to list pods.

### 3. Python Environment Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 📘 `README.md` Template

````markdown
# Pod Spec Analyzer for OpenShift/Kubernetes

This tool queries a live OpenShift or Kubernetes cluster for pod specifications in a given namespace and generates useful summaries:

- 📦 Pod/container inventory
- 🔍 Probe configuration (startup, readiness, liveness)
- 📊 RDS conformance analysis
- 🔐 ConfigMap & Secret references

## 🔧 Requirements

- Python 3.9+
- Access to a Kubernetes/OpenShift cluster via `~/.kube/config` or in-cluster service account
- Install dependencies:

```bash
pip install -r requirements.txt
````

## 🚀 Usage

```bash
python pod_spec_oc_module.py -n <namespace> -o all
```

### Output options:

* `pod_table_asciidoc` – AsciiDoc-formatted pod/container table
* `probes_csv` – CSV of all container probes
* `rds_analysis` – RDS workload summary
* `configmap_summary` – ConfigMap and Secret usage
* `all` – Run all of the above

## 📦 Example

```bash
# python3 pod_spec_oc_module.py -n openshift-storage -o all
[options="header"]
[cols=3,]
|===
|Pod Name |Cardinality |Containers
|odf-console-558889c9bf-s9qpj
|1
|odf-console
|odf-operator-controller-manager-64584965f6-8hbxc
|2
|kube-rbac-proxy +
manager
|===

---

Pod name,Container name,Image,Probe type,Check,Command,Period,FailThresh,Timeout,InitDelay,SuccessThresh
odf-console-558889c9bf-s9qpj,odf-console,odf4/odf-console-rhel9@sha256:5e9709c236ffa2354f9dc8dd3ed2a79af0454ccc1d253bb40d055d38786ebfd7,livenessProbe,httpGet,HTTPS://:9001/plugin-manifest.json,None,None,None,None,None
odf-operator-controller-manager-64584965f6-8hbxc,manager,odf4/odf-rhel9-operator@sha256:e79a5bcb39b924a1349517fc43b99f0280928969fb5a8d9b772985b0e6dd3ac7,readinessProbe,httpGet,HTTP://:8081/readyz,None,None,None,None,None
odf-operator-controller-manager-64584965f6-8hbxc,manager,odf4/odf-rhel9-operator@sha256:e79a5bcb39b924a1349517fc43b99f0280928969fb5a8d9b772985b0e6dd3ac7,livenessProbe,httpGet,HTTP://:8081/healthz,None,None,None,None,None

---

2 pods / 3 containers in total.
0 exec probes total. 0 with periodSeconds < 10

---

[ConfigMaps]
- odf-console-nginx-conf
- odf-operator-manager-config

[Secrets]
- odf-console-serving-cert
```

## 🔐 Permissions

If running inside a pod, make sure the ServiceAccount has the following RBAC:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]

---

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-reader-binding
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: <your-sa>
  namespace: <your-namespace>
```

## 🐛 Known Limitations

* Only top-level container specs are analyzed (initContainers and ephemeral containers not yet supported).
* Probe summaries assume well-formed objects; malformed fields may result in warnings.

## 🤝 Contributing

Pull requests and issue reports are welcome.

## 📄 License

Apache 2.0 (or your preferred license)
