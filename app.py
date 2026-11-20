import streamlit as st
import yaml, json
from datetime import datetime, timezone
from pathlib import Path

st.set_page_config(page_title="KubeShield AI | Cloud Security", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

RULES = [
    ("KS001", "Privileged container", "CRITICAL", "Disable privileged mode; grant only required permissions."),
    ("KS002", "Container runs as root", "HIGH", "Set runAsNonRoot: true and use a non-zero runAsUser."),
    ("KS003", "Privilege escalation enabled", "HIGH", "Set allowPrivilegeEscalation: false."),
    ("KS004", "Host network enabled", "HIGH", "Disable hostNetwork unless strictly required."),
    ("KS005", "Host PID namespace enabled", "HIGH", "Disable hostPID unless strictly required."),
    ("KS006", "Host path volume mounted", "HIGH", "Prefer a PersistentVolume or a narrowly scoped alternative."),
    ("KS007", "Dangerous Linux capability", "HIGH", "Drop ALL capabilities and add back only the minimum required."),
    ("KS008", "Service account token auto-mounted", "MEDIUM", "Set automountServiceAccountToken: false when API access is unnecessary."),
    ("KS009", "Missing container resource limits", "MEDIUM", "Define CPU and memory limits for every container."),
    ("KS010", "RBAC wildcard permission", "CRITICAL", "Replace wildcard verbs/resources with least-privilege permissions."),
    ("KS011", "Cluster-admin binding", "CRITICAL", "Use a narrowly scoped Role or ClusterRole instead."),
    ("KS012", "No read-only root filesystem", "LOW", "Set readOnlyRootFilesystem: true where the workload supports it."),
    ("KS013", "No seccomp profile", "MEDIUM", "Set seccompProfile.type to RuntimeDefault or an approved profile."),
    ("KS014", "No NetworkPolicy found", "LOW", "Review namespace traffic controls and add a default-deny NetworkPolicy where appropriate."),
]
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def path(obj, *keys):
    cur = obj
    for key in keys:
        if not isinstance(cur, dict): return None
        cur = cur.get(key)
    return cur


def scan_yaml(raw):
    findings, errors, kinds = [], [], []
    try:
        docs = list(yaml.safe_load_all(raw))
    except yaml.YAMLError as exc:
        return [], [str(exc)], []
    kinds = [str(d.get("kind", "Unknown")) for d in docs if isinstance(d, dict)]
    has_network_policy = any(isinstance(d, dict) and d.get("kind") == "NetworkPolicy" for d in docs)
    def add(rule, resource, evidence):
        rid, title, severity, fix = rule
        findings.append({"id": rid, "title": title, "severity": severity, "resource": resource, "evidence": evidence, "recommendation": fix})
    for i, doc in enumerate(docs, 1):
        if doc is None: continue
        if not isinstance(doc, dict):
            errors.append(f"Document {i}: expected a YAML object, got {type(doc).__name__}.")
            continue
        kind = str(doc.get("kind", "Unknown")); name = str(path(doc, "metadata", "name") or f"document-{i}")
        resource = f"{kind}/{name}"
        pod = None
        if kind == "Pod": pod = doc.get("spec", {})
        elif kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"): pod = path(doc, "spec", "template", "spec")
        elif kind == "CronJob": pod = path(doc, "spec", "jobTemplate", "spec", "template", "spec")
        if isinstance(pod, dict):
            if pod.get("hostNetwork") is True: add(RULES[3], resource, "spec.hostNetwork: true")
            if pod.get("hostPID") is True: add(RULES[4], resource, "spec.hostPID: true")
            if pod.get("automountServiceAccountToken") is True: add(RULES[7], resource, "spec.automountServiceAccountToken: true")
            seccomp = path(pod, "securityContext", "seccompProfile", "type")
            if not seccomp: add(RULES[12], resource, "Pod securityContext.seccompProfile is not configured")
            for vol in pod.get("volumes", []) or []:
                if isinstance(vol, dict) and "hostPath" in vol: add(RULES[5], resource, f"volume {vol.get('name', '(unnamed)')} uses hostPath")
            containers = (pod.get("containers", []) or []) + (pod.get("initContainers", []) or [])
            for c in containers:
                if not isinstance(c, dict): continue
                cname = c.get("name", "unnamed-container"); sc = c.get("securityContext") or {}; cr = f"{resource} / container {cname}"
                if sc.get("privileged") is True: add(RULES[0], cr, "securityContext.privileged: true")
                if sc.get("runAsUser") == 0: add(RULES[1], cr, "securityContext.runAsUser: 0")
                if sc.get("runAsNonRoot") is not True and sc.get("runAsUser") != 0: add(RULES[1], cr, "securityContext.runAsNonRoot is not true")
                if sc.get("allowPrivilegeEscalation") is True: add(RULES[2], cr, "securityContext.allowPrivilegeEscalation: true")
                caps = path(sc, "capabilities", "add") or []
                dangerous = sorted({str(x).upper() for x in caps} & {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL"})
                if dangerous: add(RULES[6], cr, "Added capabilities: " + ", ".join(dangerous))
                limits = path(c, "resources", "limits")
                if not isinstance(limits, dict) or not limits: add(RULES[8], cr, "resources.limits is missing or empty")
                if sc.get("readOnlyRootFilesystem") is not True: add(RULES[11], cr, "securityContext.readOnlyRootFilesystem is not true")
        if kind in ("Role", "ClusterRole"):
            for ri, rule in enumerate(doc.get("rules", []) or []):
                if isinstance(rule, dict) and ("*" in (rule.get("verbs") or []) or "*" in (rule.get("resources") or [])):
                    add(RULES[9], resource, f"rule {ri+1}: verbs={rule.get('verbs', [])}, resources={rule.get('resources', [])}")
        if kind in ("RoleBinding", "ClusterRoleBinding") and path(doc, "roleRef", "name") == "cluster-admin":
            add(RULES[10], resource, "roleRef.name: cluster-admin")
    if any(k in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Pod", "Job", "CronJob"} for k in kinds) and not has_network_policy:
        add(RULES[13], "Namespace (manifest scope)", "No NetworkPolicy resource was found in the uploaded YAML bundle")
    return findings, errors, kinds


def score_findings(findings):
    weights = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2}
    return max(0, 100 - sum(weights[f["severity"]] for f in findings))


def render_badge(sev):
    colors = {"CRITICAL":"#ff4d5e", "HIGH":"#ff8b3d", "MEDIUM":"#f4c542", "LOW":"#56a6ff"}
    return f'<span style="background:{colors[sev]}20;color:{colors[sev]};border:1px solid {colors[sev]}70;padding:4px 10px;border-radius:20px;font-size:12px;font-weight:700;">{sev}</span>'

st.markdown("""
<style>
:root{color-scheme:dark} .stApp{background:radial-gradient(ellipse at 15% 0%,#142747 0%,#080d18 42%,#080d18 100%);color:#eaf1ff}
[data-testid="stHeader"]{background:rgba(8,13,24,.75)} .block-container{padding-top:1.7rem;padding-bottom:3rem;max-width:1450px}
[data-testid="stSidebar"]{background:#0d1728;border-right:1px solid #243650}
.hero{padding:25px 28px;border:1px solid #2b4163;border-radius:22px;background:linear-gradient(120deg,#142642,#101a2d 58%,#1d1420);box-shadow:0 18px 50px #0005;margin-bottom:22px}
.hero-kicker{color:#ff9a45;text-transform:uppercase;letter-spacing:2px;font-size:11px;font-weight:800}.hero h1{font-size:38px;margin:7px 0;color:#fff}.hero p{color:#a9bad4;margin:0;font-size:15px}
.metric{background:linear-gradient(145deg,#14233a,#101a2c);border:1px solid #2a3d5b;border-radius:16px;padding:17px 18px;min-height:110px}.metric .label{color:#9eb1cc;font-size:12px;text-transform:uppercase;letter-spacing:1px}.metric .value{font-size:30px;font-weight:800;color:#f6f8ff;margin-top:4px}.metric .hint{font-size:11px;color:#7f94b3}
.panel{background:#101b2e;border:1px solid #263a58;border-radius:17px;padding:18px 20px;margin:10px 0}.small-muted{color:#92a6c4;font-size:13px}
.stButton>button[kind="primary"]{background:linear-gradient(90deg,#ff7b22,#ff4f36);border:0;color:white;font-weight:750;border-radius:11px}
[data-testid="stFileUploader"]{background:#101b2e;border:1px dashed #496486;border-radius:15px;padding:12px}
[data-testid="stMetric"]{background:#111e32;border:1px solid #2a3d5b;padding:14px;border-radius:14px}
hr{border-color:#263a58}
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("# 🛡️ KubeShield")
    st.caption("CLOUD-NATIVE SECURITY • PS-09")
    st.divider()
    page = st.radio("WORKSPACE", ["Security Scanner", "Detection Rules", "About & Scope"], label_visibility="collapsed")
    st.divider()
    st.markdown("**Prototype status**")
    st.markdown("🟢 YAML parser ready  \n🟢 14 rule checks  \n🟢 JSON export")
    st.caption("Static analysis only · No cluster connection")

st.markdown('<div class="hero"><div class="hero-kicker">Hackathon 2026 · Problem Statement PS-09</div><h1>🛡️ KubeShield AI</h1><p>Kubernetes Security Misconfiguration Detection Platform</p></div>', unsafe_allow_html=True)

if page == "Security Scanner":
    st.markdown("### Security assessment workspace")
    st.markdown('<p class="small-muted">Inspect Kubernetes manifests before deployment. Upload a YAML bundle or run the included demo scenarios.</p>', unsafe_allow_html=True)
    c1,c2 = st.columns([1.35,1])
    with c1:
        uploaded = st.file_uploader("Upload Kubernetes manifest", type=["yaml","yml"], help="Multi-document YAML is supported.")
    with c2:
        demo = st.selectbox("Quick demo scenario", ["Choose a sample…", "Vulnerable deployment", "Hardened deployment"])
    sample_dir = Path(__file__).parent / "samples"
    raw = ""
    source_name = ""
    if uploaded is not None:
        raw = uploaded.getvalue().decode("utf-8", errors="replace"); source_name = uploaded.name
    elif demo == "Vulnerable deployment":
        raw = (sample_dir / "vulnerable.yaml").read_text(encoding="utf-8"); source_name = "vulnerable.yaml"
    elif demo == "Hardened deployment":
        raw = (sample_dir / "fixed.yaml").read_text(encoding="utf-8"); source_name = "fixed.yaml"
    if raw:
        with st.expander(f"Preview source · {source_name}", expanded=False): st.code(raw, language="yaml")
        findings, errors, kinds = scan_yaml(raw)
        counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITY_ORDER}
        score = score_findings(findings)
        st.markdown("#### Assessment overview")
        cols = st.columns(5)
        metrics = [("SECURITY SCORE",f"{score}/100","Heuristic score"),("TOTAL FINDINGS",str(len(findings)),"Configured checks triggered"),("CRITICAL",str(counts['CRITICAL']),"Immediate review"),("HIGH",str(counts['HIGH']),"High priority"),("RESOURCES",str(len(kinds)),"YAML documents with kind")]
        for col,(label,value,hint) in zip(cols,metrics):
            col.markdown(f'<div class="metric"><div class="label">{label}</div><div class="value">{value}</div><div class="hint">{hint}</div></div>',unsafe_allow_html=True)
        st.progress(score/100, text=f"Heuristic posture score: {score}/100 · Higher is better")
        if errors:
            st.error("YAML parsing / document warnings")
            for err in errors: st.code(err)
        st.markdown("#### Security findings")
        if findings:
            findings.sort(key=lambda f: SEVERITY_ORDER[f['severity']])
            filters = st.multiselect("Filter by severity", ["CRITICAL","HIGH","MEDIUM","LOW"], default=["CRITICAL","HIGH","MEDIUM","LOW"])
            visible = [f for f in findings if f['severity'] in filters]
            for f in visible:
                with st.expander(f"{f['id']}  ·  {f['title']}  ·  {f['resource']}", expanded=f['severity']=="CRITICAL"):
                    st.markdown(render_badge(f['severity']), unsafe_allow_html=True)
                    st.markdown(f"**Evidence**  \n{f['evidence']}")
                    st.markdown(f"**Recommended remediation**  \n{f['recommendation']}")
        else:
            st.success("No configured checks were triggered. This does not prove the manifest is secure.")
        report = {"tool":"KubeShield AI","problem_statement":"PS-09","generated_at":datetime.now(timezone.utc).isoformat(),"source_file":source_name,"scope":"Static YAML checks only; not a full Kubernetes audit","security_score":score,"summary":counts,"resource_kinds":kinds,"findings":findings,"errors":errors}
        st.download_button("⬇️ Download security assessment (JSON)",json.dumps(report,indent=2),file_name="kubeshield_security_report.json",mime="application/json",type="primary")
    else:
        st.markdown('<div class="panel"><h4>🚀 Run your first assessment</h4><p class="small-muted">Select a demo scenario to see the scanner in action, or upload your own Kubernetes YAML manifest.</p><p>① Choose vulnerable sample &nbsp; → &nbsp; ② Review evidence &nbsp; → &nbsp; ③ Compare hardened sample &nbsp; → &nbsp; ④ Export JSON report</p></div>',unsafe_allow_html=True)
        a,b = st.columns(2)
        with a:
            st.markdown("**🔴 Vulnerable scenario**")
            st.caption("Intentionally insecure workload and RBAC examples for demonstration.")
        with b:
            st.markdown("**🟢 Hardened scenario**")
            st.caption("Example manifest with safer container settings and resource limits.")

elif page == "Detection Rules":
    st.markdown("### Detection rule catalogue")
    st.caption("The current prototype implements these deterministic static checks. Results require human validation.")
    for rule in RULES:
        rid,title,severity,fix = rule
        with st.expander(f"{rid} · {title}"):
            st.markdown(render_badge(severity),unsafe_allow_html=True)
            st.write("**Recommended action:**",fix)
    st.info("NetworkPolicy check is a bundle-level presence check, not a semantic network-policy validator.")
else:
    st.markdown("### Project overview")
    st.markdown('<div class="panel"><h4>What KubeShield AI does</h4><p>Parses uploaded Kubernetes YAML manifests, evaluates selected security configuration rules, and presents prioritized findings with evidence and remediation guidance.</p></div>',unsafe_allow_html=True)
    x,y,z = st.columns(3)
    x.metric("Rule checks","14","Static checks")
    y.metric("Input","YAML","Single or multi-document")
    z.metric("Output","JSON","Downloadable report")
    st.markdown("#### Architecture")
    st.code("YAML upload → PyYAML parser → Resource identification → Rule engine (KS001–KS014) → Severity + evidence + remediation → Streamlit dashboard + JSON report",language="text")
    st.markdown("#### Security boundary & limitations")
    st.warning("This prototype does not connect to a Kubernetes cluster, run kubectl, modify resources, or perform a complete CIS benchmark audit. The checks are rule-based (not an ML model). The score is a heuristic, not a certified security rating. Human review is required.")

st.divider()
st.markdown('<p class="small-muted">KubeShield AI · Cyber Arena 2026 · PS-09 · Built for defensive configuration review. Validate findings before production use.</p>',unsafe_allow_html=True)
