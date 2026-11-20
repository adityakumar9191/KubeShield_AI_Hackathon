from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("kubeshield_app", ROOT / "app.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def test_vulnerable_sample_triggers_critical_and_high_findings():
    raw = (ROOT / "samples" / "vulnerable.yaml").read_text(encoding="utf-8")
    findings, errors, kinds = app.scan_yaml(raw)
    assert not errors
    assert "Deployment" in kinds
    assert any(f["severity"] == "CRITICAL" for f in findings)
    assert any(f["severity"] == "HIGH" for f in findings)


def test_fixed_sample_has_no_configured_findings():
    raw = (ROOT / "samples" / "fixed.yaml").read_text(encoding="utf-8")
    findings, errors, kinds = app.scan_yaml(raw)
    assert not errors
    assert "Deployment" in kinds
    assert findings == []


def test_invalid_yaml_returns_parse_error():
    findings, errors, kinds = app.scan_yaml("kind: [broken")
    assert findings == []
    assert errors
