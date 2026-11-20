# Test plan and verification status

The repository includes two controlled demo manifests and automated regression tests in `tests/test_scanner.py`.

## Expected outcomes
- `samples/vulnerable.yaml`: scanner should report CRITICAL and HIGH findings, including privileged execution and broad RBAC.
- `samples/fixed.yaml`: no configured findings should be triggered by the current rule set.
- Invalid YAML: parser error should be displayed instead of crashing the dashboard.

## Run tests on Windows
```bat
py -m pip install -r requirements.txt
py -m pip install pytest
py -m pytest -q
```

Do not describe these tests as a complete Kubernetes security audit. The scanner performs deterministic static checks against uploaded YAML only. Review findings manually before using recommendations.
