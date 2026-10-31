"""Heuristic static-analysis engine tests — these must run without any AI API key."""

from app.core.security_engine import SecurityEngine, TargetFile


def _f(path: str, content: str) -> TargetFile:
    return TargetFile(path=path, content=content, size=len(content))


class TestSecretDetection:
    def test_detects_aws_access_key(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [
                _f(
                    "deploy/aws.py",
                    'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
                )
            ]
        )
        assert any(f.category == "Hardcoded Secrets" for f in findings)
        secret = next(f for f in findings if f.category == "Hardcoded Secrets")
        assert secret.cwe_id == "CWE-798"
        assert "AKIA" not in secret.snippet  # value must be redacted

    def test_ignores_placeholder_secret(self):
        engine = SecurityEngine()
        findings = engine.scan([_f("app.py", 'API_KEY = "your-api-key-here"\n')])
        assert not any(f.category == "Hardcoded Secrets" for f in findings)

    def test_detects_private_key_block(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [_f("id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n")]
        )
        assert any(f.category == "Hardcoded Secrets" for f in findings)

    def test_detects_generic_api_key_assignment(self):
        engine = SecurityEngine()
        findings = engine.scan([_f("cfg.py", 'password = "s3cr3t-p@ssw0rd-value"\n')])
        assert any(f.category == "Hardcoded Secrets" for f in findings)


class TestInjectionDetection:
    def test_detects_python_command_injection(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [_f("run.py", "import os\nos.system('ls ' + user_input)\n")]
        )
        assert any(f.category == "Command Injection" for f in findings)

    def test_detects_shell_true_subprocess(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [_f("run.py", "subprocess.run(cmd, shell=True)\n")]
        )
        assert any(f.category == "Command Injection" for f in findings)

    def test_detects_sql_string_concatenation(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [_f("db.py", 'cursor.execute("SELECT * FROM users WHERE id = " + uid)\n')]
        )
        assert any(f.category == "SQL Injection" for f in findings)

    def test_detects_python_format_sql(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [_f("db.py", 'cursor.execute("SELECT * FROM u WHERE id = %s" % uid)\n')]
        )
        assert any(f.category == "SQL Injection" for f in findings)

    def test_detects_eval_of_user_input(self):
        engine = SecurityEngine()
        findings = engine.scan([_f("calc.py", "result = eval(request.args['x'])\n")])
        assert any(f.category == "Code Injection" for f in findings)

    def test_detects_js_innerhtml_assignment(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [_f("app.js", "el.innerHTML = userInput;\n")]
        )
        assert any(f.category == "XSS" for f in findings)

    def test_detects_dangerously_set_inner_html(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [_f("App.tsx", '<div dangerouslySetInnerHTML={{ __html: data }} />\n')]
        )
        assert any(f.category == "XSS" for f in findings)


class TestAccessControlDetection:
    def test_flags_fastapi_route_without_auth_dependency(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [
                _f(
                    "api/users.py",
                    "from fastapi import APIRouter\n"
                    "router = APIRouter()\n"
                    '@router.get("/users/{uid}")\n'
                    "def get_user(uid: int):\n"
                    "    return db.query(uid)\n",
                )
            ]
        )
        assert any(f.category == "Broken Access Control" for f in findings)

    def test_does_not_flag_route_with_auth_dependency(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [
                _f(
                    "api/users.py",
                    "from fastapi import APIRouter, Depends\n"
                    "router = APIRouter()\n"
                    '@router.get("/users/{uid}")\n'
                    "def get_user(uid: int, user=Depends(current_user)):\n"
                    "    return db.query(uid)\n",
                )
            ]
        )
        assert not any(f.category == "Broken Access Control" for f in findings)

    def test_flags_flask_route_without_auth(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [_f("app.py", '@app.route("/admin")\ndef admin():\n    return "ok"\n')]
        )
        assert any(f.category == "Broken Access Control" for f in findings)


class TestInfrastructureDetection:
    def test_flags_root_user_in_dockerfile(self):
        engine = SecurityEngine()
        findings = engine.scan([_f("Dockerfile", "FROM python:3.11\nUSER root\n")])
        assert any("Container" in f.category for f in findings)

    def test_flags_privileged_kubernetes_container(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [
                _f(
                    "k8s/deploy.yaml",
                    "securityContext:\n  privileged: true\n  runAsUser: 0\n",
                )
            ]
        )
        assert any("Kubernetes" in f.category for f in findings)

    def test_flags_public_s3_bucket_terraform(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [
                _f(
                    "main.tf",
                    'resource "aws_s3_bucket" "b" {\n'
                    '  bucket = "data"\n'
                    "  acl    = \"public-read\"\n"
                    "}\n",
                )
            ]
        )
        assert any("Terraform" in f.category for f in findings)


class TestOpenApiDetection:
    def test_flags_missing_security_scheme(self):
        engine = SecurityEngine()
        spec = (
            "openapi: 3.0.0\n"
            "paths:\n"
            "  /users:\n"
            "    get:\n"
            "      responses:\n"
            "        '200': {description: ok}\n"
        )
        findings = engine.scan([_f("openapi.yaml", spec)])
        assert any(f.category == "API Exposure" for f in findings)

    def test_flags_http_only_scheme(self):
        engine = SecurityEngine()
        spec = (
            "openapi: 3.0.0\n"
            "security:\n"
            "  - apiKey: []\n"
            "components:\n"
            "  securitySchemes:\n"
            "    apiKey:\n"
            "      type: apiKey\n"
            "      name: X-Key\n"
            "      in: header\n"
            "paths:\n"
            "  /users:\n"
            "    get:\n"
            "      responses:\n"
            "        '200': {description: ok}\n"
        )
        findings = engine.scan([_f("openapi.yaml", spec)])
        assert any(f.category == "API Exposure" for f in findings)

    def test_secure_spec_is_clean(self):
        engine = SecurityEngine()
        spec = (
            "openapi: 3.0.0\n"
            "security:\n"
            "  - bearerAuth: []\n"
            "components:\n"
            "  securitySchemes:\n"
            "    bearerAuth:\n"
            "      type: http\n"
            "      scheme: bearer\n"
            "paths:\n"
            "  /users:\n"
            "    get:\n"
            "      responses:\n"
            "        '200': {description: ok}\n"
        )
        findings = engine.scan([_f("openapi.yaml", spec)])
        assert not any(f.category == "API Exposure" for f in findings)


class TestScoringAndStructure:
    def test_every_finding_carries_a_valid_cvss_vector(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [
                _f("bad.py", "os.system(cmd)\ncursor.execute('SELECT ' + x)\n"),
                _f("k8s/p.yaml", "privileged: true\n"),
            ]
        )
        assert findings
        for finding in findings:
            assert finding.cvss_vector.startswith("CVSS:3.1/")
            assert 0.0 <= finding.cvss_score <= 10.0
            assert finding.severity in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_line_numbers_are_one_based_and_in_range(self):
        engine = SecurityEngine()
        content = "x = 1\ny = 2\nos.system(cmd)\n"
        findings = engine.scan([_f("a.py", content)])
        cmd = next(f for f in findings if f.category == "Command Injection")
        assert cmd.line == 3

    def test_ignores_binary_and_oversized_files(self):
        engine = SecurityEngine()
        findings = engine.scan([_f("image.png", "\x89PNG\x00\x01\x02")])
        assert findings == []

    def test_project_summary_counts_files_and_languages(self):
        engine = SecurityEngine()
        summary = engine.summarize(
            [
                _f("a.py", "print(1)\n"),
                _f("b.ts", "export const x = 1;\n"),
                _f("c.md", "# hi\n"),
            ]
        )
        assert summary.file_count == 3
        assert summary.languages["Python"] == 1
        assert summary.languages["TypeScript"] == 1

    def test_skips_vendor_and_lockfiles(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [
                _f("node_modules/foo/index.js", "el.innerHTML = x;\n"),
                _f("package-lock.json", '{"dependencies":{}}'),
            ]
        )
        assert findings == []
