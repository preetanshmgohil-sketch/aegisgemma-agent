"""Tests for the scanner behaviours that need multi-line context."""

from app.core.security_engine import SecurityEngine, TargetFile


def _f(path: str, content: str) -> TargetFile:
    return TargetFile(path=path, content=content, size=len(content))


class TestRouteDeduplication:
    def test_route_decorator_is_reported_once_not_also_the_def_line(self):
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
        access = [f for f in findings if f.category == "Broken Access Control"]
        assert len(access) == 1
        assert access[0].line == 3


class TestEnvSecrets:
    def test_flags_kubernetes_env_var_with_literal_password(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [
                _f(
                    "k8s/deploy.yaml",
                    "          env:\n"
                    "            - name: DATABASE_PASSWORD\n"
                    '              value: "production-db-password-2024"\n',
                )
            ]
        )
        secrets = [f for f in findings if f.category == "Hardcoded Secrets"]
        assert len(secrets) == 1
        assert "production-db-password-2024" not in secrets[0].snippet

    def test_ignores_env_var_sourced_from_a_secret_manager(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [
                _f(
                    "k8s/deploy.yaml",
                    "          env:\n"
                    "            - name: DATABASE_PASSWORD\n"
                    "              valueFrom:\n"
                    "                secretKeyRef:\n"
                    "                  name: db-secret\n",
                )
            ]
        )
        assert not any(f.category == "Hardcoded Secrets" for f in findings)

    def test_ignores_placeholder_env_value(self):
        engine = SecurityEngine()
        findings = engine.scan(
            [
                _f(
                    "k8s/deploy.yaml",
                    "          env:\n"
                    "            - name: API_TOKEN\n"
                    '              value: "your-token-here"\n',
                )
            ]
        )
        assert not any(f.category == "Hardcoded Secrets" for f in findings)


class TestPoCTokenIntegrity:
    def test_broken_access_control_poc_keeps_a_placeholder_token(self):
        from app.core.orchestrator import POC_TEMPLATES

        command = POC_TEMPLATES["Broken Access Control"][2]
        assert "YOUR_TOKEN" in command
        assert "***" not in command
