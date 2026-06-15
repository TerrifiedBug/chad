"""Tests for gated bidirectional GitOps inbound import (I6).

The git layer (GitSyncService.read_rules) is monkeypatched — no real repo. The
key guarantees: inbound is gated OFF by default, and apply only stages UNDEPLOYED
draft versions (deployment state is never changed by an import).
"""

import uuid

import pytest

from app.core.security import create_access_token, get_password_hash
from app.models.environment import Environment
from app.models.rule import Rule, RuleSource, RuleStatus, RuleVersion
from app.models.user import User, UserRole


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': str(user.id)})}"}


async def _make_user(session, email, role=UserRole.ADMIN) -> User:
    user = User(id=uuid.uuid4(), email=email, password_hash=get_password_hash("pw-12345678"),
                role=role, is_active=True)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def _make_env(session) -> Environment:
    env = Environment(id=uuid.uuid4(), name="prod", git_repo_url="https://example.com/repo.git",
                      git_branch="main")
    session.add(env)
    await session.commit()
    await session.refresh(env)
    return env


async def _make_rule(session, index_pattern, user, title, yaml_content, git_path=None):
    rule = Rule(id=uuid.uuid4(), title=title, yaml_content=yaml_content, severity="low",
                status=RuleStatus.DEPLOYED, source=RuleSource.USER, deployed_version=1,
                index_pattern_id=index_pattern.id, created_by=user.id, git_path=git_path)
    session.add(rule)
    await session.flush()
    session.add(RuleVersion(rule_id=rule.id, version_number=1, yaml_content=yaml_content,
                            changed_by=user.id, change_reason="init"))
    await session.commit()
    await session.refresh(rule)
    return rule


class _FakeService:
    def __init__(self, files):
        self._files = files

    def read_rules(self, subdir):
        return dict(self._files)


@pytest.fixture
def fake_repo(monkeypatch):
    # Patch the service factory so tests never import the real GitSyncService
    # (which needs GitPython); we still exercise the gating + diff/apply logic.
    files: dict[str, str] = {}
    monkeypatch.setattr(
        "app.services.git.git_import._service_for_env",
        lambda environment: _FakeService(files),
    )
    return files


@pytest.mark.asyncio
async def test_inbound_disabled_by_default(client, test_session, fake_repo):
    admin = await _make_user(test_session, "admin@example.com")
    env = await _make_env(test_session)
    flag = await client.get("/api/gitops/inbound", headers=_auth(admin))
    assert flag.json()["enabled"] is False
    # Preview is blocked while disabled.
    resp = await client.post(f"/api/gitops/environments/{env.id}/import-preview", headers=_auth(admin), json={})
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_enable_then_preview_classifies(client, test_session, fake_repo, test_index_pattern):
    admin = await _make_user(test_session, "admin2@example.com")
    env = await _make_env(test_session)
    await _make_rule(test_session, test_index_pattern, admin, "Existing Rule",
                     "title: Existing Rule\ndetection: {}", git_path="rules/prod/existing.yml")

    fake_repo["rules/prod/existing.yml"] = "title: Existing Rule\ndetection:\n  sel: changed"
    fake_repo["rules/prod/brand_new.yml"] = "title: Brand New\ndetection: {}"

    await client.put("/api/gitops/inbound", headers=_auth(admin), json={"enabled": True})

    prev = await client.post(f"/api/gitops/environments/{env.id}/import-preview", headers=_auth(admin), json={})
    assert prev.status_code == 200, prev.text
    by_path = {i["path"]: i["status"] for i in prev.json()["items"]}
    assert by_path["rules/prod/existing.yml"] == "modified"
    assert by_path["rules/prod/brand_new.yml"] == "new"


@pytest.mark.asyncio
async def test_apply_stages_undeployed_draft(client, test_session, fake_repo, test_index_pattern):
    admin = await _make_user(test_session, "admin3@example.com")
    env = await _make_env(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin, "Existing Rule",
                            "title: Existing Rule\noriginal: true", git_path="rules/prod/existing.yml")
    deployed_version_before = rule.deployed_version

    fake_repo["rules/prod/existing.yml"] = "title: Existing Rule\nimported: true"
    await client.put("/api/gitops/inbound", headers=_auth(admin), json={"enabled": True})

    resp = await client.post(
        f"/api/gitops/environments/{env.id}/import",
        headers=_auth(admin), json={"paths": ["rules/prod/existing.yml"]},
    )
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["updated"]) == 1

    from sqlalchemy import select
    refreshed = (await test_session.execute(select(Rule).where(Rule.id == rule.id))).scalar_one()
    # YAML updated as a draft, but the DEPLOYED version is unchanged (never auto-deployed).
    assert "imported: true" in refreshed.yaml_content
    assert refreshed.deployed_version == deployed_version_before


@pytest.mark.asyncio
async def test_apply_skips_new_files(client, test_session, fake_repo):
    admin = await _make_user(test_session, "admin4@example.com")
    env = await _make_env(test_session)
    fake_repo["rules/prod/new.yml"] = "title: Totally New\ndetection: {}"
    await client.put("/api/gitops/inbound", headers=_auth(admin), json={"enabled": True})
    resp = await client.post(
        f"/api/gitops/environments/{env.id}/import",
        headers=_auth(admin), json={"paths": ["rules/prod/new.yml"]},
    )
    assert resp.status_code == 200
    assert resp.json()["updated"] == []
    assert len(resp.json()["skipped"]) == 1
