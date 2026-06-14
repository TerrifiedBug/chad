"""Unit tests for SSO group -> team + role reconciliation (idempotent, source-aware)."""

import uuid

import pytest

from app.models.sso_provider import SSOGroupMapping, SSOProvider
from app.models.team import Team
from app.models.user import TeamSource, User, UserRole
from app.services.sso_reconcile import reconcile_user_team_memberships


def _provider(mappings=None, default_team_id=None, default_role="viewer"):
    p = SSOProvider(
        id=uuid.uuid4(),
        name="P",
        enabled=True,
        issuer_url="https://idp",
        client_id="c",
        group_sync_enabled=True,
        groups_claim="groups",
        default_team_id=default_team_id,
        default_role=default_role,
    )
    # group_mappings is normally a relationship; assign a plain list for the unit.
    p.group_mappings = mappings or []
    return p


def _mapping(group_value, team_id, role):
    return SSOGroupMapping(
        id=uuid.uuid4(), group_value=group_value, team_id=team_id, role=role
    )


def _user(**kw):
    return User(
        id=uuid.uuid4(),
        email=kw.get("email", "u@example.com"),
        role=kw.get("role", UserRole.VIEWER),
        team_id=kw.get("team_id"),
        team_source=kw.get("team_source"),
        is_active=True,
    )


class TestReconcile:
    def test_group_sets_team_and_role(self):
        team = uuid.uuid4()
        provider = _provider([_mapping("soc-admins", team, "admin")])
        user = _user()
        result = reconcile_user_team_memberships(user, ["soc-admins"], provider)
        assert result.changed is True
        assert user.team_id == team
        assert user.role == UserRole.ADMIN
        assert user.team_source == TeamSource.GROUP_MAPPING.value

    def test_idempotent_second_call_no_change(self):
        team = uuid.uuid4()
        provider = _provider([_mapping("g", team, "analyst")])
        user = _user()
        assert reconcile_user_team_memberships(user, ["g"], provider).changed is True
        # Second call with identical inputs -> nothing changes.
        assert reconcile_user_team_memberships(user, ["g"], provider).changed is False
        assert user.role == UserRole.ANALYST
        assert user.team_id == team

    def test_highest_role_wins_across_groups(self):
        team_a, team_b = uuid.uuid4(), uuid.uuid4()
        provider = _provider(
            [
                _mapping("viewers", team_a, "viewer"),
                _mapping("admins", team_b, "admin"),
            ]
        )
        user = _user()
        reconcile_user_team_memberships(user, ["viewers", "admins"], provider)
        # admin > viewer, so the admin mapping's team wins.
        assert user.role == UserRole.ADMIN
        assert user.team_id == team_b

    def test_case_insensitive_group_match(self):
        team = uuid.uuid4()
        provider = _provider([_mapping("SOC-Admins", team, "admin")])
        user = _user()
        reconcile_user_team_memberships(user, ["soc-admins"], provider)
        assert user.role == UserRole.ADMIN
        assert user.team_id == team

    def test_no_match_sets_default_team_but_leaves_role_untouched(self):
        # No group matched: team falls back to default_team, but role is NOT
        # overwritten with the provider default — reconciliation never sets role
        # on a non-match (escalation/demotion guard).
        default_team = uuid.uuid4()
        provider = _provider([], default_team_id=default_team, default_role="analyst")
        user = _user(role=UserRole.VIEWER)
        result = reconcile_user_team_memberships(user, ["unknown-group"], provider)
        assert result.group_matched is False
        assert user.team_id == default_team
        assert user.role == UserRole.VIEWER  # untouched, NOT demoted/promoted to default
        assert user.team_source == TeamSource.GROUP_MAPPING.value

    def test_manual_team_not_clobbered_when_no_group_matches(self):
        manual_team = uuid.uuid4()
        provider = _provider([], default_team_id=uuid.uuid4(), default_role="viewer")
        user = _user(team_id=manual_team, team_source=TeamSource.MANUAL.value)
        reconcile_user_team_memberships(user, ["nope"], provider)
        # Manual assignment is sacred when nothing matches.
        assert user.team_id == manual_team
        assert user.team_source == TeamSource.MANUAL.value

    def test_legacy_null_source_with_team_treated_as_manual(self):
        existing_team = uuid.uuid4()
        provider = _provider([], default_team_id=uuid.uuid4())
        user = _user(team_id=existing_team, team_source=None)
        reconcile_user_team_memberships(user, [], provider)
        assert user.team_id == existing_team

    def test_group_match_overrides_manual(self):
        manual_team, group_team = uuid.uuid4(), uuid.uuid4()
        provider = _provider([_mapping("g", group_team, "admin")])
        user = _user(team_id=manual_team, team_source=TeamSource.MANUAL.value)
        reconcile_user_team_memberships(user, ["g"], provider)
        # When a group DOES match, the IdP is authoritative.
        assert user.team_id == group_team
        assert user.team_source == TeamSource.GROUP_MAPPING.value
        assert user.role == UserRole.ADMIN

    def test_empty_groups_no_default_clears_group_sourced_team(self):
        old_group_team = uuid.uuid4()
        provider = _provider([], default_team_id=None)
        user = _user(team_id=old_group_team, team_source=TeamSource.GROUP_MAPPING.value)
        reconcile_user_team_memberships(user, [], provider)
        # A previously group-sourced team with no current match + no default -> cleared.
        assert user.team_id is None
        assert user.team_source is None

    def test_existing_admin_empty_groups_claim_keeps_admin(self):
        # An existing SSO admin whose groups claim is empty/absent must NOT be
        # demoted to the provider default role.
        provider = _provider([_mapping("admins", uuid.uuid4(), "admin")],
                             default_role="viewer")
        user = _user(role=UserRole.ADMIN)
        result = reconcile_user_team_memberships(user, [], provider)
        assert result.group_matched is False
        assert user.role == UserRole.ADMIN  # NOT demoted to viewer

    def test_existing_admin_unknown_groups_keeps_admin(self):
        provider = _provider([_mapping("admins", uuid.uuid4(), "admin")],
                             default_role="viewer")
        user = _user(role=UserRole.ADMIN)
        reconcile_user_team_memberships(user, ["some-other-group"], provider)
        assert user.role == UserRole.ADMIN

    def test_manually_promoted_role_not_clobbered_on_no_match(self):
        # A user manually promoted to ANALYST keeps it when no group matches.
        provider = _provider([], default_role="viewer")
        user = _user(role=UserRole.ANALYST)
        reconcile_user_team_memberships(user, ["nope"], provider)
        assert user.role == UserRole.ANALYST

    def test_group_admin_mapping_promotes_and_flags_audit(self):
        team = uuid.uuid4()
        provider = _provider([_mapping("soc-admins", team, "admin")])
        user = _user(role=UserRole.VIEWER)
        result = reconcile_user_team_memberships(user, ["soc-admins"], provider)
        assert result.group_matched is True
        assert result.admin_granted_via_group is True
        assert user.role == UserRole.ADMIN

    def test_already_admin_via_group_no_double_audit(self):
        # Idempotency: a user already ADMIN does not re-flag the audit grant.
        team = uuid.uuid4()
        provider = _provider([_mapping("soc-admins", team, "admin")])
        user = _user(role=UserRole.ADMIN)
        result = reconcile_user_team_memberships(user, ["soc-admins"], provider)
        assert result.admin_granted_via_group is False

    @pytest.mark.asyncio
    async def test_reconcile_persists_via_session(self, test_session):
        """End-to-end through a real session + team rows."""
        team = Team(id=uuid.uuid4(), name="SOC")
        test_session.add(team)
        await test_session.flush()

        provider = SSOProvider(
            id=uuid.uuid4(), name="Persisted", enabled=True,
            issuer_url="https://idp", client_id="c", group_sync_enabled=True,
            groups_claim="groups",
        )
        provider.group_mappings.append(
            SSOGroupMapping(group_value="soc", team_id=team.id, role="analyst")
        )
        test_session.add(provider)
        await test_session.commit()

        # Re-load with the mappings eager-loaded, mirroring the callback path
        # (the callback uses selectinload), so reconcile never triggers lazy IO.
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        provider = (
            await test_session.execute(
                select(SSOProvider)
                .options(selectinload(SSOProvider.group_mappings))
                .where(SSOProvider.id == provider.id)
            )
        ).scalar_one()

        user = User(id=uuid.uuid4(), email="x@example.com", role=UserRole.VIEWER, is_active=True)
        test_session.add(user)
        await test_session.flush()

        reconcile_user_team_memberships(user, ["soc"], provider)
        await test_session.commit()
        await test_session.refresh(user)
        assert user.team_id == team.id
        assert user.role == UserRole.ANALYST
