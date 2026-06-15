# Plan 004: Encrypt the pending TOTP setup secret at rest (`TwoFactorToken.token_data`)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If a
> "STOP condition" occurs, stop and report. When done, update this plan's row
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat ccf9970..HEAD -- backend/app/models/two_factor_token.py backend/app/api/auth.py backend/app/models/user.py`
> If these changed since this plan was written, compare the "Current state"
> excerpts to the live code before proceeding; on a mismatch, STOP.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: 001 (for CI to run the new test)
- **Category**: security
- **Planned at**: commit `ccf9970`, 2026-06-15

## Why this matters

During 2FA enrollment, the freshly generated TOTP secret is written to `TwoFactorToken.token_data` as **plaintext** and lives there for the 10-minute setup window. The column's own docstring claims it holds "the encrypted secret or temporary token", but nothing encrypts it. By contrast the *permanent* secret on the user (`User.totp_secret`) **is** encrypted at rest via a property that calls `encrypt()`/`decrypt_with_fallback()`. This plan closes the gap so a database snapshot taken mid-enrollment can't yield a usable TOTP seed, and makes the column match its documented contract. The fix reuses the existing `app/core/encryption.py` helpers and needs **no DB migration** (same column, same type) because `decrypt_with_fallback()` tolerates any pre-existing plaintext rows, which self-expire within 10 minutes anyway.

## Current state

- `backend/app/core/encryption.py` — the helpers to reuse:
  - `encrypt(plaintext: str) -> str` (line 62)
  - `decrypt_with_fallback(value: str | None) -> str | None` (line 74) — returns the value unchanged if it isn't Fernet ciphertext, so legacy plaintext rows keep working.
- Exemplar of the exact pattern to mirror — `backend/app/models/user.py:65-78`:

```python
    totp_secret_encrypted: Mapped[str | None] = mapped_column(
        "totp_secret", String(255), nullable=True
    )
    @property
    def totp_secret(self) -> str | None:
        return decrypt_with_fallback(self.totp_secret_encrypted)
    @totp_secret.setter
    def totp_secret(self, value: str | None) -> None:
        self.totp_secret_encrypted = encrypt(value) if value else None
```

- `backend/app/models/two_factor_token.py:35` — the plaintext column today:

```python
    token_data: Mapped[str] = mapped_column(String(500), nullable=False)
```

- `backend/app/models/two_factor_token.py:84-95` — `create_token(...)` constructs the row passing `token_data=token_data` straight into the constructor (plaintext).
- `backend/app/models/two_factor_token.py` — `get_valid_token(...)` returns the row; callers read `.token_data` directly.
- Read/write call sites in `backend/app/api/auth.py` (all go through the column or `create_token`): writes at `:421`, `:1032`, `:1124` (line 1124 is the TOTP setup secret: `token_data=secret`); reads at `:1070`, `:1152` (`pending_secret = pending_token.token_data`), `:1232`. Note `token_data` is dual-purpose — for `login`/exchange tokens it stores `str(user.id)`; for `setup` it stores the TOTP secret. Encrypting all of them transparently is fine (user-id values just become opaque at rest).

Repo conventions: SQLAlchemy 2.0 declarative `Mapped[...]` + `mapped_column`. The user-model property approach is the established pattern for encrypted-at-rest columns — match it exactly.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| TOTP tests | `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/services/test_totp.py -q` | all pass |
| Auth-related tests | `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/ -k "totp or two_factor or auth" -q` | all pass |
| Lint | `docker compose -f docker-compose.dev.yml run --rm backend ruff check app/models/two_factor_token.py` | exit 0 |

## Scope

**In scope**:
- `backend/app/models/two_factor_token.py`
- `backend/tests/services/test_totp.py` (add a regression test)

**Out of scope** (do NOT touch):
- `backend/app/models/user.py` — already encrypted; reference only.
- `backend/app/api/auth.py` — call sites read/write `.token_data` and call `create_token(token_data=...)`; the property approach keeps all of them working with no edits. Do not change auth.py.
- No Alembic migration — the column name and type are unchanged.

## Git workflow

- Branch: `advisor/004-encrypt-totp-setup-token`
- Commit message: `fix(security): encrypt pending TOTP setup secret at rest`
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Make `token_data` an encrypt-on-write / decrypt-on-read property

In `backend/app/models/two_factor_token.py`:

1. Add the import: `from app.core.encryption import decrypt_with_fallback, encrypt`.
2. Rename the mapped column attribute to `token_data_encrypted`, keeping the **DB column name** `"token_data"` and the same type:

```python
    token_data_encrypted: Mapped[str] = mapped_column(
        "token_data", String(500), nullable=False
    )

    @property
    def token_data(self) -> str:
        return decrypt_with_fallback(self.token_data_encrypted) or ""

    @token_data.setter
    def token_data(self, value: str) -> None:
        self.token_data_encrypted = encrypt(value)
```

This mirrors `user.py` exactly. Every existing `.token_data` read now decrypts transparently; legacy plaintext rows are returned as-is by `decrypt_with_fallback`.

### Step 2: Set via the property in `create_token`

`create_token(...)` currently constructs the row with `token_data=token_data` in the constructor. Because `token_data` is now a Python property (not a mapped column attr), it cannot be passed to the declarative constructor. Change the construction to set it after instantiation so the setter (and thus `encrypt`) runs:

```python
        token = cls(
            user_id=user_id,
            token_type=token_type,
            expires_at=datetime.now(UTC) + timedelta(minutes=expires_minutes),
        )
        token.token_data = token_data
        db_session.add(token)
        await db_session.flush()
        return token
```

Leave the method signature (`token_data: str` parameter) unchanged so the three `auth.py` call sites need no edits.

**Verify**: `docker compose -f docker-compose.dev.yml run --rm backend ruff check app/models/two_factor_token.py` → exit 0.

### Step 3: Add a regression test

In `backend/tests/services/test_totp.py` (mirror its existing async + fixture style), add a test that:
- Calls `TwoFactorToken.create_token(db, user_id="u@example.com", token_type="setup", token_data="JBSWY3DPEHPK3PXP")`.
- Asserts the raw stored column `token.token_data_encrypted` is **not equal** to the plaintext `"JBSWY3DPEHPK3PXP"` (i.e. it was encrypted).
- Asserts the property `token.token_data` round-trips back to `"JBSWY3DPEHPK3PXP"`.
- Optionally: a plaintext legacy row (set `token_data_encrypted` directly to a non-ciphertext string) is still readable via `.token_data` (fallback path).

Tests run with `CHAD_ENCRYPTION_KEY` from the dev/test environment; the dev default is allowed in DEBUG/test mode (see `encryption.py:get_encryption_key`).

**Verify**: `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/services/test_totp.py -q` → all pass including the new test.

## Test plan

- New regression test in `tests/services/test_totp.py`: stored column is ciphertext, property round-trips, legacy plaintext still readable. These cover exactly the behavior this plan introduces.
- Run the broader auth/2FA selection to confirm no call site regressed: `pytest tests/ -k "totp or two_factor or auth" -q`.

## Done criteria

ALL must hold:

- [ ] `grep -n "token_data_encrypted" backend/app/models/two_factor_token.py` shows the renamed column + property
- [ ] `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/services/test_totp.py -q` → all pass; new ciphertext/round-trip test present
- [ ] `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/ -k "totp or two_factor or auth" -q` → all pass
- [ ] `ruff check app/models/two_factor_token.py` exits 0
- [ ] No edits to `auth.py`, `user.py`, or any migration (`git status`)
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back if:
- The "Current state" excerpts don't match the live files (drift).
- Any auth/2FA test that passed before your change now fails (a call site assumed plaintext in the DB) — report which one rather than editing auth.py.
- The declarative constructor still accepts `token_data=` after the rename (it shouldn't) and tests pass without Step 2 — double-check the secret is actually being encrypted before declaring done.

## Maintenance notes

- The same pattern applies to any future token columns; reuse `encrypt`/`decrypt_with_fallback`.
- No migration is needed now, but if a future migration ever re-types this column, preserve the DB name `token_data`.
- Reviewer should confirm the column's docstring ("encrypted secret") is now accurate, and that `create_token` sets via the property (not the constructor).
