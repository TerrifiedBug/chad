# CHAD - Cyber Hunting And Detection

Web-based Sigma rule management and alerting platform for OpenSearch.

## Critical Rules

**NEVER:**
1. Run Python/Node directly on host - Always use Docker
2. Commit `internal-docs/` - Gitignored globally
3. Add AI co-author lines to commits (no "Co-Authored-By")
4. Push directly to main - Branch protection enabled
5. Generate package-lock locally - Use Docker command below
6. Assume a library is available - Check codebase first
7. Silently retry failures - Stop, report, ask
8. Refactor unless explicitly requested
9. Use `git add .` or `git add -A` - Add files individually
10. Create new files unless absolutely necessary - Prefer editing existing
11. Use f-strings in logging - Use parameterized format to prevent log injection: `logger.info("msg %s", var)` not `logger.info(f"msg {var}")`

**ALWAYS:**
1. Read files before modifying them
2. Use existing patterns over inventing new ones
3. Run verification after changes (tests, lint, typecheck)
4. Ask before architectural changes or new dependencies
5. Commit changes to working branch - Never leave uncommitted work

## AI Operating Contract

### Before Acting
- Check for existing implementations first
- Understand the pattern before adding to it
- If unsure, propose options instead of choosing silently
- **Chesterton's Fence**: Can't explain why something exists? Don't touch it until you can

### Autonomy Boundaries
Stop and ask when:
- Ambiguous intent or unexpected state
- Anything irreversible (migrations, API changes, deletions)
- Scope change discovered
- Choosing between valid approaches with tradeoffs
- Data model, API contract, or index mapping changes

### On Failures
NEVER silently retry. When something fails:
1. State what failed (raw error)
2. Theory about why
3. Proposed fix
4. Ask before proceeding

### Code Quality
- Avoid over-engineering - Only make changes directly requested
- Don't add features, refactor, or "improve" beyond what was asked
- Don't add comments/docstrings to code you didn't change
- Keep solutions simple and focused

### Communication
- Be concise - Don't over-explain actions
- Don't apologize for errors - Fix them
- Surface disagreement; don't bury contradictions

## Environment Variables

For local development with external services (OpenSearch, MISP), create a `.env.local` file:

```bash
# .env.local (not committed to git)
OPENSEARCH_HOST=https://your-opensearch:9200
OPENSEARCH_USER=chad
OPENSEARCH_PASSWORD=your-password
MISP_HOST=https://your-misp:443
MISP_KEY=your-misp-api-key
```

Source it before running docker-compose:
```bash
source .env.local && docker compose -f docker-compose.dev.yml up -d
```

## Verification Commands

```bash
# Start development environment (with external services)
source .env.local && docker compose -f docker-compose.dev.yml up -d

# Start development environment (local only)
docker compose -f docker-compose.dev.yml up -d

# Backend verification
docker compose -f docker-compose.dev.yml run --rm backend pytest
docker compose -f docker-compose.dev.yml run --rm backend ruff check .

# Frontend verification
docker compose -f docker-compose.dev.yml run --rm frontend npm test
docker compose -f docker-compose.dev.yml run --rm frontend npm run lint

# Integration tests (requires OpenSearch running)
docker compose -f docker-compose.dev.yml up opensearch -d
docker compose -f docker-compose.dev.yml run --rm backend pytest tests/integration/ -m integration

# Skip integration tests in fast runs
docker compose -f docker-compose.dev.yml run --rm backend pytest -m "not integration" --ignore=tests/integration

# Package-lock generation (MUST use this, not local npm)
docker run --rm -v "$PWD/frontend:/app" -w /app node:20-slim npm install --package-lock-only
```

## CodeQL Security Scanning (Run Before Committing)

Run CodeQL locally to catch security issues before pushing. Much faster than waiting for GitHub CI.

```bash
# Install CodeQL CLI (one-time)
brew install codeql
codeql pack download codeql/python-queries
codeql pack download codeql/javascript-queries

# Python backend - create database and run security queries
codeql database create --language=python --source-root=backend codeql-db-backend --overwrite
codeql database analyze codeql-db-backend --format=csv --output=codeql-python.csv codeql/python-queries

# TypeScript frontend - create database and run security queries
codeql database create --language=javascript --source-root=frontend codeql-db-frontend --overwrite
codeql database analyze codeql-db-frontend --format=csv --output=codeql-js.csv codeql/javascript-queries

# Run specific query (e.g., log injection only)
codeql database analyze codeql-db-backend --format=csv --output=results.csv \
  "codeql/python-queries:Security/CWE-117/LogInjection.ql"

# Clean up databases when done
rm -rf codeql-db-backend codeql-db-frontend codeql-*.csv
```

**Common security queries:**
- `Security/CWE-117/LogInjection.ql` - Log injection
- `Security/CWE-078/CommandInjection.ql` - Command injection
- `Security/CWE-089/SqlInjection.ql` - SQL injection
- `Security/CWE-079/ReflectedXss.ql` - XSS

## Protected Areas (Do Not Modify Without Approval)

- `migrations/` - Database schema changes require review
- `internal-docs/` - Never commit (gitignored globally)
- `.env` / `.env.local` - Never commit (`.env.example` is OK)
- `docker-compose.yml` - Production config
- API contracts / data models / index mappings

## Project Architecture

| Layer | Technology | Location |
|-------|------------|----------|
| Frontend | React + shadcn/ui + Tailwind | `frontend/` |
| Backend | FastAPI + pySigma | `backend/` |
| Database | PostgreSQL | Docker service |
| Search | OpenSearch | External infrastructure |

### Domain Concepts
- **Push Mode**: OpenSearch alerting monitors push alerts to CHAD queue
- **Pull Mode**: CHAD polls OpenSearch on schedule for rule matches
- Index patterns configured via `detection_mode` field

### Key Files
- Frontend entry: `frontend/src/main.tsx` → `App.tsx`
- API client: `frontend/src/lib/api.ts`
- Backend routes: `backend/app/api/`
- Settings page: `frontend/src/pages/Settings.tsx` (large file, ~2600 lines)

## Gotchas

- Docker compose files at **project root**, not subdirectories
- Integration tests use `pytest.importorskip` for optional deps (testcontainers)
- TypeScript types may differ from intuitive names - Always check type definitions
- First-run setup wizard creates admin account (no hardcoded credentials)
- All config (except DB credentials) managed via GUI, not env vars

## Git Workflow

- Main branch is write-protected - Use feature branches or worktrees
- Conventional commits: `feat|fix|refactor|docs|test|chore`
- Test locally before committing
- Add files individually, never `git add .`

### Worktrees (Parallel Agentic Sessions)

Run multiple Claude sessions at once without branches colliding. Each session gets its own
worktree + branch + working directory, so edits, commits, and dev containers stay isolated.

```bash
# Create a worktree for a new task (branch + directory in one step)
git worktree add ../chad-<task-slug> -b <type>/<task-slug>

# Example: two concurrent sessions
git worktree add ../chad-rbac-fix    -b fix/rbac-scope
git worktree add ../chad-ingest-perf -b perf/ingest-bulk

# Open each in its own Claude session, cd'd into that directory
cd ../chad-rbac-fix     # session A
cd ../chad-ingest-perf  # session B

# List / inspect active worktrees
git worktree list

# Remove when the branch is merged or abandoned
git worktree remove ../chad-<task-slug>
git worktree prune          # clean up stale metadata
```

**Rules for worktree sessions:**
- One task = one worktree = one branch. Never run two agentic sessions in the same directory.
- Name the worktree dir `chad-<task-slug>` (sibling of the main repo), branch `<type>/<task-slug>`.
- Each worktree needs its own dev stack — use distinct compose project names / ports to avoid
  clashes: `docker compose -p chad-<task-slug> -f docker-compose.dev.yml up -d`.
- `.env.local` is not copied into new worktrees — symlink or re-create it per worktree.
- Commit before `git worktree remove`; removal of a dirty worktree is blocked (use `--force` only
  when you intend to discard).
- Keep the main checkout (`chad/`) on a clean branch for reviews; do task work in worktrees.

## Refactoring Rules
- NEVER remove comments that explain "why" — ordering constraints, external system behavior, non-obvious side effects, or business logic
- Only remove comments that merely restate what the code does
- When in doubt, keep the comment

### Release Process
1. Update versions in `frontend/package.json` and `backend/pyproject.toml`
2. Create PR, ensure CI passes
3. Merge to main
4. Create tag: `git tag -a v0.1.0 -m "Release v0.1.0"`
5. Push tag: `git push origin v0.1.0`
6. GitHub Actions builds images and creates release

## When Stopping Mid-Task

Leave summary of:
1. State of work (done/in progress/untouched)
2. Current blockers or open questions
3. Files touched

---

<claude-mem-context>
# Recent Activity

<!-- This section is auto-generated by claude-mem. Edit content outside the tags. -->

*No recent activity*
</claude-mem-context>
