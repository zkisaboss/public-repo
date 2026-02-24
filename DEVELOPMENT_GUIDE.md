# RoomSync Development Guide

## 1. Initial Setup

### Git Configuration

```bash
git config --global user.name "Your Full Name"
git config --global user.email "your.email@example.com"
```

### Environment Setup

If you don't have Python's package manager installed, download and install pip first: [https://pip.pypa.io/en/stable/installation/](https://pip.pypa.io/en/stable/installation/)

```bash
git clone <repository-url>
cd roomsync
pip install -r requirements.txt
cp .env.example .env  # Add ANTHROPIC_API_KEY (request from lead)
```

**Security:** Never commit `.env` to version control.

---

## 2. Branch Strategy

Never commit directly to `main`. Every change requires a branch.

### Workflow

```bash
git checkout main
git pull origin main
git checkout -b <branch-name>
# make changes, then:
git push origin <branch-name>
```

### Types (branches & commits)

Use the same type prefix for both branch names and commit messages.

| Type       | Use For                                       | Branch Example                  | Commit Example                                      |
|------------|-----------------------------------------------|---------------------------------|-----------------------------------------------------|
| `feat`     | New feature                                   | `feat/zk-grocery-sorting`      | `feat(groceries): add price sorting`                |
| `fix`      | Bug fix                                       | `fix/zk-login-redirect`        | `fix(auth): resolve session timeout`                |
| `docs`     | Documentation only                            | `docs/zk-update-readme`        | `docs(readme): update setup instructions`           |
| `style`    | Formatting, whitespace (no logic changes)     | `style/zk-button-colors`       | `style(nav): align header spacing`                  |
| `refactor` | Code restructuring (no new features or fixes) | `refactor/zk-extract-helpers`  | `refactor(api): extract validation utility`         |
| `test`     | Adding or updating tests                      | `test/zk-auth-unit-tests`      | `test(chores): add assignment rotation tests`       |
| `chore`    | Build scripts, deps, configs                  | `chore/zk-update-deps`         | `chore(deps): bump Flask to 3.1.2`                  |

**Branch naming:** `<type>/<initials>-<description>`

**Commit format:** `<type>(<scope>): <short description>` — imperative mood, ≤50 chars.

---

## 3. Development

### Local Server

```bash
python app.py
```

Access at `http://127.0.0.1:5000`

---

## 4. Testing

Tests run automatically on GitHub via CI on every push and pull request.

### Running Tests Locally

```bash
pytest           # Run all tests
pytest -v        # Verbose output
```

Tests use an in-memory SQLite database — no real database or API keys needed.

### Pre-Push Checklist

1. `pytest` passes with zero failures.
2. New routes or features have corresponding tests in `tests/`.

---

## 5. Code Review & Deployment

### Preview Deployment

```bash
git push origin <branch-name>
```

Vercel generates a preview URL at `<branch>.vercel.app`. Share this link for team review.

### Pull Request Checklist

1. Create PR on GitHub with a clear title and description of changes.
2. Link related issues (use `Closes #XX` in the PR description).
3. Confirm all tests pass in the PR checks.
4. Request reviewer assignment.
5. Obtain at least one approval before merging.

### Merge to Production

Approved PRs merged to `main` trigger automatic deployment.

---

## 6. Troubleshooting

| Issue                          | Command                            |
|--------------------------------|------------------------------------|
| Check current state            | `git status`                       |
| Discard file changes           | `git checkout -- <file>`           |
| Reset database                 | Delete `household.db`, restart app |
| Undo last commit (keep changes)| `git reset --soft HEAD~1`          |
| View branch history            | `git log --oneline -10`            |
| Run tests to diagnose issues   | `pytest -v --tb=short`             |