# RoomSync Development Guide

## 1. Initial Setup

### Git Configuration
```bash
git config --global user.name "Your Full Name"
git config --global user.email "your.email@example.com"
```

### Environment Setup
```bash
git clone <repository-url>
cd roomsync
pip install -r requirements.txt
cp .env.example .env  # Add ANTHROPIC_API_KEY (request from lead)
```

> **Security**: Never commit `.env` to version control.

---

## 2. Branch Strategy

**Never commit directly to `main`.** Every change requires a branch.

### Workflow
```bash
git checkout main
git pull origin main
git checkout -b <branch-name>
# make changes, then:
git push origin <branch-name>
```

### Naming: `<type>/<initials>-<description>`

| Type | Example |
|------|---------|
| `feat` | `feat/zk-grocery-sorting` |
| `fix` | `fix/zk-login-redirect` |
| `docs` | `docs/zk-update-readme` |
| `style` | `style/zk-button-colors` |
---

## 3. Development

### Local Server
```bash
python app.py
```
Access at `http://127.0.0.1:5001`

---

## 4. Commits

### Format
```
<type>(<scope>): <description>
```

**Rules**:
- Use imperative mood ("add" not "added")
- Limit subject to 50 characters
- Scope = affected component

**Examples**:
```bash
git commit -m "feat(groceries): add price sorting"
git commit -m "fix(auth): resolve session timeout bug"
git commit -m "docs(readme): update setup instructions"
```

---

## 5. Code Review & Deployment

### Preview Deployment
```bash
git push origin <branch-name>
```
Vercel generates a preview URL at `<branch>.vercel.app`. Share this link for team review.

### Pull Request Checklist
1. Create PR on GitHub with clear description
2. Link related issues
3. Request reviewer assignment
4. Obtain approval before merging

### Merge to Production
Approved PRs merged to `main` trigger automatic deployment.

---

## 6. Troubleshooting

| Issue | Command |
|-------|---------|
| Check current state | `git status` |
| Discard file changes | `git checkout -- <file>` |
| Reset database | Delete `household.db`, restart app |
| Undo last commit (keep changes) | `git reset --soft HEAD~1` |
| View branch history | `git log --oneline -10` |