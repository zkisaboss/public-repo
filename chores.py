from flask import Flask, jsonify, request, render_template
from datetime import date
from dataclasses import dataclass, field
from typing import List, Optional

app = Flask(__name__)


# --- Domain model: matches class diagram exactly ---

@dataclass
class User:
    user_id: int
    name: str


@dataclass
class Chore:
    choreId: int
    name: str
    assignedUsers: List[User] = field(default_factory=list)
    lastCompletedBy: List[User] = field(default_factory=list)
    createdBy: Optional[User] = None
    nextDueBy: Optional[date] = None
    completed: bool = False


# --- Demo users (stand‑in for real authentication / FR1) ---

USERS = [
    User(user_id=1, name="Alice"),
    User(user_id=2, name="Bob"),
    User(user_id=3, name="Charlie"),
]

CURRENT_USER = USERS[0]  # pretend Alice is logged in


# --- In-memory storage (would be DB in real app) ---

chores: List[Chore] = []
next_chore_id = 1


# --- Helpers ---

def find_user(user_id: int) -> Optional[User]:
    return next((u for u in USERS if u.user_id == user_id), None)


def chore_to_dict(chore: Chore):
    return {
        "choreId": chore.choreId,
        "name": chore.name,
        "assignedUsers": [
            {"user_id": u.user_id, "name": u.name} for u in chore.assignedUsers
        ],
        "lastCompletedBy": [
            {"user_id": u.user_id, "name": u.name} for u in chore.lastCompletedBy
        ],
        "createdBy": (
            {"user_id": chore.createdBy.user_id, "name": chore.createdBy.name}
            if chore.createdBy
            else None
        ),
        "nextDueBy": chore.nextDueBy.isoformat() if chore.nextDueBy else None,
        "completed": chore.completed,
    }


# --- Routes ---

@app.route("/")
def index():
    return render_template("chores.html", users=USERS)


@app.route("/api/users", methods=["GET"])
def get_users():
    return jsonify([{"user_id": u.user_id, "name": u.name} for u in USERS])


# FR9 + FR12: list/create chores
@app.route("/api/chores", methods=["GET", "POST"])
def chores_collection():
    global next_chore_id

    if request.method == "GET":
        return jsonify([chore_to_dict(c) for c in chores])

    data = request.get_json()
    name = data.get("name", "").strip()
    next_due_str = data.get("nextDueBy")
    assigned_ids = data.get("assignedUserIds", [])

    if not name:
        return jsonify({"error": "name is required"}), 400

    next_due = date.fromisoformat(next_due_str) if next_due_str else None
    assigned_users = [find_user(uid) for uid in assigned_ids if find_user(uid)]

    chore = Chore(
        choreId=next_chore_id,
        name=name,
        assignedUsers=assigned_users,
        lastCompletedBy=[],
        createdBy=CURRENT_USER,
        nextDueBy=next_due,
        completed=False,
    )
    next_chore_id += 1
    chores.append(chore)
    return jsonify(chore_to_dict(chore)), 201


# FR9: mark as completed
@app.route("/api/chores/<int:chore_id>/complete", methods=["POST"])
def complete_chore(chore_id):
    for chore in chores:
        if chore.choreId == chore_id:
            chore.completed = True
            chore.lastCompletedBy.append(CURRENT_USER)
            return jsonify(chore_to_dict(chore))
    return jsonify({"error": "chore not found"}), 404


# FR10: simple recurring / auto‑assign rotation
@app.route("/api/chores/<int:chore_id>/auto-assign", methods=["POST"])
def auto_assign_chore(chore_id):
    for chore in chores:
        if chore.choreId == chore_id:
            if chore.assignedUsers:
                # rotate: move first user to end
                first = chore.assignedUsers.pop(0)
                chore.assignedUsers.append(first)
            chore.completed = False
            return jsonify(chore_to_dict(chore))
    return jsonify({"error": "chore not found"}), 404


if __name__ == "__main__":
    app.run(debug=True)
