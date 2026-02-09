from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

# In-memory chore storage
chores = []
chore_id_counter = 1


@app.route("/chores", methods=["GET"])
def get_chores():
    return jsonify(chores)


@app.route("/chores", methods=["POST"])
def create_chore():
    global chore_id_counter

    data = request.json

    chore = {
        "choreId": chore_id_counter,
        "name": data["name"],
        "assignedUsers": data.get("assignedUsers", []),
        "createdBy": data.get("createdBy", "system"),
        "lastCompletedBy": None,
        "nextDueBy": data.get("nextDueBy"),
        "completed": False
    }

    chores.append(chore)
    chore_id_counter += 1

    return jsonify(chore), 201


@app.route("/chores/<int:chore_id>/complete", methods=["PUT"])
def complete_chore(chore_id):
    data = request.json

    for chore in chores:
        if chore["choreId"] == chore_id:
            chore["completed"] = True
            chore["lastCompletedBy"] = data.get("completedBy", "unknown")
            return jsonify(chore)

    return jsonify({"error": "Chore not found"}), 404


@app.route("/chores/<int:chore_id>", methods=["DELETE"])
def delete_chore(chore_id):
    global chores
    chores = [c for c in chores if c["choreId"] != chore_id]
    return jsonify({"message": "Chore deleted"})


if __name__ == "__main__":
    app.run(debug=True)
