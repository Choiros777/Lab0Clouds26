from flask import Flask, request, jsonify
from dotenv import load_dotenv
import os

from models import db, User, Note
from auth import hash_password, check_password, create_token, get_current_user_id


load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


with app.app_context():
    db.create_all()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    username = username.strip()

    if not username:
        return jsonify({"error": "Username cannot be empty"}), 400

    existing_user = User.query.filter_by(username=username).first()

    if existing_user:
        return jsonify({"error": "Username already exists"}), 409

    password_hash = hash_password(password)

    user = User(
        username=username,
        password_hash=password_hash
    )

    db.session.add(user)
    db.session.commit()

    token = create_token(user.id)

    return jsonify({"token": token}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not check_password(password, user.password_hash):
        return jsonify({"error": "Invalid username or password"}), 401

    token = create_token(user.id)

    return jsonify({"token": token}), 200


@app.route("/api/notes", methods=["GET"])
def get_notes():
    user_id = get_current_user_id()

    if user_id is None:
        return jsonify({"error": "Unauthorized"}), 401

    notes = Note.query.filter_by(user_id=user_id).order_by(
        Note.created_at.desc()
    ).all()

    result = []

    for note in notes:
        result.append({
            "id": note.id,
            "title": note.title,
            "body": note.body,
            "created_at": note.created_at.isoformat()
        })

    return jsonify({"notes": result}), 200


@app.route("/api/notes", methods=["POST"])
def create_note():
    user_id = get_current_user_id()

    if user_id is None:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    title = data.get("title")
    body = data.get("body")

    if not title or not title.strip():
        return jsonify({"error": "Title is required"}), 400

    note = Note(
        user_id=user_id,
        title=title.strip(),
        body=body
    )

    db.session.add(note)
    db.session.commit()

    return jsonify({
        "id": note.id,
        "title": note.title,
        "body": note.body,
        "created_at": note.created_at.isoformat()
    }), 201


@app.route("/api/notes/<int:note_id>", methods=["DELETE"])
def delete_note(note_id):
    user_id = get_current_user_id()

    if user_id is None:
        return jsonify({"error": "Unauthorized"}), 401

    note = Note.query.filter_by(
        id=note_id,
        user_id=user_id
    ).first()

    if note is None:
        return jsonify({"error": "Note not found"}), 404

    db.session.delete(note)
    db.session.commit()

    return "", 204


if __name__ == "__main__":
    app.run(debug=True)