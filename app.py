
from flask import Flask, request, jsonify, g
from functools import wraps
import sqlite3
import bcrypt
import secrets
import hashlib
import time
from database import create_database

app = Flask(__name__)

# Create database tables when the application starts
create_database()


@app.route("/")
def home():
    return "Nestack Secure Records API is running!"


# STEP 1: User Registration
@app.route("/register", methods=["POST"])
def register():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data"}), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Username and password are required"}), 400

    username = username.strip()

    if len(username) < 3 or len(username) > 30:
        return jsonify({"error": "Username must be 3 to 30 characters"}), 400

    if len(password) < 8 or len(password) > 128:
        return jsonify({"error": "Password must be 8 to 128 characters"}), 400

    # Hash password using bcrypt
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )

    try:
        connection = sqlite3.connect("records.db")

        connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash.decode("utf-8"))
        )

        connection.commit()
        connection.close()

        return jsonify({
            "message": "User registered successfully"
        }), 201

    except sqlite3.IntegrityError:
        connection.close()
        return jsonify({"error": "Username already exists"}), 409


# STEP 2: User Login

# STEP 51: Login with Brute-Force Protection

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data"}), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Username and password are required"}), 400

    username = username.strip()

    if not username or len(username) > 30 or not password or len(password) > 128:
        return jsonify({"error": "Invalid username or password"}), 400

    connection = sqlite3.connect("records.db")

    user = connection.execute(
        """
        SELECT id, password_hash, failed_attempts, locked_until
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    if user is None:
        connection.close()
        return jsonify({"error": "Invalid username or password"}), 401

    current_time = time.time()

    # Check account lockout
    if user[3] is not None and user[3] > current_time:
        connection.close()
        return jsonify({"error": "Account temporarily locked"}), 429

    # Reset expired lockout
    if user[3] is not None and user[3] <= current_time:
        connection.execute(
            """
            UPDATE users
            SET failed_attempts = 0, locked_until = NULL
            WHERE id = ?
            """,
            (user[0],)
        )
        connection.commit()

    # Verify password
    if not bcrypt.checkpw(
        password.encode("utf-8"),
        user[1].encode("utf-8")
    ):

        failed_attempts = user[2] + 1

        if failed_attempts >= 5:
            locked_until = current_time + 900

            connection.execute(
                """
                UPDATE users
                SET failed_attempts = ?, locked_until = ?
                WHERE id = ?
                """,
                (failed_attempts, locked_until, user[0])
            )

            connection.commit()
            connection.close()

            return jsonify({
                "error": "Account temporarily locked"
            }), 429

        connection.execute(
            "UPDATE users SET failed_attempts = ? WHERE id = ?",
            (failed_attempts, user[0])
        )

        connection.commit()
        connection.close()

        return jsonify({
            "error": "Invalid username or password"
        }), 401

    # Reset failed attempts after successful login
    connection.execute(
        """
        UPDATE users
        SET failed_attempts = 0, locked_until = NULL
        WHERE id = ?
        """,
        (user[0],)
    )

    # Generate secure session token
    session_token = secrets.token_urlsafe(32)

    token_hash = hashlib.sha256(
        session_token.encode("utf-8")
    ).hexdigest()

    expires_at = current_time + 3600

    connection.execute(
        """
        INSERT INTO sessions
        (user_id, token_hash, expires_at, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (user[0], token_hash, expires_at, current_time)
    )

    connection.commit()
    connection.close()

    return jsonify({
        "message": "Login successful",
        "session_token": session_token,
        "token_type": "Bearer",
        "expires_in": 3600
    }), 200



# STEP 3: Token Authentication
def token_required(route_function):

    @wraps(route_function)
    def decorated(*args, **kwargs):

        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({
                "error": "Authorization token is missing"
            }), 401

        token = auth_header.split(" ", 1)[1].strip()

        if not token:
            return jsonify({
                "error": "Authorization token is missing"
            }), 401

        # Hash received token
        token_hash = hashlib.sha256(
            token.encode("utf-8")
        ).hexdigest()

        connection = sqlite3.connect("records.db")

        # Verify token and expiry
        session = connection.execute(
            """
            SELECT user_id
            FROM sessions
            WHERE token_hash = ? AND expires_at > ?
            """,
            (token_hash, time.time())
        ).fetchone()

        connection.close()

        if session is None:
            return jsonify({
                "error": "Invalid or expired token"
            }), 401

        g.user_id = session[0]
        g.token_hash = token_hash

        return route_function(*args, **kwargs)

    return decorated

# STEP 46: Logout and Session Revocation

@app.route("/logout", methods=["POST"])
@token_required
def logout():

    connection = sqlite3.connect("records.db")

    connection.execute(
        "DELETE FROM sessions WHERE token_hash = ?",
        (g.token_hash,)
    )

    connection.commit()
    connection.close()

    return jsonify({
        "message": "Logout successful. Session revoked."
    }), 200



# STEP 4: Protected Records API
@app.route("/records", methods=["GET"])
@token_required
def get_records():

    connection = sqlite3.connect("records.db")
    connection.row_factory = sqlite3.Row

    records = connection.execute(
        """
        SELECT id, title, body
        FROM records
        WHERE user_id = ?
        """,
        (g.user_id,)
    ).fetchall()

    connection.close()

    return jsonify({
        "records": [dict(record) for record in records]
    }), 200
# STEP 22: Create a Protected Record
@app.route("/records", methods=["POST"])
@token_required
def create_record():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data"}), 400

    title = data.get("title")
    body = data.get("body")

    if not isinstance(title, str) or not isinstance(body, str):
        return jsonify({
            "error": "Title and body are required"
        }), 400

    title = title.strip()
    body = body.strip()

    if not title or not body:
        return jsonify({
            "error": "Title and body cannot be empty"
        }), 400

    connection = sqlite3.connect("records.db")

    cursor = connection.execute(
        """
        INSERT INTO records (user_id, title, body)
        VALUES (?, ?, ?)
        """,
        (g.user_id, title, body)
    )

    record_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return jsonify({
        "message": "Record created successfully",
        "record_id": record_id
    }), 201

# STEP 50: Read a Single Record

@app.route("/records/<int:record_id>", methods=["GET"])
@token_required
def get_single_record(record_id):

    connection = sqlite3.connect("records.db")
    connection.row_factory = sqlite3.Row

    user = connection.execute(
        "SELECT role FROM users WHERE id = ?",
        (g.user_id,)
    ).fetchone()

    if user is None:
        connection.close()
        return jsonify({"error": "User not found"}), 401

    if user["role"] == "admin":
        record = connection.execute(
            """
            SELECT id, user_id, title, body
            FROM records
            WHERE id = ?
            """,
            (record_id,)
        ).fetchone()
    else:
        record = connection.execute(
            """
            SELECT id, title, body
            FROM records
            WHERE id = ? AND user_id = ?
            """,
            (record_id, g.user_id)
        ).fetchone()

    connection.close()

    if record is None:
        return jsonify({"error": "Record not found"}), 404

    return jsonify({"record": dict(record)}), 200

# STEP 32: Admin Records API

@app.route("/admin/records", methods=["GET"])
@token_required
def admin_get_records():

    connection = sqlite3.connect("records.db")
    connection.row_factory = sqlite3.Row

    # Check user role
    user = connection.execute(
        "SELECT role FROM users WHERE id = ?",
        (g.user_id,)
    ).fetchone()

    if user is None or user["role"] != "admin":
        connection.close()

        return jsonify({
            "error": "Admin access required"
        }), 403

    # Admin can view all records
    records = connection.execute(
        """
        SELECT id, user_id, title, body
        FROM records
        """
    ).fetchall()

    connection.close()

    return jsonify({
        "records": [dict(record) for record in records]
    }), 200


# Run Flask application
if __name__ == "__main__":
    app.run(debug=True)
