import os
import re
import secrets
from functools import wraps

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.security import generate_password_hash, check_password_hash


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "sqlite:///secure_users.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# =========================================================
# SECURITY KEYS
# =========================================================

AES_KEY_HEX = os.getenv("AES_256_KEY")
CAPABILITY_CODE = os.getenv("CAPABILITY_CODE")


if not AES_KEY_HEX:
    raise RuntimeError(
        "AES_256_KEY is not set."
    )


if len(AES_KEY_HEX) != 64:
    raise RuntimeError(
        "AES_256_KEY must contain exactly 64 hexadecimal characters."
    )


if not CAPABILITY_CODE:
    raise RuntimeError(
        "CAPABILITY_CODE is not set."
    )


try:
    AES_KEY = bytes.fromhex(AES_KEY_HEX)

except ValueError:
    raise RuntimeError(
        "AES_256_KEY must contain only hexadecimal characters."
    )


if len(AES_KEY) != 32:
    raise RuntimeError(
        "AES key must be exactly 32 bytes / 256 bits."
    )


# =========================================================
# DATABASE MODEL
# =========================================================

class User(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    email_encrypted = db.Column(
        db.LargeBinary,
        nullable=False
    )

    phone_encrypted = db.Column(
        db.LargeBinary,
        nullable=False
    )


# =========================================================
# AES-256-GCM ENCRYPTION
# =========================================================

def encrypt_data(data):

    nonce = secrets.token_bytes(12)

    encrypted_data = AESGCM(AES_KEY).encrypt(
        nonce,
        data.encode("utf-8"),
        None
    )

    return nonce + encrypted_data


def decrypt_data(encrypted_data):

    nonce = encrypted_data[:12]

    ciphertext = encrypted_data[12:]

    decrypted_data = AESGCM(AES_KEY).decrypt(
        nonce,
        ciphertext,
        None
    )

    return decrypted_data.decode("utf-8")


# =========================================================
# CAPABILITY CODE SECURITY
# =========================================================

def capability_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        supplied_code = request.headers.get(
            "X-Capability-Code",
            ""
        )

        if not supplied_code:

            return jsonify({
                "error": "Capability code is required"
            }), 403

        if not secrets.compare_digest(
            supplied_code,
            CAPABILITY_CODE
        ):

            return jsonify({
                "error": "Access denied"
            }), 403

        return function(*args, **kwargs)

    return wrapper


# =========================================================
# SQL INJECTION DETECTION
# =========================================================

def detect_sql_injection(value):

    if not isinstance(value, str):
        return False

    patterns = [

        r"(?i)\bunion\s+select\b",

        r"(?i)\bor\s+1\s*=\s*1\b",

        r"(?i)\band\s+1\s*=\s*1\b",

        r"(?i)\bdrop\s+table\b",

        r"(?i)\bdelete\s+from\b",

        r"(?i)\binsert\s+into\b",

        r"(?i)\bupdate\s+\w+\s+set\b",

        r"--",

        r"/\*",

        r"\*/",

        r";\s*(select|insert|update|delete|drop)\b"
    ]

    for pattern in patterns:

        if re.search(pattern, value):
            return True

    return False


# =========================================================
# USERNAME VALIDATION
# =========================================================

def validate_username(username):

    if not isinstance(username, str):
        return False

    if len(username) < 3 or len(username) > 50:
        return False

    return re.fullmatch(
        r"[A-Za-z0-9_.-]+",
        username
    ) is not None


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({

        "project":
        "SQL Injection Detection and Secure Data Storage",

        "status":
        "running",

        "security_features": [

            "AES-256-GCM encryption",

            "Password hashing",

            "Capability-code authentication",

            "Parameterized SQL queries",

            "SQL injection detection",

            "Input validation"
        ]

    })


# =========================================================
# CREATE USER
# =========================================================

@app.route(
    "/api/users",
    methods=["POST"]
)
@capability_required
def create_user():

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({
            "error": "JSON request body is required"
        }), 400


    username = data.get(
        "username",
        ""
    )

    password = data.get(
        "password",
        ""
    )

    email = data.get(
        "email",
        ""
    )

    phone = data.get(
        "phone",
        "")


    # Username validation

    if not validate_username(username):

        return jsonify({
            "error":
            "Invalid username"
        }), 400


    # Password validation

    if not isinstance(password, str):

        return jsonify({
            "error":
            "Invalid password"
        }), 400


    if len(password) < 8:

        return jsonify({
            "error":
            "Password must contain at least 8 characters"
        }), 400


    # Required fields

    if not email:

        return jsonify({
            "error":
            "Email is required"
        }), 400


    if not phone:

        return jsonify({
            "error":
            "Phone number is required"
        }), 400


    # SQL Injection detection

    fields = {
        "username": username,
        "email": email,
        "phone": phone
    }


    for field_name, value in fields.items():

        if detect_sql_injection(value):

            return jsonify({

                "error":
                "Request blocked by SQL injection detection",

                "field":
                field_name

            }), 400


    # Parameterized database query

    existing_user = User.query.filter_by(
        username=username
    ).first()


    if existing_user:

        return jsonify({
            "error":
            "Username already exists"
        }), 409


    # Create user

    user = User(

        username=username,

        # Password is hashed, not reversibly encrypted

        password_hash=generate_password_hash(
            password
        ),

        # Sensitive data is AES-256 encrypted

        email_encrypted=encrypt_data(
            email
        ),

        phone_encrypted=encrypt_data(
            phone
        )
    )


    db.session.add(user)

    db.session.commit()


    return jsonify({

        "message":
        "User created securely",

        "user_id":
        user.id

    }), 201


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/api/login",
    methods=["POST"]
)
@capability_required
def login():

    data = request.get_json(
        silent=True
    )


    if not data:

        return jsonify({
            "error":
            "JSON request body is required"
        }), 400


    username = data.get(
        "username",
        ""
    )

    password = data.get(
        "password",
        ""
    )


    if not validate_username(username):

        return jsonify({
            "error":
            "Invalid credentials"
        }), 401


    # Parameterized query

    user = User.query.filter_by(
        username=username
    ).first()


    if not user:

        return jsonify({
            "error":
            "Invalid credentials"
        }), 401


    if not check_password_hash(
        user.password_hash,
        password
    ):

        return jsonify({
            "error":
            "Invalid credentials"
        }), 401


    return jsonify({

        "message":
        "Authentication successful",

        "user_id":
        user.id

    })


# =========================================================
# GET USER
# =========================================================

@app.route(
    "/api/users/<int:user_id>",
    methods=["GET"]
)
@capability_required
def get_user(user_id):

    # Parameterized database lookup

    user = db.session.get(
        User,
        user_id
    )


    if not user:

        return jsonify({
            "error":
            "User not found"
        }), 404


    # Decrypt sensitive information

    email = decrypt_data(
        user.email_encrypted
    )

    phone = decrypt_data(
        user.phone_encrypted
    )


    return jsonify({

        "id":
        user.id,

        "username":
        user.username,

        "email":
        email,

        "phone":
        phone

    })


# =========================================================
# SEARCH USER
# =========================================================

@app.route(
    "/api/search",
    methods=["GET"]
)
@capability_required
def search_user():

    username = request.args.get(
        "username",
        ""
    )


    if not validate_username(username):

        return jsonify({
            "error":
            "Invalid username"
        }), 400


    if detect_sql_injection(username):

        return jsonify({

            "error":
            "Request blocked by SQL injection detection"

        }), 400


    # Parameterized query

    user = User.query.filter_by(
        username=username
    ).first()


    if not user:

        return jsonify({
            "found":
            False
        })


    return jsonify({

        "found":
        True,

        "id":
        user.id,

        "username":
        user.username

    })


# =========================================================
# SQL INJECTION SECURITY TEST
# =========================================================

@app.route(
    "/api/security-test",
    methods=["POST"]
)
@capability_required
def security_test():

    data = request.get_json(
        silent=True
    )


    if not data:

        return jsonify({
            "error":
            "JSON request body is required"
        }), 400


    test_input = str(
        data.get(
            "input",
            ""
        )
    )


    blocked = detect_sql_injection(
        test_input
    )


    return jsonify({

        "input_checked":
        True,

        "blocked_by_secondary_layer":
        blocked,

        "parameterized_queries_enabled":
        True,

        "message":
        "User input is never executed directly as SQL."

    })


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def page_not_found(error):

    return jsonify({
        "error":
        "Endpoint not found"
    }), 404


@app.errorhandler(500)
def internal_server_error(error):

    db.session.rollback()

    return jsonify({
        "error":
        "Internal server error"
    }), 500


# =========================================================
# CREATE DATABASE
# =========================================================

with app.app_context():

    db.create_all()


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    port = int(
        os.getenv(
            "PORT",
            "5000"
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )