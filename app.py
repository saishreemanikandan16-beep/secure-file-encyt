from flask import (
    Flask, request, redirect, url_for,
    render_template_string, send_file, flash
)
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from io import BytesIO
from pathlib import Path
import sqlite3
import secrets
import os
import time


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

# Used by Flask for flash messages.
# Change this to a long random value before deploying publicly.
app.secret_key = secrets.token_hex(32)

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "encrypted_storage"
DATABASE = BASE_DIR / "secure_files.db"

STORAGE_DIR.mkdir(exist_ok=True)

# Maximum upload size: 10 MB
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# Cryptography settings
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

# PBKDF2 iteration count
PBKDF2_ITERATIONS = 600_000

# File format identifier
FILE_MAGIC = b"SFE1"


# ============================================================
# DATABASE
# ============================================================

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            encrypted_size INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            file_name TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def log_activity(action, file_name, status):
    connection = get_db()

    connection.execute(
        """
        INSERT INTO activity
        (action, file_name, status, created_at)
        VALUES (?, ?, ?, datetime('now', 'localtime'))
        """,
        (action, file_name, status)
    )

    connection.commit()
    connection.close()


# ============================================================
# CRYPTOGRAPHY FUNCTIONS
# ============================================================

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Convert the user's password into a 256-bit encryption key.
    PBKDF2 makes password guessing more expensive.
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )

    return kdf.derive(password.encode("utf-8"))


def encrypt_file(file_data: bytes, password: str) -> bytes:
    """
    Encrypt file data using AES-256-GCM.

    Stored format:

    SFE1 + SALT + NONCE + ENCRYPTED DATA
    """

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)

    aes = AESGCM(key)

    encrypted_data = aes.encrypt(
        nonce,
        file_data,
        None
    )

    return (
        FILE_MAGIC
        + salt
        + nonce
        + encrypted_data
    )


def decrypt_file(encrypted_data: bytes, password: str) -> bytes:
    """
    Decrypt an encrypted SFE file.
    """

    minimum_size = (
        len(FILE_MAGIC)
        + SALT_SIZE
        + NONCE_SIZE
        + 16
    )

    if len(encrypted_data) < minimum_size:
        raise ValueError("Invalid encrypted file.")

    if not encrypted_data.startswith(FILE_MAGIC):
        raise ValueError("This is not a valid SFE encrypted file.")

    position = len(FILE_MAGIC)

    salt = encrypted_data[
        position:position + SALT_SIZE
    ]

    position += SALT_SIZE

    nonce = encrypted_data[
        position:position + NONCE_SIZE
    ]

    position += NONCE_SIZE

    ciphertext = encrypted_data[position:]

    key = derive_key(password, salt)

    aes = AESGCM(key)

    try:
        return aes.decrypt(
            nonce,
            ciphertext,
            None
        )

    except InvalidTag:
        raise ValueError(
            "Incorrect password or corrupted encrypted file."
        )


# ============================================================
# HTML TEMPLATE
# ============================================================

PAGE = """
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>Secure File Vault</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: #eef3f8;
    color: #17202a;
}

header {
    background: #102a43;
    color: white;
    padding: 25px;
}

header h1 {
    margin: 0;
}

header p {
    margin: 7px 0 0;
    color: #c9d8e6;
}

.container {
    width: 92%;
    max-width: 1100px;
    margin: 30px auto;
}

.cards {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(300px, 1fr));
    gap: 25px;
}

.card {
    background: white;
    padding: 25px;
    border-radius: 15px;
    box-shadow: 0 5px 20px rgba(0,0,0,0.08);
}

.card h2 {
    margin-top: 0;
    color: #102a43;
}

input[type="file"],
input[type="password"] {
    width: 100%;
    padding: 12px;
    margin: 10px 0 15px;
    border: 1px solid #ccd6e0;
    border-radius: 8px;
}

button,
.btn {
    display: inline-block;
    border: none;
    background: #147d92;
    color: white;
    padding: 11px 18px;
    border-radius: 8px;
    cursor: pointer;
    text-decoration: none;
}

button:hover,
.btn:hover {
    background: #0d6274;
}

.warning {
    background: #fff4d6;
    padding: 12px;
    border-radius: 8px;
    margin-bottom: 15px;
}

.success {
    background: #dff6e5;
    padding: 12px;
    border-radius: 8px;
    margin-bottom: 15px;
}

.error {
    background: #ffe0e0;
    padding: 12px;
    border-radius: 8px;
    margin-bottom: 15px;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}

th, td {
    text-align: left;
    padding: 12px;
    border-bottom: 1px solid #e0e6ec;
}

th {
    background: #f1f5f9;
}

.small {
    color: #607080;
    font-size: 14px;
}

.danger {
    background: #b42318;
}

.danger:hover {
    background: #8e1c14;
}

footer {
    text-align: center;
    padding: 30px;
    color: #607080;
}

@media(max-width: 700px) {

    table {
        font-size: 13px;
    }

    th, td {
        padding: 7px;
    }

}

</style>

</head>

<body>

<header>

    <h1>🔐 Secure File Vault</h1>

    <p>
        AES-256-GCM File Encryption & Decryption System
    </p>

</header>


<div class="container">

{% with messages = get_flashed_messages(with_categories=true) %}

    {% for category, message in messages %}

        <div class="{{ category }}">
            {{ message }}
        </div>

    {% endfor %}

{% endwith %}


<div class="warning">

    <strong>Security Notice:</strong>

    Your password is never stored by this application.
    If you forget the password, the encrypted file cannot
    be recovered through this application.

</div>


<div class="cards">


<!-- ENCRYPTION -->

<div class="card">

    <h2>🔒 Encrypt File</h2>

    <p class="small">
        Select a file and protect it using AES-256-GCM.
    </p>

    <form
        action="{{ url_for('encrypt') }}"
        method="POST"
        enctype="multipart/form-data"
    >

        <input
            type="file"
            name="file"
            required
        >

        <input
            type="password"
            name="password"
            placeholder="Create encryption password"
            minlength="8"
            required
        >

        <button type="submit">
            Encrypt & Secure
        </button>

    </form>

</div>


<!-- DECRYPTION -->

<div class="card">

    <h2>🔓 Decrypt File</h2>

    <p class="small">
        Select an encrypted .sfe file and enter its password.
    </p>

    <form
        action="{{ url_for('decrypt_upload') }}"
        method="POST"
        enctype="multipart/form-data"
    >

        <input
            type="file"
            name="file"
            accept=".sfe"
            required
        >

        <input
            type="password"
            name="password"
            placeholder="Enter encryption password"
            required
        >

        <button type="submit">
            Decrypt File
        </button>

    </form>

</div>

</div>


<!-- STORED FILES -->

<div class="card" style="margin-top:25px;">

<h2>📁 Encrypted Files</h2>

{% if files %}

<table>

<tr>
    <th>File</th>
    <th>Size</th>
    <th>Created</th>
    <th>Action</th>
</tr>

{% for file in files %}

<tr>

<td>
    {{ file["original_name"] }}
</td>

<td>
    {{ "%.2f"|format(file["encrypted_size"] / 1024) }} KB
</td>

<td>
    {{ file["created_at"] }}
</td>

<td>

<a
    class="btn"
    href="{{ url_for('download_encrypted',
                     file_id=file['id']) }}"
>
    Download
</a>

<form
    action="{{ url_for('delete_file',
                       file_id=file['id']) }}"
    method="POST"
    style="display:inline;"
>

<button class="danger" type="submit">
    Delete
</button>

</form>

</td>

</tr>

{% endfor %}

</table>

{% else %}

<p class="small">
    No encrypted files available yet.
</p>

{% endif %}

</div>


<!-- ACTIVITY -->

<div class="card" style="margin-top:25px;">

<h2>📊 Activity History</h2>

{% if activity %}

<table>

<tr>
    <th>Action</th>
    <th>File</th>
    <th>Status</th>
    <th>Time</th>
</tr>

{% for item in activity %}

<tr>

<td>{{ item["action"] }}</td>

<td>{{ item["file_name"] }}</td>

<td>{{ item["status"] }}</td>

<td>{{ item["created_at"] }}</td>

</tr>

{% endfor %}

</table>

{% else %}

<p class="small">
    No activity recorded yet.
</p>

{% endif %}

</div>


</div>


<footer>

    Secure File Vault |
    AES-256-GCM Cryptography |
    Cybersecurity Mini Project

</footer>

</body>
</html>
"""


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    connection = get_db()

    files = connection.execute(
        """
        SELECT *
        FROM files
        ORDER BY id DESC
        """
    ).fetchall()

    activity = connection.execute(
        """
        SELECT *
        FROM activity
        ORDER BY id DESC
        LIMIT 15
        """
    ).fetchall()

    connection.close()

    return render_template_string(
        PAGE,
        files=files,
        activity=activity
    )


# ============================================================
# ENCRYPT FILE
# ============================================================

@app.route("/encrypt", methods=["POST"])
def encrypt():

    uploaded_file = request.files.get("file")
    password = request.form.get("password", "")

    if not uploaded_file:
        flash(
            "Please select a file.",
            "error"
        )
        return redirect(url_for("home"))

    if len(password) < 8:
        flash(
            "Password must contain at least 8 characters.",
            "error"
        )
        return redirect(url_for("home"))

    original_name = secure_filename(
        uploaded_file.filename
    )

    if not original_name:
        flash(
            "Invalid file name.",
            "error"
        )
        return redirect(url_for("home"))

    try:

        file_data = uploaded_file.read()

        if not file_data:
            flash(
                "The selected file is empty.",
                "error"
            )
            return redirect(url_for("home"))

        encrypted_data = encrypt_file(
            file_data,
            password
        )

        stored_name = (
            secrets.token_hex(16)
            + ".sfe"
        )

        stored_path = STORAGE_DIR / stored_name

        stored_path.write_bytes(
            encrypted_data
        )

        connection = get_db()

        connection.execute(
            """
            INSERT INTO files
            (original_name,
             stored_name,
             encrypted_size,
             created_at)
            VALUES (?, ?, ?, datetime('now','localtime'))
            """,
            (
                original_name,
                stored_name,
                len(encrypted_data)
            )
        )

        connection.commit()
        connection.close()

        log_activity(
            "ENCRYPT",
            original_name,
            "SUCCESS"
        )

        flash(
            "File encrypted and stored successfully.",
            "success"
        )

    except Exception as error:

        log_activity(
            "ENCRYPT",
            original_name,
            "FAILED"
        )

        flash(
            "Encryption failed.",
            "error"
        )

        print("Encryption error:", error)

    return redirect(url_for("home"))


# ============================================================
# DOWNLOAD ENCRYPTED FILE
# ============================================================

@app.route("/download/<int:file_id>")
def download_encrypted(file_id):

    connection = get_db()

    file_record = connection.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        """,
        (file_id,)
    ).fetchone()

    connection.close()

    if not file_record:
        flash(
            "File not found.",
            "error"
        )
        return redirect(url_for("home"))

    file_path = (
        STORAGE_DIR
        / file_record["stored_name"]
    )

    if not file_path.exists():
        flash(
            "Stored encrypted file is missing.",
            "error"
        )
        return redirect(url_for("home"))

    return send_file(
        file_path,
        as_attachment=True,
        download_name=(
            file_record["original_name"]
            + ".sfe"
        )
    )


# ============================================================
# DECRYPT UPLOADED FILE
# ============================================================

@app.route("/decrypt", methods=["POST"])
def decrypt_upload():

    uploaded_file = request.files.get("file")
    password = request.form.get("password", "")

    if not uploaded_file:
        flash(
            "Please select an encrypted file.",
            "error"
        )
        return redirect(url_for("home"))

    try:

        encrypted_data = uploaded_file.read()

        decrypted_data = decrypt_file(
            encrypted_data,
            password
        )

        original_name = secure_filename(
            uploaded_file.filename
        )

        if original_name.lower().endswith(".sfe"):
            original_name = original_name[:-4]

        if not original_name:
            original_name = "decrypted_file"

        log_activity(
            "DECRYPT",
            original_name,
            "SUCCESS"
        )

        return send_file(
            BytesIO(decrypted_data),
            as_attachment=True,
            download_name=original_name,
            mimetype="application/octet-stream"
        )

    except ValueError as error:

        log_activity(
            "DECRYPT",
            uploaded_file.filename or "unknown",
            "FAILED"
        )

        flash(
            str(error),
            "error"
        )

    except Exception as error:

        log_activity(
            "DECRYPT",
            uploaded_file.filename or "unknown",
            "FAILED"
        )

        print("Decryption error:", error)

        flash(
            "Decryption failed.",
            "error"
        )

    return redirect(url_for("home"))


# ============================================================
# DELETE ENCRYPTED FILE
# ============================================================

@app.route("/delete/<int:file_id>", methods=["POST"])
def delete_file(file_id):

    connection = get_db()

    file_record = connection.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        """,
        (file_id,)
    ).fetchone()

    if not file_record:

        connection.close()

        flash(
            "File not found.",
            "error"
        )

        return redirect(url_for("home"))

    file_path = (
        STORAGE_DIR
        / file_record["stored_name"]
    )

    if file_path.exists():
        file_path.unlink()

    connection.execute(
        """
        DELETE FROM files
        WHERE id = ?
        """,
        (file_id,)
    )

    connection.commit()
    connection.close()

    log_activity(
        "DELETE",
        file_record["original_name"],
        "SUCCESS"
    )

    flash(
        "Encrypted file deleted.",
        "success"
    )

    return redirect(url_for("home"))


# ============================================================
# ERROR HANDLER
# ============================================================

@app.errorhandler(413)
def file_too_large(error):

    flash(
        "File is too large. Maximum size is 10 MB.",
        "error"
    )

    return redirect(url_for("home"))


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    initialize_database()

    print()
    print("=" * 55)
    print("      SECURE FILE VAULT")
    print("      AES-256-GCM ENCRYPTION")
    print("=" * 55)
    print()
    print("Open your browser and visit:")
    print("http://127.0.0.1:5000")
    print()

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )