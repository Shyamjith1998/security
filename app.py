from flask import Flask, render_template, request, redirect, session, jsonify, url_for
from flask_socketio import SocketIO, emit, join_room
import sqlite3
import uuid
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)
app.secret_key = "supersecretkey"
socketio = SocketIO(app, cors_allowed_origins="*")

DB = "chat.db"
private_keys = {}  # In-memory (non-persistent)

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    encrypted_content BLOB NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    conn.commit()
    conn.close()

init_db()

# --- RSA Utility Functions ---
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(pub_key):
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def deserialize_public_key(pem):
    return serialization.load_pem_public_key(pem.encode())

def encrypt_with_public_key(public_key_pem, message):
    pub_key = deserialize_public_key(public_key_pem)
    return pub_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_with_private_key(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode()

# --- Routes ---
@app.route("/")
def index():
    if "username" not in session:
        return render_template("home.html")
    return render_template("chat.html", username=session["username"])

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            return "Username required", 400

        private_key, public_key = generate_key_pair()
        private_keys[username] = private_key  # Not persistent

        pub_key_pem = serialize_public_key(public_key)

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('''INSERT INTO users (username, public_key) 
                     VALUES (?, ?)
                     ON CONFLICT(username) DO UPDATE SET public_key = excluded.public_key''',
                  (username, pub_key_pem))
        conn.commit()
        conn.close()

        session["username"] = username
        return redirect(url_for("index"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/get_public_key/<username>")
def get_public_key(username):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({"public_key": row[0]})
    return jsonify({"error": "User not found"}), 404

@app.route("/get_messages")
def get_messages():
    username = session.get("username")
    if not username or username not in private_keys:
        print("[ERROR] Unauthorized or private key not found for:", username)
        return jsonify({"error": "Unauthorized"}), 401

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''SELECT sender, encrypted_content, timestamp FROM messages
                 WHERE recipient = ?
                 ORDER BY timestamp ASC''',
              (username,))
    rows = c.fetchall()
    conn.close()

    decrypted_messages = []
    for row in rows:
        sender, encrypted, timestamp = row
        try:
            decrypted = decrypt_with_private_key(private_keys[username], encrypted)
        except Exception as e:
            print("[ERROR] Decryption failed for user", username, ":", str(e))
            decrypted = "[Failed to decrypt]"
        decrypted_messages.append({
            "sender": sender,
            "message": decrypted,
            "timestamp": timestamp
        })

    print(f"[INFO] Returning {len(decrypted_messages)} messages for {username}")
    return jsonify(decrypted_messages)

# --- SocketIO Real-Time Events ---
@socketio.on('join')
def handle_join():
    username = session.get("username")
    if username:
        join_room(username)
        print(f"[INFO] {username} joined their room.")

@socketio.on('send_message')
def handle_send_message(data):
    sender = session.get("username")
    recipient = data.get("recipient")
    message = data.get("message")

    if not sender or not recipient or not message:
        emit('error', {"error": "Invalid message data"})
        return

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (recipient,))
    row = c.fetchone()
    conn.close()

    if not row:
        emit('error', {"error": "Recipient not found"})
        return

    recipient_pub_key = row[0]
    try:
        encrypted = encrypt_with_public_key(recipient_pub_key, message)
    except Exception as e:
        emit('error', {"error": f"Encryption failed: {str(e)}"})
        return

    msg_id = str(uuid.uuid4())
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''INSERT INTO messages (id, sender, recipient, encrypted_content)
                 VALUES (?, ?, ?, ?)''',
              (msg_id, sender, recipient, encrypted))
    conn.commit()
    conn.close()

    print(f"[INFO] {sender} sent message to {recipient}")

    emit("receive_message", {
        "sender": sender
    }, room=recipient)

# --- Run App ---
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
