from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import uuid
import base64
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.secret_key = "supersecretkey"

DB = "database.db"

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS notes (
                    id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    iv BLOB NOT NULL
                )''')
    conn.commit()
    conn.close()

init_db()

# --- Encryption Utilities ---
def encrypt_note(content, passphrase):
    salt = get_random_bytes(16)
    key = PBKDF2(passphrase, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(content.encode())
    data = base64.b64encode(tag + ciphertext).decode()
    return data, salt, cipher.nonce

def decrypt_note(data, passphrase, salt, iv):
    try:
        key = PBKDF2(passphrase, salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        decoded = base64.b64decode(data)
        tag, ciphertext = decoded[:16], decoded[16:]
        content = cipher.decrypt_and_verify(ciphertext, tag)
        return content.decode()
    except Exception as e:
        return None

# --- Routes ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        note = request.form["note"]
        passphrase = request.form["passphrase"]
        note_id = str(uuid.uuid4())
        encrypted, salt, iv = encrypt_note(note, passphrase)

        conn = sqlite3.connect(DB)
        conn.execute("INSERT INTO notes (id, content, salt, iv) VALUES (?, ?, ?, ?)",
                     (note_id, encrypted, salt, iv))
        conn.commit()
        conn.close()

        link = request.host_url + "view/" + note_id
        return render_template("view.html", link=link)

    return render_template("index.html")

@app.route("/view/<note_id>", methods=["GET", "POST"])
def view_note(note_id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT content, salt, iv FROM notes WHERE id = ?", (note_id,))
    result = c.fetchone()
    conn.close()

    if not result:
        flash("Note not found or already viewed.")
        return redirect(url_for('index'))

    if request.method == "POST":
        passphrase = request.form["passphrase"]
        content = decrypt_note(result[0], passphrase, result[1], result[2])

        if content:
            # Delete after successful view
            conn = sqlite3.connect(DB)
            conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
            conn.commit()
            conn.close()
            return render_template("view.html", content=content)
        else:
            flash("Incorrect passphrase.")
            return redirect(request.url)

    return render_template("view.html", note_id=note_id)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
