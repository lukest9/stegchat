from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives import serialization
import sqlite3
import os

app = Flask(__name__)

# Define the database path globally
database_path = os.getenv('DATABASE_PATH', 'db/chatapp.db')  # You can change the path as needed

# Ensure the directory exists before creating the database file
db_directory = os.path.dirname(database_path)
if not os.path.exists(db_directory):
    os.makedirs(db_directory)

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Example chat route
@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    user = data.get('user')
    message = data.get('message')

    # Here you can add your steganography logic
    print(f"Message from {user}: {message}")

    return jsonify({"status": "success", "message": "Message received"})

def get_db_connection():
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    return conn

def get_private_key(username):
    conn = get_db_connection()  # Make sure database_path is available
    cursor = conn.cursor()
    cursor.execute('SELECT id, private_key FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise ValueError("User not found.")
    return row['id'], serialization.load_pem_private_key(
        row['private_key'].encode(),
        password=None
    )

if __name__ == '__main__':
    app.run(debug=True)
