from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives import serialization
import sqlite3
import os
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
import base64

app = Flask(__name__)

# Define the database path globally
database_path = os.path.join(os.path.dirname(__file__), '../db/chatapp.db')
#print(f"Make sure this is right: {database_path}")

def get_db_connection():
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    return conn

def get_private_key(username):
    print("Attempting to get private key")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT private_key FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    print(f"Pulled row from table: {row}")
    conn.close()
    if not row:
        raise ValueError(f"User ({username}) not found.")
    private_key_pem = row['private_key']
    return private_key_pem

def load_private_key(private_key_pem):
    return RSA.import_key(private_key_pem.encode())

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Luke route
@app.route('/luke', methods=['POST'])
def luke():
    try:
        data = request.get_json()
        # Decode and extract components
        username = data['username']
        enc_key = base64.b64decode(data['key'])
        nonce = base64.b64decode(data['nonce'])
        tag = base64.b64decode(data['tag'])
        ciphertext = base64.b64decode(data['data'])
        private_key_pem = get_private_key(username)
        private_key = load_private_key(private_key_pem)
        rsa_cipher = PKCS1_OAEP.new(private_key)
        # Decrypt AES key using private RSA key
        aes_key = rsa_cipher.decrypt(enc_key)
 
        # Decrypt payload using AES-GCM
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
 
        # At this point, decrypted_data is your original data

        # If you used password.encode() + b'||' + image_data:
        password, image_bytes = decrypted_data.split(b'||', 1)
        # Optionally, save image to verify
        with open('received_image.png', 'wb') as f:
            f.write(image_bytes)
 
        return jsonify({
            "message": "Image and password received successfully.",
            "password": password.decode()
        }), 200
 
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
    