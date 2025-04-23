from flask import Flask, render_template, request, jsonify, abort, send_file, session, make_response
import sqlite3
import os
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15 #this might need to change?
from Crypto.Hash import SHA256
import base64, random, string
from datetime import datetime
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.secret_key = os.urandom(24)

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, 'db', 'chatapp.db')
IMAGES_PATH = os.path.join(BASE_DIR, 'images')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_private_key(username):
    #print("Attempting to get private key")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT private_key FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    #print(f"Pulled row from table: {row}")
    conn.close()
    if not row:
        raise ValueError(f"User ({username}) not found.")
    private_key_pem = row['private_key']
    return private_key_pem

def load_private_key(private_key_pem):
    return RSA.import_key(private_key_pem.encode())

def get_public_key(username):
    #print("Attempting to get public key")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT public_key FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    #print(f"Pulled row from table: {row}")
    conn.close()
    if not row:
        raise ValueError(f"User ({username}) not found.")
    public_key_pem = row['public_key']
    return public_key_pem

def print_database_contents(): #this probably is a security risk, so delete after testing
    #connect
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
 
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
 
    print(f"{'ID':<5} {'Username':<20} {'Private Key (Serialized)':<60} {'Public Key (Serialized)'}")
    print("="*150)

    for user in users:
        id = user[0]
        username = user[1]
        private_key = user[2]
        public_key = user[3]
        print(f"{username} {public_key}...") #obviously doesnt print everything, but the other stuff doesnt matter
 
    conn.close()

#print_database_contents()

# AUTH page -----

@app.route('/auth/challenge', methods=['POST'])
def auth_challenge(): #rate limit/IP based
    challenge = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    session['challenge'] = challenge
    return jsonify({'challenge': challenge})

@app.route('/auth/verify', methods=['POST'])
def auth_verify():
    data = request.get_json()
    username = data['username']
    signature = base64.b64decode(data['signature'])
    challenge = session.get('challenge')

    if not challenge:
        return jsonify({'error': 'No challenge'}), 400
    
    public_key = RSA.import_key(get_public_key(username).encode())
    h = SHA256.new(challenge.encode())

    try:
        pkcs1_15.new(public_key).verify(h, signature) #libraries are confusing, but pkcs1_15 works best here?
        session['authenticated'] = True
        session['username'] = username
        target_dir = os.path.join(IMAGES_PATH, username) #first time the user logs in, the directory is made for them, and persists. this is technically a weakness, as DDOSing user logins would overwhelm memory
        os.makedirs(target_dir, exist_ok=True)
        return jsonify({'message': 'Authenticated'})
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid signature'}), 403
    
# UPLOAD page -----

@app.route('/upload', methods=['POST'])
def upload():
    if not session.get('authenticated'):
        print("401 error unauth")
        abort(401)

    try:
        data = request.get_json()
        username = session['username']
        enc_key = base64.b64decode(data['key'])
        nonce = base64.b64decode(data['nonce'])
        tag = base64.b64decode(data['tag'])
        ciphertext = base64.b64decode(data['data'])

        private_key_pem = get_private_key(username)
        private_key = load_private_key(private_key_pem)
        rsa_cipher = PKCS1_OAEP.new(private_key)
        aes_key = rsa_cipher.decrypt(enc_key)

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        password, target_b, image_bytes = decrypted_data.split(b'||', 2)
        target = target_b.decode()

        target_dir = os.path.join(IMAGES_PATH, target)
        os.makedirs(target_dir, exist_ok=True)

        filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}.png"
        filepath = os.path.join(target_dir, filename)

        with open(filepath, 'wb') as f:
            f.write(image_bytes)
        meta_path = filepath + ".meta"
        with open(meta_path, 'w') as meta_file:
            meta_file.write(username)

        return jsonify({"message": "Image uploaded", "password": password.decode()}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400
    
# DOWNLOAD page -----

def get_oldest_file(folder_path):
    files = sorted([
        f for f in os.listdir(folder_path)
        if f.lower().endswith('.png')
    ])
    return os.path.join(folder_path, files[0]) if files else None

@app.route('/download/<target>', methods=['GET'])
def download(target):
    if not session.get('authenticated'):
        abort(401)

    folder = os.path.join(IMAGES_PATH, target)
    if not os.path.isdir(folder):
        abort(404)

    filepath = get_oldest_file(folder)
    if not filepath:
        abort(404, description='No images found')

    try:
        # Load the file
        with open(filepath, 'rb') as f:
            image_data = f.read()

        # Encrypt using AES key
        aes_key = get_random_bytes(32)
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(image_data)

        # Get public key of recipient
        public_key_pem = get_public_key(target)
        public_key = RSA.import_key(public_key_pem.encode())

        cipher_rsa = PKCS1_OAEP.new(public_key)
        enc_key = cipher_rsa.encrypt(aes_key)

        # Build payload
        payload = {
            'enc_key': base64.b64encode(enc_key).decode(),
            'nonce': base64.b64encode(cipher_aes.nonce).decode(),
            'tag': base64.b64encode(tag).decode(),
            'data': base64.b64encode(ciphertext).decode()
        }

        return jsonify(payload), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# SYNC page -----

@app.route('/sync/<target>', methods=['GET'])
def sync(target):
    if not session.get('authenticated'):
        abort(401)

    after = request.args.get('after')
    folder = os.path.join(IMAGES_PATH, target)
    if not os.path.isdir(folder):
        abort(404)

    files = sorted([
        f for f in os.listdir(folder)
        if f.endswith('.png') and f > f"{after}.png"
    ])

    if files:
        next_file = files[0]
        file_path = os.path.join(folder, next_file)
        meta_path = file_path + ".meta"
        if not os.path.exists(meta_path): #just redundancy to avoid error
            with open(meta_path, 'w') as f:
                f.write("Anonymous") #should always get overwritten

        with open(meta_path, 'r') as f:
            sender = f.read().strip() #the .meta file right now just has the sender username, it's technically secure, maybe vulnerable to a verified /upload manipulated packet

        with open(file_path, 'rb') as f:
            image_data = f.read()
        
        aes_key = get_random_bytes(32)
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(image_data)

        # Encrypt AES key with target's public key
        public_key_pem = get_public_key(target)
        public_key = RSA.import_key(public_key_pem.encode())
        cipher_rsa = PKCS1_OAEP.new(public_key)
        enc_key = cipher_rsa.encrypt(aes_key)

        # Build response payload
        payload = {
            'filename': base64.b64encode(next_file.encode()).decode(),
            'sender': base64.b64encode(sender.encode()).decode(),
            'enc_key': base64.b64encode(enc_key).decode(),
            'nonce': base64.b64encode(cipher_aes.nonce).decode(),
            'tag': base64.b64encode(tag).decode(),
            'data': base64.b64encode(ciphertext).decode()
        }

        return jsonify(payload), 200
    else:
        return jsonify({'message': 'No new images'}), 204

# KEY page -----

@app.route('/key/<username>', methods=['GET'])
def key(username):
    try:
        #print(f"Trying get_public_key{username}")
        public_key_pem = get_public_key(username)
        return jsonify({'public_key': public_key_pem}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': f"Unexpected error: {str(e)}"}), 500 #hard catch, ive never done a pem get like this

if __name__ == '__main__':
    app.run(debug=True)