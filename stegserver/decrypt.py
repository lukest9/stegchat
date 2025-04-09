from flask import Flask, request, jsonify
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
import base64
import os
 
app = Flask(__name__)
 
@app.route('/upload', methods=['POST'])
def upload():
    try:
        data = request.get_json()
        # Decode and extract components
        username = base64.b64decode(data['username'])
        enc_key = base64.b64decode(data['key'])
        nonce = base64.b64decode(data['nonce'])
        tag = base64.b64decode(data['tag'])
        ciphertext = base64.b64decode(data['data'])
        # Load your private RSA key for decrypting AES key
        with open('private_key.pem', 'rb') as key_file:
            private_key = RSA.import_key(key_file.read())
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
        with open('received_image.jpg', 'wb') as f:
            f.write(image_bytes)
 
        return jsonify({
            "message": "Image and password received successfully.",
            "password": password.decode()
        }), 200
 
    except Exception as e:
        return jsonify({"error": str(e)}), 400
 
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
 
