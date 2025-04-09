import subprocess
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


dirname = os.path.dirname(__file__)

steganography = os.path.join(dirname, 'stegencrypt', 'stegencrypt.py')
gui = os.path.join(dirname, 'StegoGUI', 'StegGui.py')

export_path = os.path.join(dirname, 'export.txt')
import_path = os.path.join(dirname, 'import.txt')
source_path = os.path.join(dirname, 'stegencrypt', 'sources')
dest_path = os.path.join(dirname, 'stegencrypt', 'dests')

# currently assuming only one image at a ztime in the incoming folder, named 0
incoming_path = os.path.join(dirname, 'stegencrypt', 'incoming', '0.png')
keys = os.path.join(dirname, 'public_key.txt')

server = 'http://localhost:5000'

#this is local!
username = 'luke'
password = 'lpass'

with open(export_path, "w") as file:
    print(f"Cleared {export_path}")
    pass  # Opens the file in write mode, which clears its contents immediately
with open(import_path, "w") as file:
    print(f"Cleared {import_path}")
    pass  # Opens the file in write mode, which clears its contents immediately
with open(incoming_path, "wb") as img_file:
    print(f"Cleared {incoming_path}")
    pass  # Also opens the file to clear it

s1 = subprocess.Popen(['python', steganography, export_path, import_path, source_path, dest_path, incoming_path, server, username, password, keys])
s2 = subprocess.Popen(['python', gui, export_path, import_path])

s1.wait()
s2.wait()