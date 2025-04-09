import subprocess
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import sqlite3
 
dirname = os.path.dirname(__file__)
 
server = os.path.join(dirname,  'stegserver.py')
dbsetup = os.path.join(dirname, 'dbsetup.py')
 
database_path = os.path.join(dirname, 'database', 'database.db')
 
server = subprocess.Popen(['python', server, database_path])
database_setup = subprocess.Popen(['python', dbsetup, database_path])
 
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
 
    public_key = private_key.public_key()
 
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
 
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
 
    return private_pem.decode(), public_pem.decode()
 
def insert_keys(username, private_key, public_key):
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
 
    cursor.execute('''
        INSERT INTO users (username, private_key, public_key)
        VALUES (?, ?, ?)
    ''', (username, private_key, public_key))
 
    conn.commit()
    conn.close()
 
def print_database_contents():
    # Connect to the database
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
 
    # Fetch all rows from the users table
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
 
    # Print each user's details in a formatted way
    print(f"{'ID':<5} {'Username':<20} {'Private Key (Serialized)':<60} {'Public Key (Serialized)'}")
    print("="*150)  # Divider for clarity
 
    # Iterate over each user and print their information
    for user in users:
        id = user[0]
        username = user[1]
        private_key = user[2]
        public_key = user[3]
        print(f"{id:<5} {username:<20} {private_key[:60]}... {' ' * (60 - len(private_key[:60]))} {public_key[:60]}...")
 
    conn.close()
 
def clear_database():
    # Connect to the database
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
 
    # Delete all rows from the users table
    cursor.execute('DELETE FROM users')
 
    # Commit the changes and close the connection
    conn.commit()
    conn.close()
 
    print("Database cleared successfully.")
 
def export_keys_to_txt(username, file_path):
    # Connect to the database
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
 
    # Fetch the user's private and public keys by username
    cursor.execute('SELECT private_key, public_key FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
 
    # If the user exists
    if user:
        private_key, public_key = user
       
        # Write the keys to a .txt file
        with open(file_path, 'w') as file:
            file.write(f"Private Key:\n{private_key}\n\n")
            file.write(f"Public Key:\n{public_key}\n")
 
        print(f"Keys for {username} have been exported to {file_path}")
    else:
        print(f"User {username} not found.")
 
    # Close the connection
    conn.close()
 
# Example usage:
export_keys_to_txt("luke", "luke.txt")
export_keys_to_txt("cory", "cory.txt")
 
'''
clear_database()
private_key, public_key = generate_keys()
username = "luke"
insert_keys(username, private_key, public_key)
private_key, public_key = generate_keys()
username = "cory"
insert_keys(username, private_key, public_key)
'''
 
print_database_contents()
