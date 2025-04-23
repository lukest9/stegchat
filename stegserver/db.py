import os
import shutil
from Crypto.PublicKey import RSA
import sqlite3

#chatapp.db is technically super cleartext, should possibly be encrypted just for extra security
dirname = os.path.dirname(__file__) #stegserver/
database_path = os.path.join(dirname, 'db/chatapp.db')
print("Should be database path: " + database_path)

def generate_keys():
    key = RSA.generate(2048)
 
    private_pem = key.export_key().decode('utf-8')
    public_pem = key.publickey().export_key().decode('utf-8')

    return private_pem, public_pem

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
    #connect
    conn = sqlite3.connect(database_path)
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

def clear_database():
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
 
    cursor.execute('DELETE FROM users')
 
    conn.commit()
    conn.close()
 
    print("Database cleared successfully.")

def create_db(): #this probably can run like on startup, but just in case during testing it is only run once unless db.db is forcefully deleted
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            private_key TEXT NOT NULL,
            public_key TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()
    print(f"Database '{database_path}' and 'users' table created/exists successfully.")

def give_private_key_file(username):
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    cursor.execute('SELECT private_key FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        print(f"[!] User '{username}' not found in the database.")
        return

    private_key_pem = row[0]

    output_path = os.path.join(dirname, 'db', 'private_key_export', 'private_key.pem')
    with open(output_path, 'w') as f:
        f.write(private_key_pem)

    print(f"Exported private key for '{username}'")
    #cp /stegserver/db/private_key_export/private_key.pem /stegclient/private_key.pem
    #from stegchat dir

def clear_temp_project_folders():
    images_path = os.path.join(dirname, 'images')
    for subfolder in os.listdir(images_path):
        full_path = os.path.join(images_path, subfolder)
        if os.path.isdir(full_path):
            shutil.rmtree(full_path)

#create_db()
#uncomment/comment lines, this should probably be some sort of command line thing
'''
clear_database()
private_key, public_key = generate_keys()
username = "luke"
insert_keys(username, private_key, public_key)
private_key, public_key = generate_keys()
username = "cory"
insert_keys(username, private_key, public_key)
print_database_contents()
give_private_key_file('luke') #technically this would be better if the export was named or put somewhere username specific, but right now just dont want the .pem getting altered wrong
'''
clear_temp_project_folders()