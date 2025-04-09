import sqlite3
import os
import sys

# Default to 'db/chatapp.db' if the DATABASE_PATH environment variable is not set
database_path = os.getenv('DATABASE_PATH', 'db/chatapp.db')

# Ensure the directory exists before creating the database file
db_directory = os.path.dirname(database_path)
if not os.path.exists(db_directory):
    os.makedirs(db_directory)
    print(f"Created directory: {db_directory}")

def create_db():
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    # Create table for storing user info and keys
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
    print(f"Database '{database_path}' and 'users' table created successfully.")

if __name__ == "__main__":
    create_db()
