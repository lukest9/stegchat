import os
import tkinter as tk
import sys

#pki stuff
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#Note: Python 3.10

key = RSA.generate(2048)

private_key = key.export_key()
public_key = key.public_key().export_key()

DEST_PRIVATE_KEY = private_key
DEST_PUBLIC_KEY = public_key

try:
    gui_to_master_export = sys.argv[1]
    master_to_gui_import = sys.argv[2]
except IndexError:
    gui_to_master_export = r"C:\Users\lstal\Desktop\stegproject\export.txt"
    master_to_gui_import = r"C:\Users\lstal\Desktop\stegproject\import.txt"

last_mod_time = 0

def encrypt_message(message):
    public_key = RSA.import_key(DEST_PUBLIC_KEY)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message):
    private_key = RSA.import_key(DEST_PRIVATE_KEY)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode()

#this controls message sending, using states to make the output display unwritable
def send_message():
    message = message_entry.get()
    if message:
        chat_display.config(state="normal")  # enable editing
        chat_display.insert(tk.END, f"You: {message}\n")
        chat_display.config(state="disabled")  # disable editing
        message_entry.delete(0, tk.END)
        
        encrypted_bytes = encrypt_message(message)
        with open(gui_to_master_export, 'wb') as pipe:
            pipe.write(encrypted_bytes)
            print("Message written to export.txt")
        '''
        unencrypted_bytes = message
        with open(gui_to_master_export, 'w') as pipe:
            pipe.write(unencrypted_bytes)
            print("Message written to export.txt in string mode")
        '''

def check_for_updates():
    global last_mod_time
    try:
        mod_time = os.stat(master_to_gui_import).st_mtime  
        # if its been modified, write, and if file doesn't exist, just wait
        if mod_time > last_mod_time:
            last_mod_time = mod_time
            if os.stat(master_to_gui_import).st_size != 0:
                print("Reading from import.txt")
                
                with open(master_to_gui_import, 'rb') as pipe:
                    encrypted_message = pipe.read()
                    if encrypted_message:
                        try:
                            message = decrypt_message(encrypted_message)
                            chat_display.config(state="normal")
                            chat_display.insert(tk.END, f"User 2: {message}\n")
                            chat_display.config(state="disabled")
                        except (ValueError, TypeError) as e:  # catch decryption errors
                            chat_display.config(state="normal")
                            chat_display.insert(tk.END, "Error: Invalid message received\n")
                            chat_display.config(state="disabled")
                '''
                with open(master_to_gui_import, 'r') as pipe:
                    unencrypted_message = pipe.read()
                    chat_display.config(state="normal")
                    chat_display.insert(tk.END, f"Nathan: {unencrypted_message}\n")
                    chat_display.config(state="disabled")
                '''

    except FileNotFoundError:
        pass

    # this is asynchronus, so typing is still available
    root.after(500, check_for_updates)  

root = tk.Tk()
root.title("Steganography Chat Application")
root.geometry("500x400")

chat_display = tk.Text(root, height=15, width=60, state="disabled")
chat_display.pack(pady=10)

message_entry = tk.Entry(root, width=50)
message_entry.pack(pady=5)

send_button = tk.Button(root, text="Send Message", command=send_message)
send_button.pack(pady=5)

# start asynchronus stuff
check_for_updates()

print("GUI running")
root.mainloop()