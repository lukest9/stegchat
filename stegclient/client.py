from datetime import datetime
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
import time, requests
import tkinter as tk
from tkinter import Label, ttk
import threading
import cv2
import os
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

#python 3.10

dirname = os.path.dirname(__file__) #stegclient/
SERVER_URL = 'http://localhost:5000'
USERNAME = "luke" #should be updated
PASSWORD = "pass"

def pick_blank():
    img_path = os.path.join(dirname, 'sources', '0.png') #add the random selecter later
    return img_path

def steg_encode(blank_path, message):
    #get the image, prepend the stop sequence (16 bits)
    bytes_message = message.encode('utf-8') #string to bytes
    binary_message = ''.join(format(byte, '08b') for byte in bytes_message) #bytes to bin
    img = cv2.imread(blank_path)
    message_length = len(binary_message)
    length_bin = format(message_length, '016b')
    binary_data = length_bin + binary_message
    #print(f"message length: {length_bin} message: {binary_message}")
    height, width, _ = img.shape
    data_index = 0

    for y in range(height):
        for x in range(width):
            pixel = img[y,x]
            if data_index < len(binary_data):
                pixel[0] = ((pixel[0] & 0xFE) | int(binary_data[data_index]))
                img[y,x] = pixel
                data_index += 1
            else:
                return img
    print("There should probably be some sort of error catch here")

def steg_decode(img):
    binary_message = ''
    height, width, _ = img.shape

    for y in range(height):
        for x in range(width):
            pixel = img[y,x]
            binary_message += str(pixel[0] & 1)

    message_length_bin = binary_message[:16]
    message_length = int(message_length_bin, 2)
    #print(f"message length: {message_length_bin}")
    message_bin = binary_message[16:16 + message_length]

    decoded_message = ''.join(chr(int(message_bin[i:i+8], 2)) for i in range(0, len(message_bin), 8))
    return decoded_message

def upload_file(img, target):
    #the old method took an image path, used the cv2.read to get 'img_data', im pretty sure this buffer method does the same thing, they should both be bytes objects?
    success, buffer = cv2.imencode('.png', img) #stupid cv2, this is a tuple
    image_bytes = buffer.tobytes()

    aes_key = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    nonce = cipher_aes.nonce

    payload = PASSWORD.encode() + b'||' + target.encode() + b'||' + image_bytes

    ciphertext, tag = cipher_aes.encrypt_and_digest(payload)

    public_key_pem = get_public_key() #hopefully stored, read as a bytes object, then the RSA import method can take the pem bytes properly? harder since pulling from server
    public_key = RSA.import_key(public_key_pem.encode())
    cipher_rsa = PKCS1_OAEP.new(public_key) #i don't know if I should use OAEP or 1_15, the old version used OAEP, but i read something that recommended 1_15
    enc_key = cipher_rsa.encrypt(aes_key)
    
    payload = {
        'username': USERNAME,
        'key': base64.b64encode(enc_key).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'data': base64.b64encode(ciphertext).decode()
    }

    response = s.post(f"{SERVER_URL}/upload", json=payload)
    if response.status_code == 200:
        print("Upload successful")
    else:
        print(f"Upload failed: {response.text}")

#(this is the button method)
def send_message(target): #this needs to get the target somehow
    if target not in tabs:
        print(f"No tab for target: {target}")
        return #can probably just make them here instead?
    message_entry = tabs[target]['entry']
    chat_display = tabs[target]['display']
    
    message = message_entry.get()
    if message:
        chat_display.config(state="normal")  # enable editing
        chat_display.insert(tk.END, f"You: {message}\n")
        chat_display.config(state="disabled")  # disable editing
        message_entry.delete(0, tk.END)

        blank_path = pick_blank()
        #print("steg encoding in send_message")
        img = steg_encode(blank_path, message)
        #target = 'cory' #obv needs to change
        #print("uploading file from send_message")
        upload_file(img, target)

def poll_for_images():
    global last_seen
    while True:
        try:
            response = s.get( #probably redundant check to see if session is authd
                f"{SERVER_URL}/sync/{USERNAME}",
                params={"after": last_seen} #sort of a janky workaround with filename as a timestamp
            )
            if response.status_code == 200:
                payload = response.json()
                filename = base64.b64decode(payload['filename']).decode()
                sender = base64.b64decode(payload['sender']).decode()
                enc_key = base64.b64decode(payload['enc_key'])
                nonce = base64.b64decode(payload['nonce'])
                tag = base64.b64decode(payload['tag'])
                ciphertext = base64.b64decode(payload['data'])

                # Decrypt AES key with private RSA
                private_key = get_private_key()
                cipher_rsa = PKCS1_OAEP.new(private_key)
                aes_key = cipher_rsa.decrypt(enc_key)

                # Decrypt image with AES
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                image_bytes = cipher.decrypt_and_verify(ciphertext, tag)

                # Save and decode image
                incoming_path = os.path.join(dirname, "incoming.png")
                with open(incoming_path, 'wb') as f:
                    f.write(image_bytes)

                img = cv2.imread(incoming_path)
                #sender = response.headers.get("X-Sender", "Unknown")
                if sender not in tabs:
                    create_user_tab(sender)

                message = steg_decode(img)
                display = tabs[sender]['display']
                display.config(state='normal')
                display.insert(tk.END, f"{sender}: {message}\n")
                display.config(state='disabled')
                last_seen = filename.split('.')[0]

                #def update_gui():
                #    label.config(text=f"New image: {filename}")

                #root.after(1, poll_for_images) #we've had this at 500, might be too fast, but we're shooting for 1s polling
            elif response.status_code == 204:
                pass
            else:
                print(f"Polling error: {response.status_code}") #this might be redundant
        except Exception as e:
            print(f"Polling exception: {e}")

def authorize(session):
    challenge_r = session.post(f"{SERVER_URL}/auth/challenge")
    if challenge_r.status_code != 200:
        print("challenge request failed")
        return False
    challenge = challenge_r.json()['challenge']
    #b64 encode
    #pkcs1_15 sign
    h = SHA256.new(challenge.encode()) #need to match to server
    private_key = get_private_key() #check how this is passed
    signer = pkcs1_15.new(private_key) #this stuff is library based, but like im not doing this encryption myself
    signature = signer.sign(h)
    signature_b64 = base64.b64encode(signature).decode()

    verify_r = session.post(
        f"{SERVER_URL}/auth/verify",
        json={"username": USERNAME, "signature": signature_b64}
    )

    if verify_r.status_code == 200:
        print("Authenticated")
        return True
    else:
        print(f"Failed Authentication: {verify_r.text}")
        return False

def get_private_key():
    with open(os.path.join(dirname, 'private_key.pem'), 'rb') as f:
        private_key = RSA.import_key(f.read()) #RSA.RsaKey object (i think)
    return private_key

s = requests.Session()

def get_public_key():
    response = s.get(f"{SERVER_URL}/key/{USERNAME}") #I think s can pull here? rusty :/
    if response.status_code == 200:
        return response.json()['public_key']
    else:
        raise Exception("Failed to get public key from server") #probably can make this more expressive

def create_user_tab(username):
    if username in tabs:
        return
    frame = ttk.Frame(chat_tabs, style="TFrame")
    frame.pack(fill='both', expand=True)
    frame.columnconfigure(0, weight=1)

    chat_display = tk.Text(
        frame,
        height=15,
        bg=DARKER_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR,
        relief='flat',
        wrap='word',
        state='disabled'
    )
    chat_display.grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 5), sticky="nsew")

    message_entry = tk.Entry(
        frame,
        bg=ENTRY_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR,
        relief='flat'
    )
    message_entry.grid(row=1, column=0, padx=(10, 5), pady=(0, 10), sticky="ew")

    send_button = tk.Button(
        frame,
        text="Send",
        bg=ACCENT_COLOR,
        fg='white',
        activebackground='#677bc4',
        relief='flat',
        bd=0,
        command=lambda: send_message(username)
    )
    send_button.grid(row=1, column=1, padx=(5, 10), pady=(0, 10))

    frame.rowconfigure(0, weight=1)

    chat_tabs.add(frame, text=username)
    tabs[username] = {
        'frame': frame,
        'display': chat_display,
        'entry': message_entry
    }

last_seen = datetime.now().strftime('%Y%m%d%H%M%S') #in a very robust world, this would be the last time you polled the server, and then when you log back in, it would pull and present all of your new messages
authorize(s)

DARK_BG = "#1e1e2f"
DARKER_BG = "#161624"
TEXT_COLOR = "#ffffff"
ACCENT_COLOR = "#3a66ff"
ENTRY_BG = "#2a2a3a"

root = tk.Tk()
root.geometry("600x450")
root.overrideredirect(True)
root.configure(bg=DARK_BG)

is_maximized = [False]

title_bar = tk.Frame(root, bg="#2e2e2e", relief='raised', bd=0)
title_bar.pack(fill=tk.X)

title_label = tk.Label(title_bar, text="STEGCHAT", bg="#2e2e2e", fg="white", font=("Times New Roman", 10, "bold"))
title_label.pack(side=tk.LEFT, padx=10)

def minimize_window():
    root.geometry("600x450")
    is_maximized[0] = False

def toggle_maximize():
    if is_maximized[0]:
        root.geometry("600x450")
        is_maximized[0] = False
    else:
        root.geometry(f"{root.winfo_screenwidth()}x{root.winfo_screenheight()}+0+0")
        is_maximized[0] = True

def move_window(event):
    root.geometry(f"+{event.x_root}+{event.y_root}")

close_button = tk.Button(title_bar, text='X', bg="#2e2e2e", fg="white", command=root.destroy, bd=0, font=("Times New Roman", 12, "bold"))
close_button.pack(side=tk.RIGHT, padx=5)

maximize_btn = tk.Button(title_bar, text='⬜', bg="#2e2e2e", fg="white", bd=0, command=toggle_maximize, font=("Times New Roman", 8, "bold"))
maximize_btn.pack(side=tk.RIGHT, padx=5)

minimize_btn = tk.Button(title_bar, text='▪', bg="#2e2e2e", fg="white", bd=0, command=minimize_window, font=("Times New Roman", 12, "bold"))
minimize_btn.pack(side=tk.RIGHT, padx=5)

title_bar.bind("<B1-Motion>", move_window)

style = ttk.Style()
style.theme_use('default')

style.configure("TNotebook", background=DARK_BG, borderwidth=0)
style.configure("TNotebook.Tab", background=DARKER_BG, foreground=TEXT_COLOR, padding=[12, 6])
style.map("TNotebook.Tab",
          background=[("selected", ACCENT_COLOR)],
          foreground=[("selected", "#ffffff")])

style.configure("TButton", background=ACCENT_COLOR, foreground="#ffffff", padding=6)
style.map("TButton",
          background=[("active", "#677bc4")])

tabs = {}
chat_tabs = ttk.Notebook(root)
chat_tabs.pack(fill='both', expand=True) #padx, pady = 10

#chat_display = tk.Text(root, height=15, width=60, state="disabled")
#chat_display.pack(pady=10)

#message_entry = tk.Entry(root, width=50)
#message_entry.pack(pady=5)

#send_button = tk.Button(root, text="Send Message", command=send_message)
#send_button.pack(pady=5)

#label = Label(root, text="Waiting for image...")
#label.pack()

create_user_tab("cory") #just for testing, maybe a db or some sort of file for persistence later?

polling_thread = threading.Thread(target=poll_for_images, daemon=True)
polling_thread.start()

root.mainloop()