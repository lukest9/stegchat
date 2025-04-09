import sys
import base64
import requests
import os
import random
import time
import cv2
import numpy as np
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

#Note: Python 3.10
#Note: we'll use png, because JPG HAS DISTORTION

last_mod_time_export = 0
last_mod_time_incoming = 0

error_ping = False

try:
    MASTER_TO_STEG_EXPORT_PATH = sys.argv[1]
    STEG_TO_MASTER_IMPORT_PATH = sys.argv[2]
    SOURCE_PATH = sys.argv[3]
    DESTINATION_PATH = sys.argv[4]
    WEB_TO_STEG_INCOMING_PATH = sys.argv[5]
    SERVER_URL = sys.argv[6]
    USERNAME = sys.argv[7]
    PASSWORD = sys.argv[8]
    PUBLIC_KEY_PATH = sys.argv[9]
except IndexError:
    MASTER_TO_STEG_EXPORT_PATH = r'C:\Users\lstal\Desktop\stegproject\export.txt'
    STEG_TO_MASTER_IMPORT_PATH = r'C:\Users\lstal\Desktop\stegproject\import.txt'
    SOURCE_PATH = r'C:\Users\lstal\Desktop\stegproject\stegencrypt\sources'
    DESTINATION_PATH = r'C:\Users\lstal\Desktop\stegproject\stegencrypt\dests'
    WEB_TO_STEG_INCOMING_PATH = r'C:\Users\lstal\Desktop\stegproject\stegencrypt\incoming\0.png'
    USERNAME = 'luke'
    print("Manual loading: Caution")

with open(PUBLIC_KEY_PATH, 'rb') as f:
    PUBLIC_KEY = RSA.import_key(f.read())
'''
key = RSA.generate(2048)

private_key = key.export_key()
public_key = key.public_key().export_key()

DEST_PRIVATE_KEY = private_key
DEST_PUBLIC_KEY = public_key
'''

def encrypt_image(image_path):
    with open(image_path, 'rb') as img_file:
        image_data = img_file.read()

    combined = PASSWORD.encode() + b'||' + image_data

    aes_key = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(combined)
    
    cipher_rsa = PKCS1_OAEP.new(PUBLIC_KEY)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    payload = {
        'username': USERNAME,
        'key': base64.b64encode(enc_aes_key).decode(),
        'nonce': base64.b64encode(cipher_aes.nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'data': base64.b64encode(ciphertext).decode()
    }
    return payload

def upload_file(img_path):
    payload = encrypt_image(img_path)
    url = 'http://localhost:5000/luke'
    response = requests.post(url, json=payload)
    print(response.json())

def get_random_image():
    images = [f for f in os.listdir(SOURCE_PATH)]
    return os.path.join(SOURCE_PATH, random.choice(images))

def pick_dest_path():
    '''
    #This is inefficient, if I care I can add a global for the next img number to use, but this works for now
    index = 0
    while True:
        img_path = os.path.join(DESTINATION_PATH, f"img{index}.png")
        if not os.path.exists(img_path):
            return img_path
        index += 1
    '''
    return r"C:\Users\lstal\Desktop\stegproject\stegencrypt\dests\img0.png"

# Take the path of the image you want to hide the message in, the message in binary,
# and where you want to save the message to
def simple_steg_encode(path, binary_message, dest_path):
    #get the image, prepend the stop sequence (16 bits, plenty of space for 2048 size keys)
    img = cv2.imread(path)
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
                cv2.imwrite(dest_path, img)
                return
    print("There should probably be some sort of error catch here")

# Take the path to an image, return the binary message hidden in the image
def simple_steg_decode(path):
    img = cv2.imread(path)
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

    #print(f"Decoded message {message_bin}")
    return message_bin

''' dft stuff
def encrypt_message(message):
    public_key = RSA.import_key(DEST_PUBLIC_KEY)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_message(message):
    private_key = RSA.import_key(DEST_PRIVATE_KEY)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(message)
    return decrypted_message.decode()

def embed_message(path, bin_msg):
    #Split the image into its 3 channels for each color
    image = cv2.imread(path)
    blue, green, red = cv2.split(image)

    #Perform DFT on each channel, which gives you the complex output, which is 2 channel
    dft_blue = cv2.dft(np.float32(blue), flags=cv2.DFT_COMPLEX_OUTPUT)
    dft_green = cv2.dft(np.float32(green), flags=cv2.DFT_COMPLEX_OUTPUT)
    dft_red = cv2.dft(np.float32(red), flags=cv2.DFT_COMPLEX_OUTPUT)

    #Shift low freqs to the center of the spectrum for processing
    dft_blue_shift = np.fft.fftshift(dft_blue)
    dft_green_shift = np.fft.fftshift(dft_green)
    dft_red_shift = np.fft.fftshift(dft_red)

    #Convert to binary, add STOP seq
    bin_msg_stop = bin_msg + '1111111111111110'
    index = 0

    #Embed the message into the frequency coefficients, the real part, which is index ,,0.
    #If the binary number at the specific index is 0, the coefficient is unchanged, if it is 1 it is incremented by 0.1, which in a number like 20.2568, doesn't change enough to change how the image looks
    #We're doing the exact same thing to all 3 channels, just to preserve the RGB functionality, it is normally just a grayscale

    #dft_blue_shift, for example is a frequency-domain representation that has been shifted, grabbing :2 gets the rows and cols, its basically just size
    rows, cols = dft_blue_shift.shape[:2]
    for i in range(rows):
        for j in range(cols):
            if index < len(bin_msg_stop):
                dft_blue_shift[i,j,0] += int(bin_msg_stop[index]) * 0.1
                dft_green_shift[i,j,0] += int(bin_msg_stop[index]) * 0.1
                dft_red_shift[i,j,0] += int(bin_msg_stop[index]) * 0.1
                index += 1
            else:
                break
        if index >= len(bin_msg_stop):
            break
    
    #ifft puts it back, turning our frequency domain into a 3D array represenation of a spatial domain
    dft_blue_shift = np.fft.ifftshift(dft_blue_shift)
    dft_green_shift = np.fft.ifftshift(dft_green_shift)
    dft_red_shift = np.fft.ifftshift(dft_red_shift)

    idft_blue = cv2.idft(dft_blue_shift)
    idft_green = cv2.idft(dft_green_shift)
    idft_red = cv2.idft(dft_red_shift)

    #taking the magnitude squares the real and imaginary values, and adds them together, which makes them able to transcribe what a pixel looks like
    idft_blue_magnitude = cv2.magnitude(idft_blue[:,:,0], idft_blue[:,:,1])
    idft_green_magnitude = cv2.magnitude(idft_green[:,:,0], idft_green[:,:,1])
    idft_red_magnitude = cv2.magnitude(idft_red[:,:,0], idft_red[:,:,1])

    #normalizing just makes sure there are no pixel values over 255 or under 0
    blue_final = cv2.normalize(idft_blue_magnitude, None, 0, 255, cv2.NORM_MINMAX)
    green_final = cv2.normalize(idft_green_magnitude, None, 0, 255, cv2.NORM_MINMAX)
    red_final = cv2.normalize(idft_red_magnitude, None, 0, 255, cv2.NORM_MINMAX)

    #just merges the color channels
    embedded_image = cv2.merge([blue_final, green_final, red_final])

    return np.uint8(embedded_image)

def check_for_stop_sequence(bits, bytetracker):
    return "Delete this"

def deembed_message(path):
    image = cv2.imread(path)
    blue, green, red = cv2.split(image)

    dft_blue = cv2.dft(np.float32(blue), flags=cv2.DFT_COMPLEX_OUTPUT)
    dft_green = cv2.dft(np.float32(green), flags=cv2.DFT_COMPLEX_OUTPUT)
    dft_red = cv2.dft(np.float32(red), flags=cv2.DFT_COMPLEX_OUTPUT)

    dft_blue_shift = np.fft.fftshift(dft_blue)
    dft_green_shift = np.fft.fftshift(dft_green)
    dft_red_shift = np.fft.fftshift(dft_red)
    
    bin_msg = ""
    byte_tracker = 0
    rows, cols = dft_blue_shift.shape[:2]
    for i in range(rows):
        for j in range(cols):
            bin_msg += str(int(dft_blue_shift[i,j,0] % 2))
            #impossible to check for stop sequence, verify data is capturable and readable first
            if check_for_stop_sequence(bin_msg, byte_tracker):
                byte_tracker += 1
                if byte_tracker > 16:
                    byte_tracker = 1
            else:
                break
            bin_msg += str(int(dft_green_shift[i,j,0] % 2))
            if check_for_stop_sequence(bin_msg, byte_tracker):
                byte_tracker += 1
                if byte_tracker > 16:
                    byte_tracker = 1
            else:
                break
            bin_msg += str(int(dft_red_shift[i,j,0] % 2))
            if check_for_stop_sequence(bin_msg, byte_tracker):
                byte_tracker += 1
                if byte_tracker > 16:
                    byte_tracker = 1
            else:
                break
    
    #There is a stop sequence, have to remove it
    bin_msg = bin_msg[:len(bin_msg)-16]
    extracted_msg = ''.join(chr(int(bin_msg[i:i+8], 2)) for i in range(0, len(bin_msg), 8))

    return extracted_msg

def undetectable_dft_steg_main():
    while True:
        #run simple methods to identify a random image to hide the message in, and where the output will go
        image_path = get_random_image(source_path)
        destination_path = pick_dest_path(dest_path)
        #get input from terminal, similar to how a chat service will look
        inp = input(" : ")
        #encrypt the message using the RSA keypair
        encrypted_message = encrypt_message(inp)
        #key encryption spits out a byte object, we need a string, that we will later turn into binary in the steg encoding method
        encoded_message = base64.b64encode(encrypted_message).decode()
        #homemade dft method, spits out an image
        embedded_image = embed_message(image_path, encoded_message)
        #write spitted image to destination folder
        cv2.imwrite(destination_path, embedded_image)
        #homemade dft deembedder, spits out message, also in binary
        binary_desteg_message = simple_steg_decode(destination_path)
        #binary to int
        int_desteg_message = int(binary_desteg_message, 2)
        #int to bytes
        byte_desteg_message = int_desteg_message.to_bytes(len(binary_desteg_message) // 8, byteorder='big')
        #bytes to be decrypted by private key
        decrypted_message = decrypt_message(byte_desteg_message)
        print(f"Decrypted message: {decrypted_message}")
'''

#For testing purposes only
def copy_dests_to_incoming(dests_path):
    image = cv2.imread(dests_path)
    cv2.imwrite(WEB_TO_STEG_INCOMING_PATH, image)
    print(f"Image at {dests_path} written to {WEB_TO_STEG_INCOMING_PATH}")

# First sniffer for messages added to master's export folder
# Takes encrypted messages, writes image to master's dest folder
def sniffer_master_export():
    global last_mod_time_export
    try:
        mod_time = os.stat(MASTER_TO_STEG_EXPORT_PATH).st_mtime  
        # if its been modified, export, and if file doesn't exist, just wait
        if mod_time > last_mod_time_export:
            last_mod_time_export = mod_time
            if os.stat(MASTER_TO_STEG_EXPORT_PATH).st_size != 0:
                # Start Method
                image_path = get_random_image()
                destination_path = pick_dest_path()
                with open(MASTER_TO_STEG_EXPORT_PATH, 'rb') as pipe:
                    encrypted_message = pipe.read()
                    print("Message read from export.txt")
                encrypted_bin_message = ''.join(format(byte, '08b') for byte in encrypted_message)
                # encode method automatically sends to the destination folder
                simple_steg_encode(image_path, encrypted_bin_message, destination_path)
                print(f"Message steganographically encoded into {destination_path}")
                upload_file(destination_path)

    except FileNotFoundError:
        pass
    time.sleep(0.5)

# Second sniffer for images added to master's incoming folder
# Takes image, desteg, writes it into master's import folder
def sniffer_master_incoming():
    # previously declared timing varibale, checking last accessed
    global last_mod_time_incoming
    global error_ping
    try:
        # if its been modified, import, and if file doesn't exist, just wait
        mod_time = os.stat(WEB_TO_STEG_INCOMING_PATH).st_mtime
        if mod_time > last_mod_time_incoming:
            last_mod_time_incoming = mod_time
            print("Change to import detected")
            if os.stat(WEB_TO_STEG_INCOMING_PATH).st_size != 0:
                # Start Method
                print("Decoding incoming steganography image")
                binary_desteg_message = simple_steg_decode(WEB_TO_STEG_INCOMING_PATH)
                
                #binary to bytes
                byte_data = bytearray()
                for i in range(0, len(binary_desteg_message), 8):
                    byte_data.append(int(binary_desteg_message[i:i+8], 2))
                #bytes to base64
                #bytes to be decrypted by private key
                
                try:
                    with open(STEG_TO_MASTER_IMPORT_PATH, 'wb') as file:
                        file.write(byte_data)
                except ValueError as e:
                    if error_ping:
                        print(f"Error: {e}")
                    else:
                        error_ping = True
                # End Method
                '''
                # Split the binary sequence into 8-bit chunks
                binary_values = [binary_desteg_message[i:i+8] for i in range(0, len(binary_desteg_message), 8)]
                
                # Convert each 8-bit chunk to an ASCII character
                ascii_chars = [chr(int(bv, 2)) for bv in binary_values]
                
                # Join the characters into a string and return
                with open(STEG_TO_MASTER_IMPORT_PATH, 'w') as file:
                    return_string = ''.join(ascii_chars)
                    print(f'Writing {return_string} to import.txt')
                    file.write(return_string)
                # End Method
                '''

    except FileNotFoundError:
        pass
    time.sleep(0.5)

def main():
    while True:
        sniffer_master_export()
        sniffer_master_incoming()

if __name__ == "__main__":
    print("Steganography Active")
    #print("Manual Decode: " + simple_steg_decode(r'C:\Users\lstal\Desktop\stegproject\stegencrypt\dests\img4.png'))
    main()