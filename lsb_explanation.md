def steg_encode(blank_path, message):
    bytes_message = message.encode('utf-8') #string to bytes
    binary_message = ''.join(format(byte, '08b') for byte in bytes_message) #bytes to bin
    #read in the image you're encoding into
    img = cv2.imread(blank_path)
    message_length = len(binary_message)
    #the way we ended up doing the decoding is to add the message length, in binary, to the beginning of the payload,
    #so that during decoding you can quickly figure out how many pixels to pull from to rebuild the message
    length_bin = format(message_length, '016b')
    binary_data = length_bin + binary_message
    #print(f"message length: {length_bin} message: {binary_message}")
    height, width, _ = img.shape
    data_index = 0
    for y in range(height):
        for x in range(width):
            #iterates through the pixels in the image, pulling them one by one
            pixel = img[y,x]
            if data_index < len(binary_data):
                #pixel[0] pulls the blue value, which is of course one byte, doing & with 0xFE wipes just the last bit,
                #0xFE is 11111110, so then you can insert your binary bit into the pixel value
                pixel[0] = ((pixel[0] & 0xFE) | int(binary_data[data_index]))
                img[y,x] = pixel
                data_index += 1
            else:
                #when you've exhausted your data, stop
                return img
    print("There should probably be some sort of error catch here")

def steg_decode(img):
    binary_message = ''
    height, width, _ = img.shape
    for y in range(height):
        for x in range(width):
            pixel = img[y,x]
            #doing & 1 just pulls the very last bit of the blue pixel, so it rebuilds the binary message
            binary_message += str(pixel[0] & 1)
    #cut off the message length bits
    message_length_bin = binary_message[:16]
    message_length = int(message_length_bin, 2)
    #print(f"message length: {message_length_bin}")
    #pulls the message-length amount of bits from the decoded binary
    message_bin = binary_message[16:16 + message_length]
    #reformatting from binary
    decoded_message = ''.join(chr(int(message_bin[i:i+8], 2)) for i in range(0, len(message_bin), 8))
    return decoded_message
