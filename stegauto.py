import argparse
from PIL import Image
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def encrypt_password(password, key):
    # Encrypt the password using aes256
    
    padder = padding.PKCS7(128).padder()  # Create a padder for padding the password to a multiple of block size
    padded_password = padder.update(password.encode()) + padder.finalize()  # Pad the password and finalize the padding process
    iv = os.urandom(16)  # Generate a random initialization vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  # Create an aes256 cipher in CBC mode with the given key and IV
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()  # Encrypt the padded password
    return iv + encrypted_password  # Return the IV concatenated with the encrypted password

def decrypt_password(encrypted_password, key):
    # Decrypt the password using aes256
    
    iv = encrypted_password[:16]  # Extract the IV from the first 16 bytes of the encrypted data
    encrypted_data = encrypted_password[16:]  # Extract the encrypted data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  # Create an aes256 cipher in CBC mode with the given key and IV
    decryptor = cipher.decryptor()
    padded_password = decryptor.update(encrypted_data) + decryptor.finalize()  # Decrypt the data
    unpadder = padding.PKCS7(128).unpadder()  # Create an unpadder to remove padding from the decrypted data
    password = unpadder.update(padded_password) + unpadder.finalize()  # Unpad the decrypted password
    return password.decode()  # Return the decoded password

def bytes_to_binary(data):
    # Convert bytes to a binary string
    
    return ''.join(format(byte, '08b') for byte in data)  # Convert each byte to its binary representation and concatenate

def binary_to_bytes(binary_data):
    # Convert a binary string to bytes
    
    byte_array = bytearray(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))  # Convert every 8 bits in the binary string to a byte and append to byte array
    return bytes(byte_array)  # Return the byte array as bytes

def embed_data_in_image(image_data, binary_data):
    # Embed binary data into the least significant bits of image data
    
    flat_image_data = image_data.flatten()  # Flatten the image data for easier manipulation
    for i, bit in enumerate(binary_data):  # Embed each bit of binary data into the LSB of each pixel
        flat_image_data[i] = (flat_image_data[i] & 0xFE) | int(bit)
    return flat_image_data.reshape(image_data.shape)  # Reshape the modified flat data back to the original image shape

def extract_data_from_image(image_data, data_length):
    # Extract binary data from the least significant bits of image data
    
    flat_image_data = image_data.flatten()  # Flatten the image data for easier extraction
    binary_data = ''.join(str(flat_image_data[i] & 1) for i in range(data_length * 8))  # Extract the LSBs and concatenate into a binary string
    return binary_data

def embed_password_in_image(image_path, password, key, output_path):
    # Embed an encrypted password into an image
    
    image = Image.open(image_path)  # Open the image file
    image_data = np.array(image)  # Convert the image to a NumPy array
    encrypted_password = encrypt_password(password, key)  # Encrypt the password
    binary_password = bytes_to_binary(encrypted_password)  # Convert the encrypted password to a binary string
    modified_image_data = embed_data_in_image(image_data, binary_password)  # Embed the binary password into the image data
    modified_image = Image.fromarray(modified_image_data.astype(np.uint8))  # Create a new image from the modified image data
    modified_image.save(output_path)  # Save the modified image to the output path

def extract_password_from_image(image_path, key):
    # Extract an encrypted password from an image and decrypt it
    
    image = Image.open(image_path)  # Open the image file
    image_data = np.array(image)  # Convert the image to a NumPy array
    encrypted_password_length = 16 + len(encrypt_password('dummy', key)) - 16  # Calculate the length of the encrypted password (16 bytes for IV + length of encrypted password without dummy padding)
    binary_data = extract_data_from_image(image_data, encrypted_password_length)  # Extract the binary data from the image
    encrypted_password = binary_to_bytes(binary_data)  # Convert the binary data to bytes
    password = decrypt_password(encrypted_password, key)  # Decrypt the password
    return password

def main():
    parser = argparse.ArgumentParser(description='Embed or extract a password in an image using LSB steganography with aes256 encryption.')
    parser.add_argument('mode', choices=['embed', 'extract'], help='Mode: "embed" to embed a password, "extract" to extract a password')
    parser.add_argument('input_image', help='Path to the input image')
    parser.add_argument('password', nargs='?', help='Password to embed in the image (only required for embedding)')
    parser.add_argument('output_image', nargs='?', help='Path to the output image (only required for embedding)')
    args = parser.parse_args()

    if args.mode == 'embed':
        # Extract the base name of the output image and use it to generate the key file name
        base_name = os.path.splitext(os.path.basename(args.output_image))[0]
        key_file_path = f'{base_name}_key.bin'
        key = os.urandom(32)  # Generate a random aes256 key
        with open(key_file_path, 'wb') as key_file:  # Save the key to a file
            key_file.write(key)
        embed_password_in_image(args.input_image, args.password, key, args.output_image)  # Embed the password in the image
        print(f'Password embedded in {args.output_image}. aes256 key saved to {key_file_path}.')
        
    elif args.mode == 'extract':
        # Extract the base name of the input image and use it to find the key file name
        base_name = os.path.splitext(os.path.basename(args.input_image))[0]
        key_file_path = f'{base_name}_key.bin'
        with open(key_file_path, 'rb') as key_file:  # Read the key from the file
            key = key_file.read()
        password = extract_password_from_image(args.input_image, key)  # Extract the password from the image
        print(f'Extracted password: {password}')

if __name__ == '__main__':
    main()
