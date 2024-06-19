import os
import html



from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64




# Función para leer las propiedades desde el archivo
def read_properties(file_path):
    properties = {}
    with open(file_path, 'r') as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                properties[key.strip()] = value.strip()
    return properties

# Leer las propiedades del archivo
properties = read_properties('smtp.properties')
KEY = properties['smtp.encryptKey']  # Leer la clave como cadena de texto
IV = properties['smtp.encryptIV']    # Leer el IV como cadena de texto


def escape_html_entities(data):  #Hallazgo 1
    return html.escape(data)

# Función de cifrado
def encrypt(data, key):
    # Generar un IV aleatorio de 16 bytes
    iv = os.urandom(16) #Hallazgo 4
    cipher = Cipher(algorithms.AES(key.encode('utf-8')), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    # Prepend the IV to the ciphertext and encode it in Base64
    return escape_html_entities( base64.b64encode(iv + ciphertext).decode('utf-8'))

def decrypt(encrypted_data, key):
    # Decode the Base64 encoded data
    encrypted_data = base64.b64decode(encrypted_data)
    # Extract the first 16 bytes as the IV    
    iv = encrypted_data[:16] #Hallazgo 4 version 
    #fin correccion hallazgo4

    ciphertext = encrypted_data[16:]
    # Set up the cipher with the same key and IV
    cipher = Cipher(algorithms.AES(key.encode('utf-8')), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    # Decrypt and unpad the data
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return escape_html_entities( data.decode('utf-8'))


print ("IV:",IV);
data = "password1234"
encrypted_data = encrypt(data, KEY)
print(f"Encrypted: {encrypted_data}")
encrypted_data="A2VjngwgT31w5pBFyfPZUy542Df4t4HygzwtfC7f74s="
decrypted_data = decrypt(encrypted_data, KEY)
print(f"Decrypted: {decrypted_data}")
