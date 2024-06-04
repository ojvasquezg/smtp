
import os
import asyncio
import ipaddress
import ssl
import smtplib
from datetime import datetime
from email import message_from_bytes
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope, AuthResult, LoginPassword
from email.policy import default
import random

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

properties = read_properties('smtp.properties')
RUTA_CERTIFICADO = 'ca.pem'
VALID_USERNAME = properties.get('smtp.validUsername')
VALID_PASSWORD = properties.get('smtp.validPassword')
ALLOWED_IP = properties.get('smtp.allowedIP')
AUTH_REQUIRE_TLS = properties.get('smtp.authRequireTls')
SMTP_SERVER = properties.get('smtp.server')
SMTP_PORT = properties.get('smtp.port')
SMTP_USERNAME = properties.get('smtp.username')
SMTP_PASSWORD = properties.get('smtp.password')
SMTP_USE_SSL = properties.get('smtp.useSSL')
BASE_SAVE_PATH = properties.get('smtp.baseSavePath')
VALID_EXTENSIONS = properties.get('smtp.validExtension', '').split(';')
KEY = properties.get('smtp.encryptKey')  # Leer la clave como cadena de texto
IV = properties.get('smtp.encryptIV')    # Leer el IV como cadena de texto
LISTEN_IP=properties.get("smtp.listenIp")
ALLOWED_PORT=properties.get("smtp.allowedPort")
def encrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key.encode('utf-8')), modes.CBC(iv.encode('utf-8')), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv.encode('utf-8') + ciphertext).decode('utf-8')

def decrypt(encrypted_data, key, iv):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key.encode('utf-8')), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode('utf-8')


class Authenticator:  
    def __call__(self, server, session, envelope, mechanism, auth_data):
        print ("inicia autenticacion: ", mechanism,"aud:",auth_data)
        print ("Usuario valido: ", VALID_USERNAME," Clave:",VALID_PASSWORD)
        if mechanism == 'LOGIN' or mechanism == 'PLAIN':
            if isinstance(auth_data, LoginPassword):
                username, password = auth_data.login, auth_data.password
                print(f"Usuario recibido: {username}")
                print(f"Clave recibida: {password}")
                
                hashed_data=encrypt(password.decode('utf-8'), KEY, IV)
                if username.decode('utf-8') == VALID_USERNAME and hashed_data == VALID_PASSWORD:
                    print ("Entra por auth exitosa")
                    return AuthResult(success=True)
        print ("Auth NO exitosa")
        return AuthResult(success=False, handled=False,message='Autenticacion necesaria')

class CustomSMTPHandler:

    def is_valid_extension(self, filename):
        extension = filename.rsplit('.', 1)[-1].lower()  # Obtiene la extensión del archivo
        return extension in VALID_EXTENSIONS

    def get_body_to_file(self,email_message):        
        body = []        
        for part in email_message.walk():
            # Filtra solo las partes del cuerpo del mensaje que son texto y no son adjuntos
            if part.get_content_maintype() == 'text' and part.get('Content-Disposition') is None:
               charset = part.get_content_charset()
               body.append(part.get_payload(decode=True).decode(charset or 'utf-8',errors="ignore"))
        body_content = "\n".join(body)       
        print(f"Obteniendo body:{body_content}")     
        print(f"Fin Obteniendo body")     
        return body_content    
    #end get_body_to_file

    async def enviar_correo(self, email_message,sender_from, recipients):
        msg = MIMEMultipart()
        msg['From'] = sender_from
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = email_message['Subject']
        
        for part in email_message.walk():
            #print ("pasa por 1")
            # Si es texto plano, crea un objeto MIMEText
            if part.get_content_type() == 'text/plain':
                #print ("pasa por 2")
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or 'utf-8'  # Selecciona una codificación predeterminada
                body = MIMEText(payload.decode(charset) if payload else '', _charset=charset)
                #print ("pasa por 3",body)
                msg.attach(body)
                #print ("pasa por 4")
            # Si es HTML, crea un objeto MIMEText con el tipo 'html'
            elif part.get_content_type() == 'text/html':
                #print ("pasa por 5")
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or 'utf-8'  # Selecciona una codificación predeterminada
                body = MIMEText(payload.decode(charset) if payload else '', _subtype='html', _charset=charset)
                #print ("pasa por 6",body)
                msg.attach(body)
                #print ("pasa por 7")
        
        #print ("Body",body)

        for part in email_message.iter_attachments():
            filename = part.get_filename()
            if filename:
                attachment = MIMEApplication(part.get_payload(decode=True), Name=filename)
                attachment['Content-Disposition'] = f'attachment; filename="{filename}"'
                msg.attach(attachment)
        try:
            if SMTP_USE_SSL == 'True':
                server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
            else:
                server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()  # Iniciar cifrado TLS
            hashed_data=decrypt(SMTP_PASSWORD, KEY, IV)
            server.login(SMTP_USERNAME, hashed_data)
            server.send_message(msg)
            server.quit()
            print("Correo enviado exitosamente")
        except Exception as e:
            print(f"Error al enviar correo: {e}")
        '''
        '''

    #end enviar_correo

    async def handle_DATA(self, server, session, envelope):
        sender_ip = session.peer[0]
        if self.is_allowed_ip(sender_ip):
            print("IP del remitente permitida. Procesando correo...")
            sender_from =envelope.mail_from
            # Convierte los datos del correo en un objeto de email
            email_message = message_from_bytes(envelope.content, policy=default)
            subject = email_message['Subject'] or 'Sin Asunto'
            recipients = envelope.rcpt_tos
            body_content="\n"+self.get_body_to_file(email_message)
            #Registrar la informacion en un log
            # Crea la carpeta para el correo
            folder_path = os.path.join(BASE_SAVE_PATH, "logEnvios")
            os.makedirs(folder_path, exist_ok=True)            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            random_number = random.randint(1000, 9999)
            filename_name = f"email_{timestamp}_{random_number}"+".txt"
            # Guarda el contenido del cuerpo en un archivo de texto dentro de la carpeta
            file_content = f"Destinatario: {recipients}\nAsunto: {subject}\n{body_content}"
            email_filepath = os.path.join(folder_path, filename_name)
            with open(email_filepath, 'w', encoding='utf-8') as f:
                f.write(file_content)
            await self.enviar_correo(email_message, sender_from,recipients)
            return '250 Message accepted for delivery'
        else:
            print(f"IP del remitente no permitida.{sender_ip} :Rechazando correo...")
            return '550 Access denied'            

    def is_allowed_ip(self, ip_address):
        allowed_ips = ALLOWED_IP.split(';')
        for allowed_ip in allowed_ips:
            try:
                if ipaddress.ip_address(ip_address) in ipaddress.ip_network(allowed_ip):
                    return True
            except ValueError:
                # Si la dirección IP permitida no es válida, ignórala y pasa a la siguiente
                continue
        return False



async def main():
    


    auth = Authenticator()
    authRequireTls=False
    if AUTH_REQUIRE_TLS == "True":
        authRequireTls=True
    contexto_ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    contexto_ssl.load_cert_chain("code.crt", "code.key")
    handler = CustomSMTPHandler()
    controller = Controller(handler, hostname=LISTEN_IP, port=ALLOWED_PORT, authenticator=auth, auth_required=True, auth_require_tls=authRequireTls)
    controller.start()
    print("Servidor SMTP escuchando en el puerto ",ALLOWED_PORT)
    try:
        while True:
            await asyncio.sleep(3600)  # Mantén el servidor en ejecución
    except KeyboardInterrupt:
        print("Detención del programa solicitada por el usuario.")
    finally:
        controller.stop()
        print("Servidor detenido")

if __name__ == "__main__":
    asyncio.run(main())
    #data = "OXVCd0U0ck03dFB3UzN6VkVdzTNgwQpWN3/6J56j4yU="
    #encrypted_data = encrypt(data, KEY, IV)
    #print(f"Encrypted: {encrypted_data}")

    #decrypted_data = decrypt(SMTP_PASSWORD, KEY, IV)
    #print(f"Decrypted: {decrypted_data}")