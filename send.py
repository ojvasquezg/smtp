import smtplib
from email.message import EmailMessage
import threading
import ssl

def send_email(sequence):
    try:
        # Configura el mensaje
        msg = EmailMessage()
        msg['Subject'] = f'Prueba de adjuntos javscriopt :{sequence}'
        msg['From'] = 'orlandojvasquezg@outlook.com'
        msg['To'] = 'orlandojvasquez74@gmail.com'
        msg.set_content('Este es el cuerpo del mensaje en texto.')
        msg.add_alternative('huy esto <script>alert("hola");</script>se quito<p>Este es el <b>cuerpo</b> del mensaje en <i>HTML</i>.</p>', subtype='html')

        # Añade un archivo adjunto
        with open('envia.pdf', 'rb') as f:
            msg.add_attachment(f.read(), maintype='application', subtype='octet-stream', filename='envia.pdf')

        # Envía el correo
        with smtplib.SMTP("127.0.0.1", 4650) as server:
            context = ssl.create_default_context()
            #server.starttls(context=context)  
            server.login('user1@example.com', 'password1234')
            server.send_message(msg)

        print(f"Correo {sequence} enviado")
    except Exception as e:
        print(f"Error enviando el correo {sequence}: {e}")

# Crear y lanzar los hilos
threads = []
for i in range(1, 2):
    t = threading.Thread(target=send_email, args=(i,))
    threads.append(t)
    t.start()

# Esperar a que todos los hilos terminen
for t in threads:
    t.join()

print("Todos los correos han sido enviados")
