# Proyecto-Final-Lenguajes-Computacion
Proyecto Final de backend bien criptográfico de lenguajes de computacion

Primera etapa- Preparación y Definición de estructura del proyecto: En github creamos un nuevo repositorio para poder desplegar nuestro proyecto, al crear añadimos el README.md, para tenerlo listo al momento de clonar en VSCode. Para poder correr en cualquier momento los endpoints, dejamos listo el servicio web en render para desplegar cuando se haga el commit 
/Proyecto-Final-Lenguajes-Computacion
├── /src
│   ├── /controllers
│   │   ├── cryptoController.js  
│   ├── /services
│   │   ├── cryptoService.js               
│   ├── /routes
│   │   ├── cryptoRoutes.js      
│   ├── index.js
├── package-lock.json                
├── package.json                
├── .gitignore                  
├── README.md                    

Segunda etapa- Instalación de paquetes: npm install express body-parser crypto-js argon2 corremos este comando para instalar los siguientes paquetes para el funcionamiento del backend criptográfico

Tercera etapa - Desarrollo de servicio 
SHA-256 (Integridad):
Utilizando crypto, generamos un hash SHA-256 con un texto plano, convirtiendolo en hash irreversible en formato hexadecimal, SHA-256 es ideal por que mantiene una alta seguridad y es util para almacenar valores que no deben recuperarse.

Argon2 (Contraseñas):
Aqui aplicamos el algoritmo de argon2, para realizar el hashing de uuna contraseña, retornando el hash como una cadena segura, y si no puede lanza un error. Esta diseñado para introducir un costo computacional que dificulta mas saber una contraseña en caso de un ataque masivo, ya que esta diseñado como un algoritmo mas lento en comparacion a SHA-256 y con uso internsivo de memoria.

AES-256-CBC (Cifrado simétrico):
Para el cifrado tenemos que usa el algoritmo simetrico con una clave de 32 bytes y un iv de 16 bytes, en base 64, convirtiend en buffers y cifrando el texto en base64.Para desencriptar hace lo inverso, tomando la clave y iv para descifrar el contenido y convertirlo a utf8. Al usar claves de 256 bits, las cuales son el estandar para cifrado simetrico da mayor seguridad ya que es casi computacionalmente inalcanzable y estandar ya que permite cifrar gigabytes por segundo

ChaCha20-Poly1305 (Cifrado AEAD moderno):
Chacha20, implementa un cifrado chacha20poly1305, el cual genera claves 32 bytes y nonces de 12, cifrando el mensaje y generando un tag de autenticacion, devolviendo un cipher,key nonce y tag en base 64. Para el descifrado toma los valores base64 los convierte a buffers y reconstruye el mensaje original.Chacha20 es muy util por su rendimiento alto sin aceleracion por hardware, lo que permite que pueda ser usado en iot o servidores con procesadores ARM, dando cifrado y autenticacipon en una sola operacion lo utilizan google y whatsapp para conexiones seguras de alto rendimiento


RSA-OAEP con SHA-256 (Cifrado asimétrico):
RSA en modo OAEP es más seguro que RSA clásico porque protege contra ataques de relleno y manipulación. El uso de SHA-256 dentro de OAEP aumenta aún más la seguridad al ofrecer un hash resistente y moderno. RSA de 2048 bits sigue siendo estándar seguro y práctico para cifrado de claves y mensajes cortos.Integra un esquema de relleno el cual evita ataques de manipulacion, asegura que cada mensaje sea unico, aunque sea el mismo mensaje, elimina patrones y refuerza la confidencialidad, tiene un tamaño de 2048 bits, lo que asegura proteccion. RSA cifra el texto plano con la clave publica, utilizando un padding y hash SHA-256, convierte el texto a utf8 y lo cifra, en una cadena cifrada en base64 junto con la key, para descifrar usa la clave privada, y devuelve el texto original en utf8

DSA-SHA256 (Firmas digitales):
Para DSA se firma usando una clave privada con el hash de sha256, convirtiendo la firma a bas64 y convirtiendo en algoitmo, devolviendo el tamaño de clave y clave publica. Luego verfica si la firma pertenece a un mensaje, convierte de base64 a buffer, con el verificador checa si la firma coincide.DSA comnbina los algoritmos de firma digital basado en problemas matematicos, combinando con el hash sha256 lo que previene de colisiones y ataques, teniendo imposibilidad práctica de resolver el logaritmo discreto y de la calidad del número aleatorio k utilizado en cada firma

LINK DEL DESPLIEGUE EN RENDER: https://proyecto-final-lenguajes-computacion.onrender.com

ENDPOINTS:
POST https://proyecto-final-lenguajes-computacion.onrender.com/api/hash/sha256
BODY:
{
  "text": "Hola Mundo"
}
RESPONSE:
{
  "hash": "c3a4a2e49d91f2177113a9adfcb9e9faf9679dc4557a0e3a46021bd39a6f481"
}
POST https://proyecto-final-lenguajes-computacion.onrender.com/api/hash/argon2
BODY:
{
  "password": "miContraseñaSegura"
}

RESPONSE:
{
  "hash": "$argon2id$v=19$m=65536,t=3,p=4$RVMou6KBZptQtrOhdadk8AStv5glswxgESsopy9FGz1VhRFewmE9Jx1XCO5fM7S"
}
BODY:
{
  "text": "Texto a cifrar con AES-256"
}
RESPONSE:
{
  "encrypted": "S0hRezixnPoqaOtBV+3zYD6wlHGeITifKYXXAembKQw=",
  "key": "wQ1ow2PJjUzcMHHha4w6U7Al9p/je9tcrIeOZNQNIE=",
  "iv": "OGgA3YU6f3NtDHT88cXZeQ=="
}
POST https://proyecto-final-lenguajes-computacion.onrender.com/api/encrypt/aes_cbc
BODY:
{
  "encryptedText": "SDhRezixnPoqaOtBV+3zYD6wLhGeITifKYXXAembKQw=",
  "key": "wQ1ow2PJjUzcMHHha4w6U7Al9p/je9tcrIeOZNQNIE=",
  "iv": "OGgA3YU6f3NtDHT88cXZeQ=="
}
RESPONSE:
{
  "decrypted": "Texto a cifrar con AES-256"
}
POST https://proyecto-final-lenguajes-computacion.onrender.com/api/decrypt/aes_cbc
BODY:
{
  "text": "Hola mundo, este es un mensaje secreto"
}
RESPONSE:
{
  "algorithm": "chacha20-poly1305",
  "cipherTextBase64": "SH91cDpzPV5jM6S1sO2HaaEYqyRgMTTl1pEn1+Q3238ftVd46o8=",
  "keyBase64": "OH51USPqx66J3G6ljMPu7+FVOa0hJfNWAn/9Pwieeew=",
  "nonceBase64": "RzgK0VJ+0vLD1Us",
  "authTagBase64": "b7C7YNqbjpB1Zk0vQk3brQg=="
}
POST https://proyecto-final-lenguajes-computacion.onrender.com/api/encrypt/chacha20
BODY:
{
  "text": "Hola mundo, este es un mensaje secreto"
}
RESPONSE:
{
  "algorithm": "chacha20-poly1305",
  "cipherTextBase64": "SH91cDpzPV5jM6S1sO2HaaEYqyRgMTTl1pEn1+Q3238ftVd46o8=",
  "keyBase64": "OH51USPqx66J3G6ljMPu7+FVOa0hJfNWAn/9Pwieeew=",
  "nonceBase64": "RzgK0VJ+0vLD1Us",
  "authTagBase64": "b7C7YNqbjpB1Zk0vQk3brQg=="
}
POST https://proyecto-final-lenguajes-computacion.onrender.com/api/decrypt/chacha20
BODY:
{
  "algorithm": "chacha20-poly1305",
  "cipherTextBase64": "SH91cDpzPV5jM6S1sO2HaaEYqyRgMTTl1pEn1+Q3238ftVd46o8=",
  "keyBase64": "OH51USPqx66J3G6ljMPu7+FVOa0hJfNWAn/9Pwieeew=",
  "nonceBase64": "RzgK0VJ+0vLD1Us",
  "authTagBase64": "b7C7YNqbjpB1Zk0vQk3brQg=="
}
RESPONSE:
{
  "algorithm": "chacha20-poly1305",
  "plainText": "Hola mundo, este es un mensaje secreto"
}
POST https://proyecto-final-lenguajes-computacion.onrender.com/api/encrypt/rsa
BODY:
{
  "text": "Prueba 7 de 10 LETS GO"
}
RESPONSE:
{
  "algorithm": "RSA-OAEP",
  "modulusLength": 2048,
  "cipherTextBase64": "RQo9sBwv2I8GEzXoAMjpcpmzfAFS6InGDzH7Nsh4uB1KR9nOk2ta0g83susD7v0dpGVyvluFy0UYIoW0Hxjzb...",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOC... (continúa)\n-----END PUBLIC KEY-----"
}
POST https://proyecto-final-lenguajes-computacion.onrender.com/api/decrypt/rsa
BODY:
{
  "cipherTextBase64": "RQo9sBwv2I8GEzXoAMjpcpmzfAFS6InGDzH7Nsh4uB1KR9nOk2ta0g83susD7v0dpGVyvluFy0UYIoW0Hxj2WzzrKjmgKULnjBoYg78qUu1sQsg0pvVLGzkJ1y2Pycig79m8uUI4308S2vcxCebkOy0Em2ubTwv/qWLX+F0QALinG5Fx0pGR0Un3LFeKuXTtC1Gmb3y1cF/ALYs+mMlImIZE/4jphQLd2PoPTQ2M7C4/Hb+YVk0j53LLw0e8ECn1NxUfcM/ftzwxELPa54wnfo5/cIjjdSCVt0bMjDTR06t939uP2pqM9WM7M76Wy/fC/pEm2K+zYFT20f5w=="
}
RESPONSE:
{
  "algorithm": "RSA-OAEP",
  "plainText": "Prueba 7 de 10 LETS GO"
}
POST https://proyecto-final-lenguajes-computacion.onrender.com/api/sign/dsa
BODY:
{
  "message": "Prueba DSA 9 de 10 LO VAMOS A LOGRAR"
}
RESPONSE:
{
  "algorithm": "DSA-SHA256",
  "keySize": 1024,
  "message": "Prueba DSA 9 de 10 LO VAMOS A LOGRAR",
  "signatureBase64": "MD0CHQDZnEpuR16tc/mJ60I1gjk1iuSXC+hcvJv38jRzAhwqY/MhpoRy9Ts@nNmJt1W6M2fYtvN7csSRFS...",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBwDCCAT0GByqGSM44BAEwggEiAoGBA..... (continúa)\n-----END PUBLIC KEY-----"
}

POST https://proyecto-final-lenguajes-computacion.onrender.com/api/verify/dsa
BODY 
{
  "message": "Prueba DSA 9 de 10 LO VAMOS A LOGRAR",
  "signatureBase64": "MD0CHQDZnEpuR16tc/mJ60Ija1gkiIuSXC+hcwJv8jRzAhwqY/MhpoRy9TsgNmMJt1W6M2fYtwN7csSRFS2U"
}
RESPONSE:
{
  "algorithm": "DSA-SHA256",
  "keySize": 1024,
  "message": "Prueba DSA 9 de 10 LO VAMOS A LOGRAR",
  "signatureBase64": "MD0CHQDZnEpuR16tc/mJ60Ija1gkiIuSXC+hcwJv8jRzAhwqY/MhpoRy9TsgNmMJt1W6M2fYtwN7csSRFS2U",
  "valid": true
}




