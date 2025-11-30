const crypto = require('crypto');
const argon2 = require('argon2');


const sha256HashService = (text) => {
  try {
    const hash = crypto.createHash('sha256').update(text).digest('hex'); //utiliza modulo crypto de node ára crear un objeto de hash con sha256
    return hash; // devuelve el hash
  } catch (err) {
    console.error('Error en el servicio SHA-256:', err); //en caso de no lograrlo manda un error
    throw new Error('Error al generar el hash SHA-256');
  }
};

const argon2HashService = async (password) => { //recibe password como parametro
  try {
    const hash = await argon2.hash(password); //llama a argon2.hash para generar el hash
    return hash; //devuelve el hash
  } catch (err) {
    console.error('Error en el servicio Argon2:', err); // en caso de no lograrlo manda un error
    throw new Error('Error al generar el hash Argon2');
  }
};

const aesEncryptService = (text, key, iv) => { // va a recibir un texto, una llave y el vector de inicializacion
  try {
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
    let encrypted = cipher.update(text, 'utf8', 'base64'); // Convierte la clave y el iv desde base64 a buffer binario
    encrypted += cipher.final('base64'); //el texto a cifrar se concatena con el bloque restante en base64
    return encrypted;  //termina la encriptacion
  } catch (err) {
    console.error('Error en el servicio AES-256-CBC:', err); // en caso de no lograrlo manda un error
    throw new Error('Error al cifrar el texto con AES-256-CBC');
  }
};

const aesDecryptService = (encryptedText, key, iv) => { // va a recibir un texto, una llave y el vector de inicializacion
  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
    let decrypted = decipher.update(encryptedText, 'base64', 'utf8'); // Convierte la clave y el iv desde base64 a buffer
    decrypted += decipher.final('utf8'); //de base64 convierte el texto a utf8
    return decrypted;  //devuelve el texto desencriptado
  } catch (err) {
    console.error('Error en el servicio AES-256-CBC:', err); //lanza error si el descifrado falla
    throw new Error('Error al descifrar el texto con AES-256-CBC');
  }
};

/**
 * Cifra un texto plano usando ChaCha20-Poly1305
 * @param {string} plainText 
 * @param {string|null} keyBase64 
 * @param {string|null} nonceBase64 
 * @returns {Object} 
 */

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { //genera un par de llaves public key y private key spki y pkcs8 de 2048 bits
  modulusLength: 2048, 
  publicKeyEncoding: {
    type: 'spki',     
    format: 'pem'     
  },
  privateKeyEncoding: {
    type: 'pkcs8',    
    format: 'pem'     
  }
});
console.log('Par de llaves RSA generadas (2048 bits)');

const { publicKey: dsaPublicKey, privateKey: dsaPrivateKey } =  //genera otro par de llaves para el dsa, una public y otra private con longitud de 1024 y un divisor de 224
  crypto.generateKeyPairSync('dsa', {
    modulusLength: 1024,  
    divisorLength: 224,   
    publicKeyEncoding: {
      type: 'spki',       
      format: 'pem'       
    },
    privateKeyEncoding: {
      type: 'pkcs8',      
      format: 'pem'       
    }
  });

console.log('Par de llaves DSA generadas (1024 bits, divisor 224 bits)');

function getDsaPublicKeyPem() { //da formato PEM a la dsa public key
  return dsaPublicKey;
}

/**
 * Firma un mensaje usando DSA con SHA-256
 * @param {string} message 
 * @returns {object} 
 * @throws {Error} 
 */

function signWithDsa(message) {
  if (!message || typeof message !== 'string') { //verifica que sea un string
    throw new Error('El mensaje a firmar debe ser un string no vacío');
  }

  const sign = crypto.createSign('sha256'); //crea un objeto de firma con sha256
  sign.update(message, 'utf8'); //mensaje a firmar
  sign.end();
  const signature = sign.sign(dsaPrivateKey); //firma el mensaje con la clave privada
  const signatureBase64 = signature.toString('base64'); //convierte a base 64

  return { // lo que devuelve el json
    algorithm: 'DSA-SHA256',
    keySize: 1024,
    signatureBase64,
    publicKeyPem: dsaPublicKey 
  };
}

/**
 * Verifica una firma DSA de un mensaje
 * @param {string} message 
 * @param {string} signatureBase64 
 * @returns {object} 
 * @throws {Error} 
 */
function verifyWithDsa(message, signatureBase64) {
  if (!message || typeof message !== 'string') { //verifica que la firma pertenezca a un mensaje original
    throw new Error('El mensaje debe ser un string no vacío');
  }

  if (!signatureBase64 || typeof signatureBase64 !== 'string') {
    throw new Error('La firma debe ser un string Base64 no vacío');
  }
  const signatureBuffer = Buffer.from(signatureBase64, 'base64'); //convierte la firma a un buffer binario
  const verify = crypto.createVerify('sha256'); //crea un objeto verificador con sha256
  verify.update(message, 'utf8');
  verify.end();
  const isValid = verify.verify(dsaPublicKey, signatureBuffer); //finaliza la preparacion

  return { //lo que devuelve el json
    algorithm: 'DSA-SHA256',
    keySize: 1024,
    isValid
  };
}

/**
 * Obtiene la llave pública en formato PEM
 * @returns {string} Llave pública PEM
 */
function getPublicKeyPem() {
  return publicKey;
}

/**
 * Cifra un texto plano usando RSA-OAEP con SHA-256
 * @param {string} plainText 
 * @returns {object} 
 * @throws {Error} 
 */
function rsaEncrypt(plainText) {
  if (!plainText || typeof plainText !== 'string') { //valida que sea un string
    throw new Error('El texto a cifrar debe ser un string no vacío');
  }

  const plainBuffer = Buffer.from(plainText, 'utf8'); //convierte el texto a utf8
  const cipherBuffer = crypto.publicEncrypt( //cifra usando la llave publica
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256' 
    },
    plainBuffer // envia el texto para cifrarlo
  );
  const cipherTextBase64 = cipherBuffer.toString('base64'); //convierte el resultado de binario a base 64

  return { //lo que devuelve el json
    cipherTextBase64,
    publicKeyPem: publicKey 
  };
}

/**
 * Descifra un texto cifrado usando RSA-OAEP con SHA-256
 * @param {string} cipherTextBase64 
 * @returns {object} 
 * @throws {Error} 
 */
function rsaDecrypt(cipherTextBase64) {
  if (!cipherTextBase64 || typeof cipherTextBase64 !== 'string') { //verifica que sea un cifrado y un string
    throw new Error('El texto cifrado debe ser un string Base64 no vacío');
  }
  const cipherBuffer = Buffer.from(cipherTextBase64, 'base64'); //decodifica de base64 a binario
  const plainBuffer = crypto.privateDecrypt( //usa la clave privada para descifrar el mensaje
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256' 
    },
    cipherBuffer //descifra el contenido y devuelve un buffer con el texto original
  );
  const plainText = plainBuffer.toString('utf8'); //convierte a utf8

  return { //devuelve el texto original
    plainText
  };
}

function encryptChaCha20(plainText, keyBase64, nonceBase64) { //usa ChaCha20-Poly1305
  try {
    let key;
    if (!keyBase64) {
      key = crypto.randomBytes(32); //genera una clave aleatoria de 32 bytes
    } else {
      key = Buffer.from(keyBase64, 'base64'); //convierte de base 64 a buffer binario 
      if (key.length !== 32) {
        throw new Error('La clave debe tener exactamente 32 bytes');
      }
    }
    let nonce;
    if (!nonceBase64) {
      nonce = crypto.randomBytes(12); //genera un nonce aleatorio de 12 bytes
    } else {
      nonce = Buffer.from(nonceBase64, 'base64');
      if (nonce.length !== 12) {
        throw new Error('El nonce debe tener exactamente 12 bytes');
      }
    }
    const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, { //crea el cifrador con MAC de 16 bytes
      authTagLength: 16
    });
    let cipherText = cipher.update(plainText, 'utf8'); //cifra en utf8
    cipherText = Buffer.concat([cipherText, cipher.final()]); //concatena el ultimo bloque cifrado
    const authTag = cipher.getAuthTag(); //genera un tag de autenticacion
    return { //lo que devuelve el json
      cipherTextBase64: cipherText.toString('base64'),
      keyBase64: key.toString('base64'),
      nonceBase64: nonce.toString('base64'),
      authTagBase64: authTag.toString('base64')
    };
  } catch (error) { //en caso de que no pueda cifrarlo
    throw new Error(`Error al cifrar: ${error.message}`);
  }
}

/**
 * Descifra un texto cifrado usando ChaCha20-Poly1305
 * @param {string} cipherTextBase64 
 * @param {string} keyBase64 
 * @param {string} nonceBase64 
 * @param {string} authTagBase64 
 * @returns {Object} 
 */
function decryptChaCha20(cipherTextBase64, keyBase64, nonceBase64, authTagBase64) { //necesita el tag, nonce, key y cipher text
  try {
    const cipherText = Buffer.from(cipherTextBase64, 'base64');
    const key = Buffer.from(keyBase64, 'base64');
    const nonce = Buffer.from(nonceBase64, 'base64');
    const authTag = Buffer.from(authTagBase64, 'base64'); //convierte todo de base64 a buffer
    if (key.length !== 32) {
      throw new Error('La clave debe tener exactamente 32 bytes'); //verifica las longitudes de la llave y nonce
    }
    if (nonce.length !== 12) {
      throw new Error('El nonce debe tener exactamente 12 bytes');
    }
    const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { //configura para descifrar con la clave y el nonce
      authTagLength: 16
    });
    decipher.setAuthTag(authTag); //asigna el auth tag del cifrado
    let plainText = decipher.update(cipherText); //descifra el buffer
    plainText = Buffer.concat([plainText, decipher.final()]);
    return { //devuelve el texto descifrado en utf8
      plainText: plainText.toString('utf8')
    };
  } catch (error) { //devuelve error si no pudo hacerlo
    throw new Error(`Error al descifrar: ${error.message}`);
  }
}

module.exports = {
  sha256HashService,
  argon2HashService,
  aesEncryptService,
  aesDecryptService,
  encryptChaCha20,
  decryptChaCha20,
  rsaEncrypt,
  rsaDecrypt,
  getPublicKeyPem,
  getDsaPublicKeyPem,
  signWithDsa,
  verifyWithDsa,
};



