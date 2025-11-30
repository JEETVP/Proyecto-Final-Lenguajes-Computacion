const crypto = require('crypto');
const argon2 = require('argon2');


const sha256HashService = (text) => {
  try {
    const hash = crypto.createHash('sha256').update(text).digest('hex');
    return hash;
  } catch (err) {
    console.error('Error en el servicio SHA-256:', err);
    throw new Error('Error al generar el hash SHA-256');
  }
};

const argon2HashService = async (password) => {
  try {
    const hash = await argon2.hash(password);
    return hash;
  } catch (err) {
    console.error('Error en el servicio Argon2:', err);
    throw new Error('Error al generar el hash Argon2');
  }
};

const aesEncryptService = (text, key, iv) => {
  try {
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
    let encrypted = cipher.update(text, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;  
  } catch (err) {
    console.error('Error en el servicio AES-256-CBC:', err);
    throw new Error('Error al cifrar el texto con AES-256-CBC');
  }
};

const aesDecryptService = (encryptedText, key, iv) => {
  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
    let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;  
  } catch (err) {
    console.error('Error en el servicio AES-256-CBC:', err);
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

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
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

const { publicKey: dsaPublicKey, privateKey: dsaPrivateKey } = 
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

function getDsaPublicKeyPem() {
  return dsaPublicKey;
}

/**
 * Firma un mensaje usando DSA con SHA-256
 * @param {string} message 
 * @returns {object} 
 * @throws {Error} 
 */
function signWithDsa(message) {
  if (!message || typeof message !== 'string') {
    throw new Error('El mensaje a firmar debe ser un string no vacío');
  }

  const sign = crypto.createSign('sha256');
  sign.update(message, 'utf8');
  sign.end();
  const signature = sign.sign(dsaPrivateKey);
  const signatureBase64 = signature.toString('base64');

  return {
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
  if (!message || typeof message !== 'string') {
    throw new Error('El mensaje debe ser un string no vacío');
  }

  if (!signatureBase64 || typeof signatureBase64 !== 'string') {
    throw new Error('La firma debe ser un string Base64 no vacío');
  }
  const signatureBuffer = Buffer.from(signatureBase64, 'base64');
  const verify = crypto.createVerify('sha256');
  verify.update(message, 'utf8');
  verify.end();
  const isValid = verify.verify(dsaPublicKey, signatureBuffer);

  return {
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
  if (!plainText || typeof plainText !== 'string') {
    throw new Error('El texto a cifrar debe ser un string no vacío');
  }

  const plainBuffer = Buffer.from(plainText, 'utf8');
  const cipherBuffer = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256' 
    },
    plainBuffer
  );
  const cipherTextBase64 = cipherBuffer.toString('base64');

  return {
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
  if (!cipherTextBase64 || typeof cipherTextBase64 !== 'string') {
    throw new Error('El texto cifrado debe ser un string Base64 no vacío');
  }
  const cipherBuffer = Buffer.from(cipherTextBase64, 'base64');
  const plainBuffer = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256' 
    },
    cipherBuffer
  );
  const plainText = plainBuffer.toString('utf8');

  return {
    plainText
  };
}

function encryptChaCha20(plainText, keyBase64, nonceBase64) {
  try {
    let key;
    if (!keyBase64) {
      key = crypto.randomBytes(32);
    } else {
      key = Buffer.from(keyBase64, 'base64');
      if (key.length !== 32) {
        throw new Error('La clave debe tener exactamente 32 bytes');
      }
    }
    let nonce;
    if (!nonceBase64) {
      nonce = crypto.randomBytes(12);
    } else {
      nonce = Buffer.from(nonceBase64, 'base64');
      if (nonce.length !== 12) {
        throw new Error('El nonce debe tener exactamente 12 bytes');
      }
    }
    const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, {
      authTagLength: 16
    });
    let cipherText = cipher.update(plainText, 'utf8');
    cipherText = Buffer.concat([cipherText, cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
      cipherTextBase64: cipherText.toString('base64'),
      keyBase64: key.toString('base64'),
      nonceBase64: nonce.toString('base64'),
      authTagBase64: authTag.toString('base64')
    };
  } catch (error) {
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
function decryptChaCha20(cipherTextBase64, keyBase64, nonceBase64, authTagBase64) {
  try {
    const cipherText = Buffer.from(cipherTextBase64, 'base64');
    const key = Buffer.from(keyBase64, 'base64');
    const nonce = Buffer.from(nonceBase64, 'base64');
    const authTag = Buffer.from(authTagBase64, 'base64');
    if (key.length !== 32) {
      throw new Error('La clave debe tener exactamente 32 bytes');
    }
    if (nonce.length !== 12) {
      throw new Error('El nonce debe tener exactamente 12 bytes');
    }
    const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, {
      authTagLength: 16
    });
    decipher.setAuthTag(authTag);
    let plainText = decipher.update(cipherText);
    plainText = Buffer.concat([plainText, decipher.final()]);
    return {
      plainText: plainText.toString('utf8')
    };
  } catch (error) {
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



