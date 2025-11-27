const crypto = require('crypto');
const argon2 = require('argon2');
const chacha = require('chacha');
const { publicEncrypt, privateDecrypt, generateKeyPairSync, createSign, createVerify } = require('crypto');

// SHA-256 Hash
const sha256HashService = (text) => {
  try {
    // Generar hash SHA-256 del texto
    const hash = crypto.createHash('sha256').update(text).digest('hex');
    return hash;
  } catch (err) {
    console.error('Error en el servicio SHA-256:', err);
    throw new Error('Error al generar el hash SHA-256');
  }
};

// Argon2 Hash
const argon2HashService = async (password) => {
  try {
    // Generar hash usando Argon2
    const hash = await argon2.hash(password);
    return hash;
  } catch (err) {
    console.error('Error en el servicio Argon2:', err);
    throw new Error('Error al generar el hash Argon2');
  }
};


// AES-256-CBC Encrypt
const aesEncryptService = (text, key, iv) => {
  // Crear el cifrador con la clave y el IV
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));

  // Cifrar el texto
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  return encrypted;  // Retorna el texto cifrado en Base64
};

// AES-256-CBC Decrypt
const aesDecryptService = (encryptedText, key, iv) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

  // Descifrar el texto
  let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;  // Retorna el texto descifrado en UTF-8
};

// Generar claves RSA de 2048 bits
const generateRSAKeyPair = () => {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });
};

// Cifrar con clave pública usando RSA-OAEP
const encryptWithPublicKey = (publicKeyBase64, data) => {
  const publicKey = Buffer.from(publicKeyBase64, 'base64');
  const encryptedData = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    },
    Buffer.from(data)
  );
  return encryptedData.toString('base64');
};

// Descifrar con clave privada usando RSA-OAEP
const decryptWithPrivateKey = (privateKeyBase64, encryptedDataBase64) => {
  const privateKey = Buffer.from(privateKeyBase64, 'base64');
  const encryptedData = Buffer.from(encryptedDataBase64, 'base64');
  const decryptedData = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    },
    encryptedData
  );
  return decryptedData.toString();
};

module.exports = {
  sha256HashService,
  argon2HashService,
  aesEncryptService,
  aesDecryptService,
  generateRSAKeyPair,
  encryptWithPublicKey,
  decryptWithPrivateKey,
};
