const crypto = require('crypto');
const argon2 = require('argon2');

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
  try {
    // Crear el cifrador con la clave y el IV
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));

    // Cifrar el texto
    let encrypted = cipher.update(text, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    return encrypted;  // Retorna el texto cifrado en Base64
  } catch (err) {
    console.error('Error en el servicio AES-256-CBC:', err);
    throw new Error('Error al cifrar el texto con AES-256-CBC');
  }
};

// AES-256-CBC Decrypt
const aesDecryptService = (encryptedText, key, iv) => {
  try {
    // Crear el descifrador con la clave y el IV
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));

    // Descifrar el texto
    let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;  // Retorna el texto descifrado en UTF-8
  } catch (err) {
    console.error('Error en el servicio AES-256-CBC:', err);
    throw new Error('Error al descifrar el texto con AES-256-CBC');
  }
};


module.exports = {
  sha256HashService,
  argon2HashService,
  aesEncryptService,
  aesDecryptService,
};


