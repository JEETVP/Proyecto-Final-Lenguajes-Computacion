const { sha256HashService, argon2HashService, aesEncryptService, aesDecryptService, chacha20EncryptService, chacha20DecryptService, rsaEncryptService, rsaDecryptService, signDsaService, verifyDsaService } = require('../services/cryptoService');

// SHA-256 Hash
const sha256Hash = (req, res) => {
  try {
    const text = req.body.text;  // Texto a ser hasheado
    if (!text) {
      return res.status(400).json({ error: 'El texto es requerido' });
    }
    // Llamar al servicio para generar el hash SHA-256
    const hash = sha256HashService(text);
    res.json({ hash });
  } catch (err) {
    console.error('Error al generar el hash SHA-256:', err);
    res.status(500).json({ error: 'Error al generar el hash SHA-256' });
  }
};

// Argon2 Hash
const argon2Hash = async (req, res) => {
  try {
    const password = req.body.password;  // Contraseña a ser hasheada
    if (!password) {
      return res.status(400).json({ error: 'La contraseña es requerida' });
    }
    // Llamar al servicio para generar el hash Argon2
    const hash = await argon2HashService(password);
    res.json({ hash });
  } catch (err) {
    console.error('Error al generar el hash con Argon2:', err);
    res.status(500).json({ error: 'Error al generar el hash con Argon2' });
  }
};

// Endpoint AES-256-CBC (Cifrar texto)
const aesEncrypt = (req, res) => {
    const { text, key, iv } = req.body;
    const encryptedText = aesEncryptService(text, key, iv); // Llama al servicio
    res.json({ encrypted: encryptedText });
};

// Endpoint AES-256-CBC (Descifrar texto)
const aesDecrypt = (req, res) => {
    const { encryptedText, key, iv } = req.body;
    const decryptedText = aesDecryptService(encryptedText, key, iv); // Llama al servicio
    res.json({ decrypted: decryptedText });
};

// Endpoint ChaCha20 (Cifrar texto)
const chacha20Encrypt = (req, res) => {
    const { text, key, nonce } = req.body;
    const encryptedText = chacha20EncryptService(text, key, nonce); // Llama al servicio
    res.json({ encrypted: encryptedText });
};

// Endpoint ChaCha20 (Descifrar texto)
const chacha20Decrypt = (req, res) => {
    const { encryptedText, key, nonce } = req.body;
    const decryptedText = chacha20DecryptService(encryptedText, key, nonce); // Llama al servicio
    res.json({ decrypted: decryptedText });
};

// Endpoint RSA-OAEP (Cifrar con clave pública)
const rsaEncrypt = (req, res) => {
    const { text, publicKey } = req.body;
    const encryptedText = rsaEncryptService(text, publicKey); // Llama al servicio
    res.json({ encrypted: encryptedText });
};

// Endpoint RSA-OAEP (Descifrar con clave privada)
const rsaDecrypt = (req, res) => {
    const { encryptedText, privateKey } = req.body;
    const decryptedText = rsaDecryptService(encryptedText, privateKey); // Llama al servicio
    res.json({ decrypted: decryptedText });
};

// Endpoint DSA (Firmar mensaje con clave privada)
const signDsa = (req, res) => {
    const { message, privateKey } = req.body;
    const signature = signDsaService(message, privateKey); // Llama al servicio
    res.json({ signature });
};

// Endpoint DSA (Verificar firma con clave pública)
const verifyDsa = (req, res) => {
    const { message, signature, publicKey } = req.body;
    const isValid = verifyDsaService(message, signature, publicKey); // Llama al servicio
    res.json({ isValid });
};

module.exports = { sha256Hash, argon2Hash, aesEncrypt, aesDecrypt, chacha20Encrypt, chacha20Decrypt, rsaEncrypt, rsaDecrypt, signDsa, verifyDsa };
