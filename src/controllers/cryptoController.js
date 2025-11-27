const { sha256HashService, argon2HashService, aesEncryptService, aesDecryptService, chacha20EncryptService, chacha20DecryptService, rsaEncryptService, rsaDecryptService, signDsaService, verifyDsaService } = require('../services/cryptoService');

// Endpoint SHA-256 (Generar un hash del texto de entrada)
const sha256Hash = (req, res) => {
    const text = req.body.text;
    const hash = sha256HashService(text); // Llama al servicio
    res.json({ hash });
};

// Endpoint Argon2 (Generar un hash de la contraseña)
const argon2Hash = (req, res) => {
    const password = req.body.password;
    const hash = argon2HashService(password); // Llama al servicio
    res.json({ hash });
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
