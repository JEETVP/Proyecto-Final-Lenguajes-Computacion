const { 
  aesEncryptService, 
  aesDecryptService, 
  chacha20EncryptService, 
  chacha20DecryptService, 
  generateRsaKeyPair, 
  generateDsaKeyPair, 
  sha256HashService,
  argon2HashService 
} = require('../services/cryptoService');
const crypto = require('crypto');

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

// AES-256-CBC Encrypt
const aesEncrypt = (req, res) => {
  try {
    const { text } = req.body;  // Texto a cifrar

    // Generar clave de 32 bytes (256 bits) y IV de 16 bytes (128 bits)
    const key = crypto.randomBytes(32);  // 32 bytes para AES-256
    const iv = crypto.randomBytes(16);   // 16 bytes para el IV

    // Convertir la clave y el IV a Base64 para enviar en la respuesta y prueba en Postman
    const keyBase64 = key.toString('base64');
    const ivBase64 = iv.toString('base64');

    // Verificar la longitud de la clave e IV
    console.log('Generated Key:', keyBase64);
    console.log('Generated IV:', ivBase64);

    // Llamar al servicio para cifrar el texto
    const encryptedText = aesEncryptService(text, keyBase64, ivBase64);

    // Retornar el texto cifrado en Base64 y las claves en Base64 para pruebas
    res.json({
      encrypted: encryptedText,
      key: keyBase64,
      iv: ivBase64
    });
  } catch (err) {
    console.error('Error en el cifrado AES:', err);
    res.status(500).json({ error: 'Error al cifrar el texto con AES' });
  }
};

// AES-256-CBC Decrypt
const aesDecrypt = (req, res) => {
  try {
    const { encryptedText, key, iv } = req.body;

    // Agregar logs para verificar los datos recibidos
    console.log('encryptedText:', encryptedText);
    console.log('key:', key);
    console.log('iv:', iv);

    // Verificar que los parámetros existan
    if (!encryptedText || !key || !iv) {
      return res.status(400).json({ error: 'encryptedText, key, and iv are required' });
    }

    // Decodificar los parámetros Base64
    const keyBuffer = Buffer.from(key, 'base64');
    const ivBuffer = Buffer.from(iv, 'base64');

    // Verificar que la clave tenga 32 bytes (256 bits)
    if (keyBuffer.length !== 32) {
      return res.status(400).json({ error: 'La clave debe ser de 32 bytes (AES-256)' });
    }

    // Verificar que el IV tenga 16 bytes
    if (ivBuffer.length !== 16) {
      return res.status(400).json({ error: 'El IV debe ser de 16 bytes' });
    }

    // Verificar que el texto cifrado esté en Base64
    let encryptedBuffer;
    try {
      encryptedBuffer = Buffer.from(encryptedText, 'base64');
    } catch (error) {
      return res.status(400).json({ error: 'Texto cifrado no válido (debe estar en Base64)' });
    }

    // Llamar al servicio para descifrar el texto
    const decryptedText = aesDecryptService(encryptedBuffer, keyBuffer, ivBuffer);

    // Retornar el texto descifrado
    res.json({ decrypted: decryptedText });
  } catch (err) {
    console.error('Error en el descifrado AES:', err);
    res.status(500).json({ error: 'Error al descifrar el texto con AES' });
  }
};

// Endpoint para cifrar con clave pública
const encryptWithPublicKey = (req, res) => {
  const { publicKeyBase64, data } = req.body;
  try {
    const encryptedData = cryptoService.encryptWithPublicKey(publicKeyBase64, data);
    res.json({ encryptedData });
  } catch (error) {
    res.status(500).json({ error: 'Error al cifrar el dato' });
  }
};

// Endpoint para descifrar con clave privada
const decryptWithPrivateKey = (req, res) => {
  const { privateKeyBase64, encryptedDataBase64 } = req.body;
  try {
    const decryptedData = cryptoService.decryptWithPrivateKey(privateKeyBase64, encryptedDataBase64);
    res.json({ decryptedData });
  } catch (error) {
    res.status(500).json({ error: 'Error al descifrar el dato' });
  }
};

module.exports = {
  sha256Hash,
  argon2Hash,
  aesEncrypt,
  aesDecrypt,
  encryptWithPublicKey,
  decryptWithPrivateKey
};

