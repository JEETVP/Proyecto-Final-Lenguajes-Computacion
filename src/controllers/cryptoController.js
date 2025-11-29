const {  
  sha256HashService, 
  argon2HashService, 
  aesEncryptService, 
  aesDecryptService, 
} = require('../services/cryptoService');
const chacha20Service = require('../services/cryptoService');
const { rsaEncrypt, rsaDecrypt, getPublicKeyPem } = require('../services/cryptoService');
const { getDsaPublicKeyPem, signWithDsa, verifyWithDsa } = require('../services/cryptoService');

const crypto = require('crypto');

// Generar un par de claves RSA automáticamente
const generateRSAKeyPairSync = () => {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
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
    return {
      publicKey: publicKey.toString('base64'),  // Codificada en base64 para el envío en JSON
      privateKey: privateKey.toString('base64')  // Codificada en base64
    };
  } catch (err) {
    console.error('Error generando claves RSA:', err);
    throw new Error('Error al generar las claves RSA');
  }
};

// Claves RSA generadas y codificadas en base64
const { publicKeyBase64, privateKeyBase64 } = generateRSAKeyPairSync();

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

exports.chacha20Encrypt = async (req, res) => {
  try {
    // Extraer datos del body
    const { text, keyBase64, nonceBase64 } = req.body;

    // Validar que el campo text sea obligatorio
    if (!text) {
      return res.status(400).json({
        error: 'El campo text es obligatorio'
      });
    }

    // Validar que text sea un string
    if (typeof text !== 'string') {
      return res.status(400).json({
        error: 'El campo text debe ser una cadena de texto'
      });
    }

    // Llamar al servicio de cifrado
    const result = chacha20Service.encryptChaCha20(
      text,
      keyBase64 || null,
      nonceBase64 || null
    );

    // Responder con los datos cifrados
    return res.status(200).json({
      algorithm: 'chacha20-poly1305',
      cipherTextBase64: result.cipherTextBase64,
      keyBase64: result.keyBase64,
      nonceBase64: result.nonceBase64,
      authTagBase64: result.authTagBase64
    });

  } catch (error) {
    // Log del error para debugging
    console.error('Error en chacha20Encrypt:', error);

    // Determinar si es error de validación o error interno
    const isValidationError = error.message.includes('debe tener') || 
                              error.message.includes('exactamente');

    return res.status(isValidationError ? 400 : 500).json({
      error: error.message
    });
  }
};

exports.chacha20Decrypt = async (req, res) => {
  try {
    // Extraer datos del body
    const { cipherTextBase64, keyBase64, nonceBase64, authTagBase64 } = req.body;

    // Validar que todos los campos requeridos estén presentes
    const missingFields = [];
    if (!cipherTextBase64) missingFields.push('cipherTextBase64');
    if (!keyBase64) missingFields.push('keyBase64');
    if (!nonceBase64) missingFields.push('nonceBase64');
    if (!authTagBase64) missingFields.push('authTagBase64');

    if (missingFields.length > 0) {
      return res.status(400).json({
        error: `Faltan los siguientes campos obligatorios: ${missingFields.join(', ')}`
      });
    }

    // Validar que todos los campos sean strings
    if (typeof cipherTextBase64 !== 'string' || 
        typeof keyBase64 !== 'string' || 
        typeof nonceBase64 !== 'string' || 
        typeof authTagBase64 !== 'string') {
      return res.status(400).json({
        error: 'Todos los campos deben ser cadenas de texto en Base64'
      });
    }

    // Llamar al servicio de descifrado
    const result = chacha20Service.decryptChaCha20(
      cipherTextBase64,
      keyBase64,
      nonceBase64,
      authTagBase64
    );

    // Responder con el texto descifrado
    return res.status(200).json({
      algorithm: 'chacha20-poly1305',
      plainText: result.plainText
    });

  } catch (error) {
    // Log del error para debugging
    console.error('Error en chacha20Decrypt:', error);

    // Determinar si es error de validación o error interno
    const isValidationError = error.message.includes('debe tener') || 
                              error.message.includes('exactamente') ||
                              error.message.includes('Unsupported state');

    return res.status(isValidationError ? 400 : 500).json({
      error: error.message
    });
  }
};

exports.encryptRSA = async (req, res) => {
  try {
    const { text } = req.body;

    // Validación: el campo text es obligatorio
    if (!text || text.trim() === '') {
      return res.status(400).json({
        error: 'El campo text es obligatorio'
      });
    }

    // Llamar al servicio de cifrado
    const result = rsaEncrypt(text);

    // Responder con el texto cifrado y metadatos
    return res.status(200).json({
      algorithm: 'RSA-OAEP',
      modulusLength: 2048,
      cipherTextBase64: result.cipherTextBase64,
      publicKeyPem: result.publicKeyPem
    });

  } catch (err) {
    console.error('Error al cifrar con RSA-OAEP:', err);
    return res.status(500).json({
      error: 'Error al cifrar con RSA-OAEP'
    });
  }
};


exports.decryptRSA = async (req, res) => {
  try {
    const { cipherTextBase64 } = req.body;

    // Validación: el campo cipherTextBase64 es obligatorio
    if (!cipherTextBase64 || cipherTextBase64.trim() === '') {
      return res.status(400).json({
        error: 'El campo cipherTextBase64 es obligatorio'
      });
    }

    // Llamar al servicio de descifrado
    const result = rsaDecrypt(cipherTextBase64);

    // Responder con el texto descifrado
    return res.status(200).json({
      algorithm: 'RSA-OAEP',
      plainText: result.plainText
    });

  } catch (err) {
    console.error('Error al descifrar con RSA-OAEP:', err);
    return res.status(500).json({
      error: 'Error al descifrar con RSA-OAEP'
    });
  }
};

exports.signDsa = async (req, res) => {
  try {
    const { message } = req.body;

    // Validación: el campo message es obligatorio
    if (!message || message.trim() === '') {
      return res.status(400).json({
        error: 'El campo message es obligatorio'
      });
    }

    // Llamar al servicio de firma
    const result = signWithDsa(message);

    // Responder con la firma y metadatos
    return res.status(200).json({
      algorithm: result.algorithm,
      keySize: result.keySize,
      message: message,
      signatureBase64: result.signatureBase64,
      publicKeyPem: result.publicKeyPem
    });

  } catch (err) {
    console.error('Error al firmar con DSA:', err);
    return res.status(500).json({
      error: 'Error al firmar con DSA'
    });
  }
};

exports.verifyDsa = async (req, res) => {
  try {
    const { message, signatureBase64 } = req.body;

    // Validación: ambos campos son obligatorios
    if (!message || message.trim() === '') {
      return res.status(400).json({
        error: 'El campo message es obligatorio'
      });
    }

    if (!signatureBase64 || signatureBase64.trim() === '') {
      return res.status(400).json({
        error: 'El campo signatureBase64 es obligatorio'
      });
    }

    // Llamar al servicio de verificación
    const result = verifyWithDsa(message, signatureBase64);

    // Responder con el resultado de la verificación
    return res.status(200).json({
      algorithm: result.algorithm,
      keySize: result.keySize,
      message: message,
      signatureBase64: signatureBase64,
      isValid: result.isValid
    });

  } catch (err) {
    console.error('Error al verificar firma DSA:', err);
    return res.status(500).json({
      error: 'Error al verificar con DSA'
    });
  }
};

module.exports = {
  sha256Hash,
  argon2Hash,
  aesEncrypt,
  aesDecrypt,
  chacha20Encrypt: exports.chacha20Encrypt,
  chacha20Decrypt: exports.chacha20Decrypt,
  encryptRSA: exports.encryptRSA,
  decryptRSA: exports.decryptRSA,
  signDsa: exports.signDsa,
  verifyDsa: exports.verifyDsa,
};

