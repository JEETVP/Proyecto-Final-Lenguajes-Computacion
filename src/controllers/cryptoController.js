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

const generateRSAKeyPairSync = () => { //generacion de llaves RSA de manera sincrona
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { //genera con el modulo crypto tipo rsa con longitud de 2048 bits
      modulusLength: 2048,
      publicKeyEncoding: { //configuracion de la llave publica
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: { // configuracion de la llave privada
        type: 'pkcs8',
        format: 'pem',
      },
    });
    return {
      publicKey: publicKey.toString('base64'),  //regresa con dos propiedades en base64
      privateKey: privateKey.toString('base64')  
    };
  } catch (err) {
    console.error('Error generando claves RSA:', err); // manda error si no las pudo generar
    throw new Error('Error al generar las claves RSA');
  }
};

const { publicKeyBase64, privateKeyBase64 } = generateRSAKeyPairSync(); 

const sha256Hash = (req, res) => {
  try {
    const text = req.body.text;  //Extrae el texto enviado del cliente
    if (!text) {
      return res.status(400).json({ error: 'El texto es requerido' });
    }
    const hash = sha256HashService(text); //llama al servicio para generar el hash con el texto
    res.json({ hash });
  } catch (err) {
    console.error('Error al generar el hash SHA-256:', err); // si no puede manda error
    res.status(500).json({ error: 'Error al generar el hash SHA-256' });
  }
};

const argon2Hash = async (req, res) => {
  try {
    const password = req.body.password;  //extrae la contraseña enviada por el usuario
    if (!password) {
      return res.status(400).json({ error: 'La contraseña es requerida' });  //valida que exista la contraseña
    }
    const hash = await argon2HashService(password); // llama al servicio para hacer el hash con el password
    res.json({ hash });
  } catch (err) {
    console.error('Error al generar el hash con Argon2:', err); //si no puede marca error
    res.status(500).json({ error: 'Error al generar el hash con Argon2' });
  }
};

const aesEncrypt = (req, res) => {
  try {
    const { text } = req.body;  //extrae el texto que necesita
    const key = crypto.randomBytes(32);  
    const iv = crypto.randomBytes(16);   //genera la clave y el iv aleatorio de 16 y 32 bytes
    const keyBase64 = key.toString('base64');
    const ivBase64 = iv.toString('base64'); //codifica en base 64 para enviarlo
    console.log('Generated Key:', keyBase64);
    console.log('Generated IV:', ivBase64);
    const encryptedText = aesEncryptService(text, keyBase64, ivBase64); // llama al servicio pasandole el texto, la llave y el iv
    res.json({ //devuelve esto el json
      encrypted: encryptedText,
      key: keyBase64,
      iv: ivBase64
    });
  } catch (err) { // manda error si no puede
    console.error('Error en el cifrado AES:', err);
    res.status(500).json({ error: 'Error al cifrar el texto con AES' });
  }
};

const aesDecrypt = (req, res) => {
  try {
    const { encryptedText, key, iv } = req.body; // lo que necesita extraer para funcionar 
    console.log('encryptedText:', encryptedText);
    console.log('key:', key);
    console.log('iv:', iv);
    if (!encryptedText || !key || !iv) {
      return res.status(400).json({ error: 'encryptedText, key, and iv are required' }); //verifica que tenga los datos
    }
    const keyBuffer = Buffer.from(key, 'base64'); //convierte de base64 a buffers reales
    const ivBuffer = Buffer.from(iv, 'base64');
    if (keyBuffer.length !== 32) {
      return res.status(400).json({ error: 'La clave debe ser de 32 bytes (AES-256)' });
    }
    if (ivBuffer.length !== 16) {
      return res.status(400).json({ error: 'El IV debe ser de 16 bytes' });
    }
    let encryptedBuffer; //convierte desde base64 a buffer
    try {
      encryptedBuffer = Buffer.from(encryptedText, 'base64');
    } catch (error) {
      return res.status(400).json({ error: 'Texto cifrado no válido (debe estar en Base64)' });
    }
    const decryptedText = aesDecryptService(encryptedBuffer, keyBuffer, ivBuffer); //lama al servicio que hace el descifrado
    res.json({ decrypted: decryptedText }); // lo que devuelve el json
  } catch (err) {
    console.error('Error en el descifrado AES:', err); // si no puede manda error
    res.status(500).json({ error: 'Error al descifrar el texto con AES' });
  }
};

exports.chacha20Encrypt = async (req, res) => {
  try {
    const { text, keyBase64, nonceBase64 } = req.body; //extrae lo que necesita del body
    if (!text) {
      return res.status(400).json({
        error: 'El campo text es obligatorio'
      });
    }
    if (typeof text !== 'string') {
      return res.status(400).json({
        error: 'El campo text debe ser una cadena de texto' //verifica que sea texto y una cadena
      });
    }
    const result = chacha20Service.encryptChaCha20( // manda a llamar al servicio si no tiene key o nonce, asigna uno aleatori
      text,
      keyBase64 || null,
      nonceBase64 || null
    );
    return res.status(200).json({ // lo que devuelve el json
      algorithm: 'chacha20-poly1305',
      cipherTextBase64: result.cipherTextBase64,
      keyBase64: result.keyBase64,
      nonceBase64: result.nonceBase64,
      authTagBase64: result.authTagBase64
    });

  } catch (error) { //detecta si el error es por validacion
    console.error('Error en chacha20Encrypt:', error);
    const isValidationError = error.message.includes('debe tener') || 
                              error.message.includes('exactamente');

    return res.status(isValidationError ? 400 : 500).json({
      error: error.message
    });
  }
};

exports.chacha20Decrypt = async (req, res) => { 
  try {
    const { cipherTextBase64, keyBase64, nonceBase64, authTagBase64 } = req.body; //extrae los campos que necesita para descifrar
    const missingFields = [];
    if (!cipherTextBase64) missingFields.push('cipherTextBase64');
    if (!keyBase64) missingFields.push('keyBase64');
    if (!nonceBase64) missingFields.push('nonceBase64');
    if (!authTagBase64) missingFields.push('authTagBase64');

    if (missingFields.length > 0) {
      return res.status(400).json({
        error: `Faltan los siguientes campos obligatorios: ${missingFields.join(', ')}` //verifica que esten todos los campos
      });
    }
    if (typeof cipherTextBase64 !== 'string' || 
        typeof keyBase64 !== 'string' || 
        typeof nonceBase64 !== 'string' || 
        typeof authTagBase64 !== 'string') {
      return res.status(400).json({
        error: 'Todos los campos deben ser cadenas de texto en Base64' //verifica que sean cadenas en base 64
      });
    }
    const result = chacha20Service.decryptChaCha20( // llama al servicio pasandole los parametros
      cipherTextBase64,
      keyBase64,
      nonceBase64,
      authTagBase64
    );
    return res.status(200).json({ // lo que devuelve el json
      algorithm: 'chacha20-poly1305',
      plainText: result.plainText
    });

  } catch (error) {
    console.error('Error en chacha20Decrypt:', error); //errores de validacion y autenticacion
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
    const { text } = req.body; //extrae lo que necesita del body el texto unicamente
    if (!text || text.trim() === '') {
      return res.status(400).json({
        error: 'El campo text es obligatorio'
      });
    }
    const result = rsaEncrypt(text); // llama al servicio y le pasa el texto
    return res.status(200).json({ // respuesta del json
      algorithm: 'RSA-OAEP',
      modulusLength: 2048,
      cipherTextBase64: result.cipherTextBase64,
      publicKeyPem: result.publicKeyPem
    });

  } catch (err) { // en caso de que no pueda marca error
    console.error('Error al cifrar con RSA-OAEP:', err);
    return res.status(500).json({
      error: 'Error al cifrar con RSA-OAEP'
    });
  }
};

exports.decryptRSA = async (req, res) => {  
  try {
    const { cipherTextBase64 } = req.body; //extrae el mensaje y la ciphertextbase 64
    if (!cipherTextBase64 || cipherTextBase64.trim() === '') {
      return res.status(400).json({
        error: 'El campo cipherTextBase64 es obligatorio' // verifica que tenga todo
      });
    }
    const result = rsaDecrypt(cipherTextBase64); //lama al servicio y le pasa el ciphertextbase
    return res.status(200).json({ //devuelve el json
      algorithm: 'RSA-OAEP',
      plainText: result.plainText
    });

  } catch (err) { // marca error en caso de que no pueda realizarlo
    console.error('Error al descifrar con RSA-OAEP:', err);
    return res.status(500).json({
      error: 'Error al descifrar con RSA-OAEP'
    });
  }
};

exports.signDsa = async (req, res) => {
  try {
    const { message } = req.body; //verifica que tenga el mensaje
    if (!message || message.trim() === '') {
      return res.status(400).json({
        error: 'El campo message es obligatorio'
      });
    }
    const result = signWithDsa(message); //llama al servicio y le pasa el mensaje
    return res.status(200).json({ // lo que devuelve el json
      algorithm: result.algorithm,
      keySize: result.keySize,
      message: message,
      signatureBase64: result.signatureBase64,
      publicKeyPem: result.publicKeyPem
    });

  } catch (err) { // manda error en caso de que no pueda
    console.error('Error al firmar con DSA:', err);
    return res.status(500).json({
      error: 'Error al firmar con DSA'
    });
  }
};

exports.verifyDsa = async (req, res) => {
  try {
    const { message, signatureBase64 } = req.body; //extrae del body el message y signaturebase64
    if (!message || message.trim() === '') {
      return res.status(400).json({
        error: 'El campo message es obligatorio'
      }); // si el message no esta mando error
    }

    if (!signatureBase64 || signatureBase64.trim() === '') {
      return res.status(400).json({
        error: 'El campo signatureBase64 es obligatorio' 
      });
    }

    const result = verifyWithDsa(message, signatureBase64); //manda a llamar el servicio y manda mensaje y signaturebase64
    return res.status(200).json({ // lo que devuelve el json
      algorithm: result.algorithm,
      keySize: result.keySize,
      message: message,
      signatureBase64: signatureBase64,
      isValid: result.isValid
    });

  } catch (err) { //si no puede hacerlo marca un error
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

