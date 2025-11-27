const express = require('express');
const router = express.Router();
const { 
  sha256Hash, 
  argon2Hash, 
  aesEncrypt, 
  aesDecrypt, 
  chacha20Encrypt, 
  chacha20Decrypt, 
  generateRsaKey,  
  generateDsaKey 
} = require('../controllers/cryptoController');

// Endpoints de Criptografía

// Rutas de SHA-256
router.post('/hash/sha256', sha256Hash);  // Generar hash con SHA-256

// Rutas de Argon2
router.post('/hash/argon2', argon2Hash);  // Generar hash con Argon2

// Rutas para AES-256-CBC
router.post('/encrypt/aes_cbc', aesEncrypt);  // Cifrar con AES
router.post('/decrypt/aes_cbc', aesDecrypt);  // Descifrar con AES

// Rutas para ChaCha20
router.post('/encrypt/chacha20', chacha20Encrypt);  // Cifrar con ChaCha20
router.post('/decrypt/chacha20', chacha20Decrypt);  // Descifrar con ChaCha20

// Rutas para generar claves RSA/DSA
router.post('/generate/rsa', generateRsaKey);  // Generar clave RSA
router.post('/generate/dsa', generateDsaKey);  // Generar clave DSA

module.exports = router;


/*router.post('/encrypt/rsa', rsaEncrypt);
router.post('/decrypt/rsa', rsaDecrypt);
router.post('/sign/dsa', signDsa);
router.post('/verify/dsa', verifyDsa);*/


