const express = require('express');
const router = express.Router();
const cryptoController = require('../controllers/cryptoController');

// Endpoints de Criptografía

// Rutas de SHA-256
router.post('/hash/sha256', sha256Hash);  // Generar hash con SHA-256
// Rutas de Argon2
router.post('/hash/argon2', argon2Hash);  // Generar hash con Argon2
// Rutas para AES-256-CBC
router.post('/encrypt/aes_cbc', aesEncrypt);  // Cifrar con AES
router.post('/decrypt/aes_cbc', aesDecrypt);  // Descifrar con AES

// Endpoint para cifrar con clave pública (RSA)
router.post('/api/encrypt/rsa', cryptoController.encryptWithPublicKey);
// Endpoint para descifrar con clave privada (RSA)
router.post('/api/decrypt/rsa', cryptoController.decryptWithPrivateKey);

module.exports = router;


/*router.post('/encrypt/rsa', rsaEncrypt);
router.post('/decrypt/rsa', rsaDecrypt);
router.post('/sign/dsa', signDsa);
router.post('/verify/dsa', verifyDsa);*/


