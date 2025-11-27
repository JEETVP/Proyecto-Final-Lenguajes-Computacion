const express = require('express');
const router = express.Router();
const { sha256Hash, argon2Hash, aesEncrypt, aesDecrypt, chacha20Encrypt, chacha20Decrypt, rsaEncrypt, rsaDecrypt, signDsa, verifyDsa } = require('../controllers/cryptoController');

// Endpoints de Criptografía

// Rutas de SHA-256
router.post('/hash/sha256', sha256Hash);  // Generar hash con SHA-256

// Rutas de Argon2
router.post('/hash/argon2', argon2Hash);  // Generar hash con Argon2
router.post('/encrypt/aes_cbc', aesEncrypt);
router.post('/decrypt/aes_cbc', aesDecrypt);
router.post('/encrypt/chacha20', chacha20Encrypt);
router.post('/decrypt/chacha20', chacha20Decrypt);
router.post('/encrypt/rsa', rsaEncrypt);
router.post('/decrypt/rsa', rsaDecrypt);
router.post('/sign/dsa', signDsa);
router.post('/verify/dsa', verifyDsa);

module.exports = router;
