const express = require('express');
const router = express.Router();
const cryptoController = require('../controllers/cryptoController');  // Asegúrate de que esta importación sea correcta

// Endpoints de Criptografía

router.post('/hash/sha256', cryptoController.sha256Hash);  // Generar hash con SHA-256
router.post('/hash/argon2', cryptoController.argon2Hash);  // Generar hash con Argon2
router.post('/encrypt/aes_cbc', cryptoController.aesEncrypt);  // Cifrar con AES
router.post('/decrypt/aes_cbc', cryptoController.aesDecrypt);  // Descifrar con AES
router.post('/api/encrypt/chacha20', cryptoController.chacha20Encrypt);
router.post('/api/decrypt/chacha20', cryptoController.chacha20Decrypt);
router.post('/api/encrypt/rsa', cryptoController.encryptRSA);
router.post('/api/decrypt/rsa', cryptoController.decryptRSA);
router.post('/api/sign/dsa', cryptoController.signDsa);
router.post('/api/verify/dsa', cryptoController.verifyDsa);

module.exports = router;





