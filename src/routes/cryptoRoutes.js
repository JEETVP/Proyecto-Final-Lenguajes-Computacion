const express = require('express');
const router = express.Router();
const cryptoController = require('../controllers/cryptoController');  // Asegúrate de que esta importación sea correcta

// Endpoints de Criptografía

// Rutas de SHA-256
router.post('/hash/sha256', cryptoController.sha256Hash);  // Generar hash con SHA-256
// Rutas de Argon2
router.post('/hash/argon2', cryptoController.argon2Hash);  // Generar hash con Argon2
// Rutas para AES-256-CBC
router.post('/encrypt/aes_cbc', cryptoController.aesEncrypt);  // Cifrar con AES
router.post('/decrypt/aes_cbc', cryptoController.aesDecrypt);  // Descifrar con AES

module.exports = router;





