const express = require('express');
const router = express.Router();
const cryptoController = require('../controllers/cryptoController');  

// Endpoints 
router.post('/hash/sha256', cryptoController.sha256Hash); 
router.post('/hash/argon2', cryptoController.argon2Hash);  
router.post('/encrypt/aes_cbc', cryptoController.aesEncrypt);  
router.post('/decrypt/aes_cbc', cryptoController.aesDecrypt);  
router.post('/encrypt/chacha20', cryptoController.chacha20Encrypt);
router.post('/decrypt/chacha20', cryptoController.chacha20Decrypt);
router.post('/encrypt/rsa', cryptoController.encryptRSA);
router.post('/decrypt/rsa', cryptoController.decryptRSA);
router.post('/sign/dsa', cryptoController.signDsa);
router.post('/verify/dsa', cryptoController.verifyDsa);

module.exports = router;





