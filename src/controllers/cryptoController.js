const {
  aesEncrypt,
  aesDecrypt,
  chacha20Encrypt,
  chacha20Decrypt,
  generateRsaKey,  
  generateDsaKey
} = require('../controllers/cryptoController');

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
    const { text, key, iv } = req.body;

    // Verificar que la clave y el IV estén en Base64 y tengan la longitud correcta
    if (Buffer.from(key, 'base64').length !== 32) {
      return res.status(400).json({ error: 'La clave debe ser de 32 bytes (AES-256)' });
    }
    if (Buffer.from(iv, 'base64').length !== 16) {
      return res.status(400).json({ error: 'El IV debe ser de 16 bytes' });
    }

    // Llamar al servicio para cifrar el texto
    const encryptedText = aesEncryptService(text, key, iv);

    // Retornar el texto cifrado en Base64
    res.json({ encrypted: encryptedText });
  } catch (err) {
    console.error('Error en el cifrado AES:', err);
    res.status(500).json({ error: 'Error al cifrar el texto' });
  }
};

// AES-256-CBC Decrypt
const aesDecrypt = (req, res) => {
  try {
    const { encryptedText, key, iv } = req.body;

    // Verificar que la clave y el IV estén en Base64 y tengan la longitud correcta
    if (Buffer.from(key, 'base64').length !== 32) {
      return res.status(400).json({ error: 'La clave debe ser de 32 bytes (AES-256)' });
    }
    if (Buffer.from(iv, 'base64').length !== 16) {
      return res.status(400).json({ error: 'El IV debe ser de 16 bytes' });
    }

    // Llamar al servicio para descifrar el texto
    const decryptedText = aesDecryptService(encryptedText, key, iv);

    // Retornar el texto descifrado
    res.json({ decrypted: decryptedText });
  } catch (err) {
    console.error('Error en el descifrado AES:', err);
    res.status(500).json({ error: 'Error al descifrar el texto' });
  }
};

// ChaCha20 Encrypt
const chacha20Encrypt = (req, res) => {
  try {
    const { text, key, nonce } = req.body;

    // Verificar que la clave y el nonce estén en Base64 y tengan la longitud correcta
    if (Buffer.from(key, 'base64').length !== 32) {
      return res.status(400).json({ error: 'La clave debe ser de 32 bytes (ChaCha20)' });
    }
    if (Buffer.from(nonce, 'base64').length !== 12) {
      return res.status(400).json({ error: 'El nonce debe ser de 12 bytes' });
    }

    // Llamar al servicio para cifrar el texto
    const encryptedText = chacha20EncryptService(text, key, nonce);

    // Retornar el texto cifrado en Base64
    res.json({ encrypted: encryptedText });
  } catch (err) {
    console.error('Error en el cifrado ChaCha20:', err);
    res.status(500).json({ error: 'Error al cifrar el texto con ChaCha20' });
  }
};

// ChaCha20 Decrypt
const chacha20Decrypt = (req, res) => {
  try {
    const { encryptedText, key, nonce } = req.body;

    // Verificar que la clave y el nonce estén en Base64 y tengan la longitud correcta
    if (Buffer.from(key, 'base64').length !== 32) {
      return res.status(400).json({ error: 'La clave debe ser de 32 bytes (ChaCha20)' });
    }
    if (Buffer.from(nonce, 'base64').length !== 12) {
      return res.status(400).json({ error: 'El nonce debe ser de 12 bytes' });
    }

    // Llamar al servicio para descifrar el texto
    const decryptedText = chacha20DecryptService(encryptedText, key, nonce);

    // Retornar el texto descifrado
    res.json({ decrypted: decryptedText });
  } catch (err) {
    console.error('Error en el descifrado ChaCha20:', err);
    res.status(500).json({ error: 'Error al descifrar el texto con ChaCha20' });
  }
};

// Generación de Claves RSA (2048 bits)
const generateRsaKey = (req, res) => {
  try {
    const { publicKey, privateKey } = generateRsaKeyPair();
    res.json({ publicKey: publicKey.toString('base64'), privateKey: privateKey.toString('base64') });
  } catch (err) {
    console.error('Error al generar las claves RSA:', err);
    res.status(500).json({ error: 'Error al generar las claves RSA' });
  }
};

// Generación de Claves DSA (1024 bits)
const generateDsaKey = (req, res) => {
  try {
    const { publicKey, privateKey } = generateDsaKeyPair();
    res.json({ publicKey: publicKey.toString('base64'), privateKey: privateKey.toString('base64') });
  } catch (err) {
    console.error('Error al generar las claves DSA:', err);
    res.status(500).json({ error: 'Error al generar las claves DSA' });
  }
};

/*const rsaEncrypt = (req, res) => {
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
};*/

module.exports = {
  aesEncrypt,
  aesDecrypt,
  chacha20Encrypt,
  chacha20Decrypt,
  generateRsaKey,  
  generateDsaKey
};