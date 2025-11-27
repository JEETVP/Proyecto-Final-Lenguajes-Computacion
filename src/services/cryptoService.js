const crypto = require('crypto');
const argon2 = require('argon2');
const { publicEncrypt, privateDecrypt, generateKeyPairSync, createSign, createVerify } = require('crypto');

// SHA-256 Hash
const sha256HashService = (text) => {
  const hash = crypto.createHash('sha256').update(text).digest('hex');
  return hash;
};

// Argon2 Hash
const argon2HashService = async (password) => {
  const hash = await argon2.hash(password);
  return hash;
};

// AES Encryption (256-CBC)
const aesEncryptService = (text, key, iv) => {
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
};

// AES Decryption (256-CBC)
const aesDecryptService = (encryptedText, key, iv) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
  let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

// ChaCha20 Encryption
const chacha20EncryptService = (text, key, nonce) => {
  const cipher = crypto.createCipheriv('chacha20', Buffer.from(key, 'base64'), Buffer.from(nonce, 'base64'));
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
};

// ChaCha20 Decryption
const chacha20DecryptService = (encryptedText, key, nonce) => {
  const decipher = crypto.createDecipheriv('chacha20', Buffer.from(key, 'base64'), Buffer.from(nonce, 'base64'));
  let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

// RSA Encryption (Public Key)
const rsaEncryptService = (text, publicKey) => {
  const encrypted = publicEncrypt(
    {
      key: Buffer.from(publicKey, 'base64'),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    },
    Buffer.from(text, 'utf8')
  );
  return encrypted.toString('base64');
};

// RSA Decryption (Private Key)
const rsaDecryptService = (encryptedText, privateKey) => {
  const decrypted = privateDecrypt(
    {
      key: Buffer.from(privateKey, 'base64'),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    },
    Buffer.from(encryptedText, 'base64')
  );
  return decrypted.toString('utf8');
};

// DSA Signing (Private Key)
const signDsaService = (message, privateKey) => {
  const sign = createSign('SHA256');
  sign.update(message);
  const signature = sign.sign(Buffer.from(privateKey, 'base64'), 'base64');
  return signature;
};

// DSA Verification (Public Key)
const verifyDsaService = (message, signature, publicKey) => {
  const verify = createVerify('SHA256');
  verify.update(message);
  const isValid = verify.verify(Buffer.from(publicKey, 'base64'), Buffer.from(signature, 'base64'));
  return isValid;
};

// RSA Key Pair Generation
const generateRsaKeyPair = () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048, // Size of the RSA key in bits
    publicKeyEncoding: {
      type: 'pkcs1',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem',
    },
  });
  return { publicKey, privateKey };
};

// DSA Key Pair Generation
const generateDsaKeyPair = () => {
  const { publicKey, privateKey } = generateKeyPairSync('dsa', {
    modulusLength: 1024, // Size of the DSA key in bits
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });
  return { publicKey, privateKey };
};

module.exports = {
  sha256HashService,
  argon2HashService,
  aesEncryptService,
  aesDecryptService,
  chacha20EncryptService,
  chacha20DecryptService,
  rsaEncryptService,
  rsaDecryptService,
  signDsaService,
  verifyDsaService,
  generateRsaKeyPair,
  generateDsaKeyPair,
};
