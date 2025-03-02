
const crypto = require('crypto');
const NodeRSA = require('node-rsa');

const AES_KEY = crypto.randomBytes(32); // 256-bit key
const AES_IV = crypto.randomBytes(16); // 128-bit IV

// AES Encryption
function encryptAES(data) {
    const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, AES_IV);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// AES Decryption
function decryptAES(encrypted) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', AES_KEY, AES_IV);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// SHA-256 Hashing
function hashSHA256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

// RSA Key Generation
const rsaKey = new NodeRSA({ b: 2048 });
const publicKey = rsaKey.exportKey('public');
const privateKey = rsaKey.exportKey('private');

// RSA Encryption
function encryptRSA(data) {
    return rsaKey.encrypt(data, 'base64');
}

// RSA Decryption
function decryptRSA(encrypted) {
    return rsaKey.decrypt(encrypted, 'utf8');
}

module.exports = {
    encryptAES,
    decryptAES,
    hashSHA256,
    encryptRSA,
    decryptRSA,
    publicKey,
    privateKey
};
