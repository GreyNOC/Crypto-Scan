const crypto = require('crypto');
const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);  // AES-128
const weak = crypto.createCipheriv('des-ede3', k, iv);         // 3DES
const h = crypto.createHash('sha1');                            // SHA-1
