// JSON Web Token signing — mixed JOSE algorithms.
const jwt = require('jsonwebtoken');

const access = jwt.sign(payload, rsaPrivateKey, { algorithm: 'RS256' });  // RSA
const session = jwt.sign(payload, hmacSecret, { algorithm: 'HS256' });    // HMAC
const device = jwt.sign(payload, ecPrivateKey, { algorithm: 'ES256' });   // ECDSA
