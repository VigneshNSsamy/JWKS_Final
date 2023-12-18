const express = require('express')
const NodeRsa = require('node-rsa')

'use strict'
const fs = require('fs')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')


/*const key = new NodeRsa({ b: 2048 })
 let serect = 'Hello from RSA'

 
 var encriptString = key.encrypt(serect, 'base64')
 console.log(encriptString);

 var decriptString = key.decrypt(encriptString, 'utf8')
 console.log(decriptString);


var publicKey = key.exportKey('public')
var privateKey = key.exportKey('private')

console.log(publicKey + '\n'+ privateKey);

publicKey = '-----BEGIN PUBLIC KEY-----\n' +
'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxFXpF47rwFLhQvX7CpXP\n' +
'gRWpNCx5NlDYjNUCluX/yzuGQIrCuev7L9l9mu7NJrJ1B+bfYJ/EXrWvyQ0N/1Uh\n' +
'hCBGetNMIxfknyFErfteIesj/7567h4e4ww8r9lJEJyncDG4A+5zmHZ33Gk4l27i\n' +
'pJiebIslhXk7P7+1VPi/uzQHPPR8Xaj7IHFAnuLLb9V11A2EwSm+r0fZyvAGz3wN\n' +
'AcEGSWp+qnbMOUC1dNE0fKrLHzFljEhpajQWgbkFUnVk0Y4ZW7B06gt1QcHjjPns\n' +
'MYfWxsDFsIQI/4/9CRhXruZF6TuCgFmMsbOhOhwFJCwT0xDHFJB+VlakDU4EsIQz\n' +
'QwIDAQAB\n' +
'-----END PUBLIC KEY-----'

privateKey = '-----BEGIN RSA PRIVATE KEY-----\n' +
'MIIEpAIBAAKCAQEAxFXpF47rwFLhQvX7CpXPgRWpNCx5NlDYjNUCluX/yzuGQIrC\n' +
'uev7L9l9mu7NJrJ1B+bfYJ/EXrWvyQ0N/1UhhCBGetNMIxfknyFErfteIesj/756\n' +
'7h4e4ww8r9lJEJyncDG4A+5zmHZ33Gk4l27ipJiebIslhXk7P7+1VPi/uzQHPPR8\n' +
'Xaj7IHFAnuLLb9V11A2EwSm+r0fZyvAGz3wNAcEGSWp+qnbMOUC1dNE0fKrLHzFl\n' +
'jEhpajQWgbkFUnVk0Y4ZW7B06gt1QcHjjPnsMYfWxsDFsIQI/4/9CRhXruZF6TuC\n' +
'gFmMsbOhOhwFJCwT0xDHFJB+VlakDU4EsIQzQwIDAQABAoIBAC1LIHX1279Hn34C\n' +
'H0MG4pMF+z31EJWOOxbqQSmsr8Ej30neeSPJI+6a/xYSBzPpMYR8J4Yz9WpgAcih\n' +
'AVypOA0yIPBO9J6X8X8gfqagecvbYjeqqtNqEXgRp6JtvyRc72e7oJcPmI1Qr0Ai\n' +
'6hJNW23bY5jo1OQg3qFLSbrrk9fMtnnEdqYZ4iu9glgSmKWF3FkEKnRiTzkV4fGB\n' +
'U/NSee67YAl2bklbZjnYIkFhJ9qI9Bw3gwSg9M5A78uhaD8z28UclnAUrnoA6o7s\n' +
'REg0n40t7bdV1R05IkrlESw3t6QQoaOtww4njEuHTJtt0kctMNu+B16LCvo73Ksk\n' +
'ug+AfxECgYEA4M/isA0HFAyQQpQgCny1RpRxh1eYVoEX9+HT52wkFWMdbBRXCvyB\n' +
'9l4GsdW+q3YcjUkMMiFlDKonHkTpTIF6/BgI9kLXryjGihT5m2/8v/86UHA1nj/i\n' +
'UqDqfJQ+H2+QrRqi9DNpSP/nyQFFmwn1dHnuzUcM4rWEtW+d0R18jfsCgYEA35Kx\n' +
't4veomO4Yx5Ej89fetYlY0jxgS7LeSTGWkSJVm/vOeHLegy3DmxUpaNiGKr4zYEm\n' +
'wTCKLB3x4IojUad5p/NWg1iYUY28ykLddeg/D3uLQwcNy95zXB6v3PyiexmWazyh\n' +
'49xuDBIL6g5uhclr1xcu5K2w9fl2qx+jJKcv1VkCgYAHzA3/ryP8tQbX2E1YL8UV\n' +
'wpZBbG9TKL0NEt8Hmr+RolNl6TqvndxgEBjJWDF5vun0mID8yB26F7itmxRAXAlI\n' +
'7wh4ig7y+0YPifSySGsKua5rFck2SN7voLchRP72lib9afwW3iWbq4x9czbXzrud\n' +
'o5D9u6Ydws/sfweJNi2YuwKBgQCikSJUmonqfqRGvm2QPHPq9+f7x8CD9KjTj+AD\n' +
'Jy7OAVpsNjkkqDY7cJ4kSyc7VKbRl4W8mDUAW03Tvd5ss2CMtS5FF5i6RFvwnqo1\n' +
'4Ahqk6TxuiFYCorLgyzRfYoQBM0RcOcursv+TukG6jOHaKzXm+3nLj0svpaBW+He\n' +
'9wqbEQKBgQCcWvD/lg2YdAFPT3BFBJk5km6WLC3SWSQTMWaHorzZTtmbr61x/cir\n' +
'Fz4lQbaHZDc8kclUByNgM8stdDkwNYhNjkun5BnqjbHcNn2H1lK3fp5wCKdn51Np\n' +
'KH2GvI9WPfgkLLB6GryFqNgb08YGYFxuTCsvMNa8KU6txOmsFsLhvw==\n' +
'-----END RSA PRIVATE KEY-----' 

let key_private = new NodeRsa(privateKey)
let key_public = new NodeRsa(publicKey)

var encriptedString = key_public.encrypt(serect, 'base64')
console.log(encriptedString);

var decriptedString = key_private.decrypt(encriptedString, 'utf8')
console.log(decriptedString);
*/

function generateKeyPair(){
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    return { publicKey, privateKey };
}

function saveKeyToFile(key, fileName){
    fs.writeFileSync(fileName, key, 'utf8');
    console.log(`Key Saved to ${fileName}`);
}

const { publicKey, privateKey }=  generateKeyPair();

console.log('PrivateKey: \n'+ privateKey);
console.log('PublicKey:\n'+ publicKey);

saveKeyToFile(privateKey, 'privateKey.pem');
saveKeyToFile(publicKey, 'publicKey.pem');

var private_key = fs.readFileSync('./privateKey.pem', 'utf8')
var public_key = fs.readFileSync('./publicKey.pem', 'utf8')

var payload = { };
payload.userName = 'HOS';
payload.userId = '0010';
payload.roal = 'admin';

console.log('Payload: '+ JSON.stringify(payload));

var iss = 'HighonSwift';
var sub = 'vignesh@highonswift';
var aud = 'https://www.youtube.com/channel/UC2JdAJFt6w7MCVX57OlDyDg';
var exp = '1h';

var signOption = {
    issuer: iss,
    subject: sub,
    audience: aud,
    expiresIn: exp,
    algorithm: 'RS256'
};

var token = jwt.sign(payload, private_key, signOption);

console.log('Token:\n'+ token);

var verifyOptions = {
    issuer: iss,
    subject: sub,
    audience: aud,
    expiresIn: exp,
    algorithm: 'RS256'
};

var verify = jwt.verify(token, public_key, verifyOptions);

console.log('\nVerified: '+ JSON.stringify(verify));

var decode = jwt.decode(token, {complete: true});
console.log('\n Decode Header: '+ JSON.stringify(decode.header));
console.log('\n Decode Payload: '+ JSON.stringify(decode.payload));
console.log('\nDetails for the user: ' + payload.userId + 'is sent back to client');

