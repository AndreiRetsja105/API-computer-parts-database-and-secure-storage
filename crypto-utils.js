// FILE: /js/crypto-utils.js  
// part 9 – secure document signing with ecdsa p-256
// this file holds all the crypto helpers the html page calls for signing + verifying
// it also has pbkdf2 + aes-gcm bits you can reuse later for encrypted storage or login stuff

export const b64 = u8 => btoa(String.fromCharCode(...u8)); // turn bytes into base64
export const ub64 = s => new Uint8Array(atob(s).split('').map(c => c.charCodeAt(0))); // back to bytes
export const enc = new TextEncoder();   // text → bytes
export const dec = new TextDecoder();   // bytes → text

// make aes-gcm key from a password using pbkdf2 sha-256
export async function pbkdf2Key(password, salt, iterations = 150000, usage = ['encrypt','decrypt']) {
    const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name:'PBKDF2', salt, iterations, hash:'SHA-256' },
        material,
        { name:'AES-GCM', length:256 },
        false,
        usage
    );
}

// same idea but gives you 256 raw bits if you only need bytes
export async function pbkdf2Bits(password, salt, iterations = 150000) {
    const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', salt, iterations, hash:'SHA-256' }, material, 256);
    return new Uint8Array(bits);
}

// quick helper to grab random bytes – used for ivs etc
export function randomBytes(n) {
    const u = new Uint8Array(n);
    crypto.getRandomValues(u);
    return u;
}

// encrypt a js object with aes-gcm and return iv + ciphertext as base64 strings
export async function aesGcmEncryptJSON(obj, key) {
    const iv = randomBytes(12);
    const plain = enc.encode(JSON.stringify(obj));
    const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, plain);
    return { iv: b64(iv), ciphertext: b64(new Uint8Array(ct)) };
}

// decrypt back into object
export async function aesGcmDecryptJSON(encrypted, key) {
    const iv = ub64(encrypted.iv);
    const ct = ub64(encrypted.ciphertext);
    const plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
    return JSON.parse(dec.decode(plain));
}

// aes-gcm encrypt raw bytes
export async function aesGcmEncryptBytes(bytes, key) {
    const iv = randomBytes(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, bytes));
    return { iv, ciphertext: ct };
}

// aes-gcm decrypt raw bytes
export async function aesGcmDecryptBytes(iv, ct, key) {
    const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
    return new Uint8Array(pt);
}

// make a fresh aes key (random)
export async function genFileKey() {
    return crypto.subtle.generateKey({ name:'AES-GCM', length:256 }, true, ['encrypt','decrypt']);
}

// export/import raw aes keys if you want to save or load them
export async function exportRawKey(key) {
    return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

export async function importRawAesKey(raw) {
    return crypto.subtle.importKey('raw', raw, { name:'AES-GCM' }, false, ['encrypt','decrypt']);
}

// derive aes key + hmac key from the same password
export async function deriveEncAndMac(password, salt, iterations = 150000) {
    const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    const setup = { name:'PBKDF2', salt, iterations, hash:'SHA-256' };
    const aesKey = await crypto.subtle.deriveKey(setup, material, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
    const macKey = await crypto.subtle.deriveKey(setup, material, { name:'HMAC', hash:'SHA-256', length:256 }, false, ['sign','verify']);
    return { aesKey, macKey };
}

// make hmac-sha256 tag
export async function hmac(macKey, bytes) {
    const sig = await crypto.subtle.sign('HMAC', macKey, bytes);
    return new Uint8Array(sig);
}

// check hmac tag
export async function hmacVerify(macKey, bytes, sig) {
    return crypto.subtle.verify('HMAC', macKey, sig, bytes);
}

// stick a few Uint8Arrays together into one
export function concatBytes(...arrs) {
    const len = arrs.reduce((a,b) => a + b.length, 0);
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrs) { out.set(a, off); off += a.length; }
    return out;
}

// ---------- ecdsa stuff below – what the sign & verify page actually uses ----------

// makes a key pair for signing and verifying
export async function genEcdsaKeyPair() {
    return crypto.subtle.generateKey({ name:'ECDSA', namedCurve:'P-256' }, true, ['sign','verify']);
}

// sign file bytes with your private key
export async function ecdsaSign(privateKey, dataBytes) {
    return new Uint8Array(await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, privateKey, dataBytes));
}

// verify file signature with the matching public key
export async function ecdsaVerify(publicKey, dataBytes, signature) {
    return crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, publicKey, signature, dataBytes);
}

// export public key so you can share it for verification
export async function exportSpki(pub) {
    return new Uint8Array(await crypto.subtle.exportKey('spki', pub));
}

// export private key so you can back it up safely – keep it secret
export async function exportPkcs8(priv) {
    return new Uint8Array(await crypto.subtle.exportKey('pkcs8', priv));
}

// import a public key again when someone sends you their .spki file
// only used for verify
export async function importSpki(spki) {
    return crypto.subtle.importKey('spki', spki, { name:'ECDSA', namedCurve:'P-256' }, true, ['verify']);
}

// import your private key again from a .pk8 file
// only used when you need to sign new stuff
export async function importPkcs8(pkcs8) {
    return crypto.subtle.importKey('pkcs8', pkcs8, { name:'ECDSA', namedCurve:'P-256' }, true, ['sign']);
}

// helper that lets the browser save any Uint8Array as a download
// used for saving keys and .sig files after signing
export function download(filename, bytes) {
    const blob = new Blob([bytes], { type:'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}
