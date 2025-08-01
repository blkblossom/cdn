async function getKeyMaterial(password) {
    return new TextEncoder().encode(password);
}

async function encryptURL(url, secretKey) {
    const enc = new TextEncoder();

    const keyMaterial = await getKeyMaterial(secretKey);
    const key = await window.crypto.subtle.importKey(
        "raw", keyMaterial, "PBKDF2", false, ["deriveKey"]
    );

    const derivedKey = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode("some-salt"),
            iterations: 100000,
            hash: "SHA-256"
        },
        key,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
    );

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        derivedKey,
        enc.encode(url)
    );

    // Return base64 string of IV + ciphertext
    const encryptedBytes = new Uint8Array(iv.length + encrypted.byteLength);
    encryptedBytes.set(iv, 0);
    encryptedBytes.set(new Uint8Array(encrypted), iv.length);
    return btoa(String.fromCharCode(...encryptedBytes));
}

async function decryptURL(encryptedBase64, secretKey) {
    const enc = new TextEncoder();
    const data = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

    const iv = data.slice(0, 12);
    const encryptedBytes = data.slice(12);

    const keyMaterial = await getKeyMaterial(secretKey);
    const key = await window.crypto.subtle.importKey(
        "raw", keyMaterial, "PBKDF2", false, ["deriveKey"]
    );

    const derivedKey = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode("some-salt"),
            iterations: 100000,
            hash: "SHA-256"
        },
        key,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );

    const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        derivedKey,
        encryptedBytes
    );

    return new TextDecoder().decode(decrypted);
}

function obfuscate(str, key) {
    return btoa(str.split('').map((c, i) =>
        String.fromCharCode(c.charCodeAt(0) ^ key.charCodeAt(i % key.length))
    ).join(''));
}

function deobfuscate(encoded, key) {
    const str = atob(encoded);
    return str.split('').map((c, i) =>
        String.fromCharCode(c.charCodeAt(0) ^ key.charCodeAt(i % key.length))
    ).join('');
}
