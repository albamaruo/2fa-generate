const crypto = require("crypto");
const secret = ""; //2fa秘密鍵
function base32Decode(str) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    str = str.replace(/=+$/, "").toUpperCase();
    let bits = "";
    for (const char of str) {
        const value = alphabet.indexOf(char);
        if (value === -1) {
            throw new Error(`Invalid Base32 character: ${char}`);
        }

        bits += value.toString(2).padStart(5, "0");
    }
    const bytes = [];

    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.substring(i, i + 8), 2));
    }

    return Buffer.from(bytes);
}
function generateTOTP(secret) {
    const key = base32Decode(secret);
    const counter = Math.floor(Date.now() / 1000 / 30);
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeBigUInt64BE(BigInt(counter));
    const hmac = crypto
        .createHmac("sha1", key)
        .update(counterBuffer)
        .digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
        ((hmac[offset] & 0x7f) << 24) |
        (hmac[offset + 1] << 16) |
        (hmac[offset + 2] << 8) |
        hmac[offset + 3];
    return String(binary % 1000000).padStart(6, "0");
}
try {
    const code = generateTOTP(secret);
    console.log("Secret :", secret);
    console.log("2FA Code:", code);
    console.log("残り秒数:", 30 - (Math.floor(Date.now() / 1000) % 30));
} catch (error) {
    console.error("Error:", error.message);
}