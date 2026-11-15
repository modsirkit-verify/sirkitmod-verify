const crypto = require('crypto');
const https = require('https');

const FIREBASE_DB_URL = "https://modsirkit-a625b-default-rtdb.firebaseio.com";

function fetchFirebaseData(path) {
    return new Promise((resolve) => {
        https.get(`${FIREBASE_DB_URL}${path}`, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try { resolve(JSON.parse(data)); } catch (e) { resolve(null); }
            });
        }).on('error', () => resolve(null));
    });
}

module.exports = async (req, res) => {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, error: "Method Not Allowed" });
    }

    try {
        const body = req.body || {};
        const { key, uuid, localCrc, role, nonce } = body;

        // Nonce aur UUID check zaroori hai
        if (!key || !uuid || !nonce) {
            return res.status(200).json({ success: false, error: "Key, UUID and Nonce required!" });
        }

        const keyData = await fetchFirebaseData(`/keys/${key}.json`);
        const sysSettings = await fetchFirebaseData(`/system_settings/lib_integrity.json`);

        if (!keyData) {
            return res.status(200).json({ success: false, error: "Key does not exist!" });
        }

        if (keyData.status && keyData.status !== 'ACTIVE') {
            return res.status(200).json({ success: false, error: "Key is Expired or Revoked!" });
        }

        if (keyData.expectedCrc32 && localCrc && keyData.expectedCrc32.toUpperCase() !== localCrc.toUpperCase()) {
            return res.status(200).json({ success: false, error: "Security Error: Library CRC Mismatch!" });
        }

        // Server Private Key (Vercel Environment Variables mein 'SERVER_PRIVATE_KEY' naam se save karein)
        const privateKeyPem = process.env.SERVER_PRIVATE_KEY || `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCz9Sl59WECdgHo
yTsFEH1DTQ+UP5pLtD3lV12GiGTHtCzD8eH4DfyKKqamOT9gYKY6jKjL3p8TbndK
iKGxseCS0bmDO2C1WebKxgfP5ttWUkLbFKdmo888F5kNnslB17P2mLB/t60ytGxT
U7yYWzptIRZhF22uHQEoHM+885bIFpa/0EZWuP2Ssc/XpOGF55Ucfs2+n/cMr/3m
TKJvz6V3y8+hRmuwpYJou5W25u6UKys5uDm/hvFfYXy48PF+dX4p8umQGwbj7kwM
UJyT59o97HuaQZ/8aSER49qq3C9NCJkk9srNmpfJpnAfh/dOhgkEOn+Fu4VE+/fc
u77mox95AgMBAAECggEADTlm4t91UYj6evDOtYCQs/Flw68o14dXRRM2fDxpq4NC
BuQvhtsAQ+b+eBic36g6jvLnNJQXfIYRnhiMSVKY/jELQOmMIceJfj0vNcfxNla1
MwRBiPlgsTnKtYWFpKEFSInP7pLA14kKrNTqdwe9M2fLDTd7h9/5xcjYOzprSii+
/7ZpeC0yxbbN0uSVfSKvEjAHLXAWa0JLxGGWN1cqqwTAdAZuyHKoIX4nWO9iAQpy
lDCplH538rs1RJcHMrY//aU3PKsoa6fq3YrPW8bBJHuvRZaJWuS+Cz2O9xjs1Mui
Utt3X7+JZLXPF37ZL25r0UVRCnjkWQi/O6JjmOxgAQKBgQDzXMClCWvCoShmoOUF
oQTttTSEhTsZiRyzY2tSkNZhabBATre5P+0n4cBMddfCrHP7aAn8iGV+rXaocJPS
zzooEYUqRgFtY8r8t9Gg82lZK+hGBv5WFS9Mv7vHoEa2lcsMup8maGfowKTpK3hc
bBMuCjrDPzKVZ/p0CkNGSoSlOQKBgQC9TYLPTcw5FnMcJ0//hgut8tHeMjQujwTi
ZUDa4NBVzKZuiXlJCbu5kADFDNI0Yzn4m+1LZlSqw5wofiRcQM16dbTt93lvdsO1
GYKMtkg8buOw1HFFkyCwmdUIln8mVq8jCKcLj1sFj21WnkUmdS43sn8v9FvsW+J1
IXsQP2qMQQKBgAI7UoTw7i0Nv0oZpaAElv/7Dm08r4sPZ9T5T22laGHiTzx3vFWV
kX4xIstQtVbSsAmZLaZENfIQcyseRSzEu7rMVlVJ6Q9wv9bLdL+uG8Q2k924iLKP
ZSymAXnWLW/VNdR7DaSThohq49hDjsoCL7bXXyyVMsiN+I0B3xYQ7uB5AoGANidC
UIN09K/TZi5o2DREixJ3rxS1kMwhHZLRpsvBTYop4l05cQdzyHXFgplUWOA56UDR
9Uvk1KT4uyy6whlXrryVca3l81kKS3hsvEw5BfDC+gcMEFcydtLK+pXy8cjCeUc0
Yj40T7bkFG9aYNIM0qohcFp7IXZ3pgJZ7h/2HwECgYB8BaPKeFzDeDj4yEllz1At
4olmd5Bpjj5RfXU13MMtwfVPADLbABIHqSxIbLT+laAihAHVmKfFnNy0Qi83Cp3H
7UstdB8WoglGKWaNHUX8kKmPUI/PBpBPoQ6evVhjeVrUhoHBAhg+xP0YJJ9c2Ra9
u8Q9vCVQAIehzfysfIGo8A==
-----END PRIVATE KEY-----`;

        const now = Math.floor(Date.now() / 1000);
        const exp = now + 3600; // Token 1 ghante tak valid rahega
        const assignedRole = role || "user";

        // Claims payload jo C++ client validate karega
        const payloadData = { 
            app: "com.alfas.xD", 
            iat: now,
            exp: exp, 
            uuid: uuid, 
            nonce: nonce,
            role: assignedRole 
        };
        
        const payloadStr = JSON.stringify(payloadData);
        
        // RSA-SHA256 Signature Generate karna (C++ client compatibility ke liye)
        const sign = crypto.createSign('SHA256');
        sign.update(payloadStr);
        sign.end();
        const signatureBuffer = sign.sign(privateKeyPem);
        const signatureHex = signatureBuffer.toString('hex');

        // 🔥 FIX: Colon (:) ka use kiya gaya hai taaki C++ client ke sath seamlessly match ho
        const token = `${payloadStr}:${signatureHex}`;

        return res.status(200).json({ success: true, token: token });

    } catch (err) {
        return res.status(200).json({ success: false, error: err.message });
    }
};
