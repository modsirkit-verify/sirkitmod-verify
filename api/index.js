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

function updateFirebaseData(path, dataObj) {
    return new Promise((resolve) => {
        const url = new URL(`${FIREBASE_DB_URL}${path}`);
        const dataStr = JSON.stringify(dataObj);
        
        const reqOptions = {
            hostname: url.hostname,
            path: url.pathname + url.search,
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(dataStr)
            }
        };

        const req = https.request(reqOptions, (res) => {
            let resData = '';
            res.on('data', chunk => resData += chunk);
            res.on('end', () => resolve(true));
        });

        req.on('error', () => resolve(false));
        req.write(dataStr);
        req.end();
    });
}

module.exports = async (req, res) => {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, error: "Method Not Allowed" });
    }

    try {
        const body = req.body || {};
        const { key, uuid, deviceModel, localCrc, role, nonce } = body;

        if (!key || !uuid || !nonce) {
            return res.status(200).json({ success: false, error: "Key, UUID and Nonce required!" });
        }

        const keyData = await fetchFirebaseData(`/keys/${key}.json`);

        if (!keyData) {
            return res.status(200).json({ success: false, error: "Key does not exist!" });
        }

        if (keyData.status && keyData.status !== 'ACTIVE') {
            return res.status(200).json({ success: false, error: "Key is Expired or Revoked!" });
        }

        // 🔥 Strict Enforcement: Auto-binding removed! Key MUST have pre-configured CRC from SirkitMod Panel.
        if (!keyData.expectedCrc32) {
            return res.status(200).json({ 
                success: false, 
                error: `Security Error: Invalid Key Source! (Please use SirkitMod Panel)` 
            });
        }

        const clientCrc = String(localCrc || '').trim().toUpperCase();
        let clientHex = clientCrc;
        if (/^[0-9]+$/.test(localCrc.trim())) {
            const num = parseInt(localCrc.trim(), 10) >>> 0;
            clientHex = '0x' + num.toString(16).toUpperCase().padStart(8, '0');
        }

        // 🔍 DEBUGGING LOGS (Vercel Dashboard -> Logs mein yeh dikhega)
        console.log("-----------------------------------------");
        console.log("KEY CHECK:", key);
        console.log("DB expectedCrc32:", keyData.expectedCrc32);
        console.log("Client raw localCrc:", localCrc);
        console.log("Converted clientHex:", clientHex);
        console.log("-----------------------------------------");

        if (clientHex) {
            const dbCrcHex = String(keyData.expectedCrc32).trim().toUpperCase();
            const dbCrcDec = keyData.expectedCrc32Dec ? String(keyData.expectedCrc32Dec).trim() : '';
            
            let clientDec = clientCrc;
            if (/^[0-9]+$/.test(localCrc.trim())) {
                clientDec = parseInt(localCrc.trim(), 10).toString(10);
            } else if (/^0x[0-9a-fA-F]+$/i.test(localCrc.trim())) {
                clientDec = parseInt(localCrc.trim(), 16).toString(10);
            }

            const isMatch = (clientHex === dbCrcHex) || 
                            (clientDec === dbCrcDec) || 
                            (clientCrc === dbCrcHex) || 
                            (clientCrc === dbCrcDec);

            if (!isMatch) {
                console.log("❌ CRC MISMATCH DETECTED! DB:", dbCrcHex, "VS Client:", clientHex);
                return res.status(200).json({ 
                    success: false, 
                    error: `Security Error: Library CRC Mismatch! (Wrong Mod Version for this Key)` 
                });
            }
        }

        // Dashboard ke sath compatible device binding & limit check
        let devices = keyData.devices || {};
        if (Array.isArray(devices)) {
            const obj = {};
            devices.forEach((d, idx) => {
                if (typeof d === 'object' && d.uuid) obj[d.uuid] = d;
                else obj['dev_' + idx] = { uuid: d, model: 'Device', lastLogin: Date.now() };
            });
            devices = obj;
        }

        const deviceKeys = Object.keys(devices);
        const maxDevices = keyData.maxDevices || 1;

        if (!devices[uuid]) {
            if (deviceKeys.length >= maxDevices) {
                return res.status(200).json({ success: false, error: `Device limit reached! Max allowed: ${maxDevices}` });
            }
            devices[uuid] = {
                uuid: uuid,
                model: deviceModel || "Unknown Device",
                lastLogin: Date.now()
            };
        } else {
            devices[uuid].lastLogin = Date.now();
            if (deviceModel) devices[uuid].model = deviceModel;
        }

        await updateFirebaseData(`/keys/${key}.json`, {
            devices: devices
        });

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
        const exp = now + 3600; 
        const assignedRole = role || "user";

        const payloadData = { 
            app: "com.alfas.xD", 
            iat: now,
            exp: exp, 
            uuid: uuid, 
            nonce: nonce,
            role: assignedRole 
        };
        
        const payloadStr = JSON.stringify(payloadData);
        
        const sign = crypto.createSign('SHA256');
        sign.update(payloadStr);
        sign.end();
        const signatureBuffer = sign.sign(privateKeyPem);
        const signatureHex = signatureBuffer.toString('hex');

        const token = `${payloadStr}:${signatureHex}`;

        return res.status(200).json({ success: true, token: token });

    } catch (err) {
        return res.status(200).json({ success: false, error: err.message });
    }
};
