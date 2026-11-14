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
        const privateKeyPem = process.env.SERVER_PRIVATE_KEY ||
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDxVCqOZvP/t62+
h4YJHoNcpkn83Su5PdrCllQNuHc6o1jx660nGrboumKybRIxc9AKvZO0ZgPEuZdv
io7NFFYTaiV75dtct8IPxKorKHvJ1PpSLtTY3urpXJju6JvJSbQoGmI2MVWP+kzB
zfHC1IFGgYp3m2V4RwywOIrsN/wyuiB7QO8Pz0rhZa9gW1SK3UdwKuz863LDg50g
Wu7IgFY/iIYWjnIN2SMmaJFXtn8MJFIyHrl2UXpo/wiNt+HjNtSqBUiq/YgAkgDf
LxXsifxX/jXXGijHbv1odZaCfqlYms6loBb4qpz3gY+kdAR702JNwjPrDXxI4TpR
SyE/WvLHAgMBAAECggEBAIaT/CNrcFhDUwW0R9/f/zt0lEAKCq8DunHXKUp5eyvd
GeXXGrl64VOJVS7ROlsPjY3fyHXKigFzyepu51GgLJwpDnw4Y4siAnuOnaLxsY6N
UYbxDMtgDLpUZAie+PlYO7o9dFVqT5+54oIVWePfY7Qw20n2A7D+VioTbg1q7x5N
rjvcCoH17P4lJq+gJ1M779Qu7HTCuavvxcf8FWH1tBgeYn9JF8KruqWUGiLI20rd
wMzSh7MGCOoOmlZo2qwm/K6MueuTpCe6rkKkSrJ/QBN4+QadKBe2lecn/TgxG3bK
2a9qmaflHy++/4XFVsiCw4IdF9BgmdCCBhiLfWgU3HECgYEA/Il8YpgHbjefiO96
0C3Dj8EGUxxtADIfwEmVmrRh42rxNaDgT1lEBSHtRUgkZC5RVQ86P6NBQt4Li+f/
pHMCNeC9BGNFuZX3cU3w3SwjbzhBrnXYOy1p6UGgjwU8Ga7nVfWlyYxgHgPg4+ch
wvJfnqCFmirIJySq1CgujKvymt8CgYEA9KNVnrqk83LrXDXdHPU4H9fHYqWyBRux
wbRblxlbmyTDZb4Bo1V/X1ysG5NCPK/hUp4L4zaGTy0JKBgBtiSUEv14ptkN3FUG
Az2IhJe7VsFunopPiISdpLAjfGyUXwmAeVnabHNE62uITLkB5Ppn5CwZ68Iv7Mj0
6Hi+ZVNDjRkCgYARgXpU31MMieCOPoOV8MYwreHBWyQXMmJPEwrC2aQ7fotP+2Hx
Pi/f5zUqa1DSfP94VQDlrmx0tS25uhBXlv1dPMH9juAjeEjZ2txKiKfAKvcqn9Ko
b4J6/+igYW2EHkK9C7U9XnS/P+eUBM6rU9/bACeiwzpytDD/WfW4HKdJowKBgGT9
1MfNR3FVHMKZXempdfz3SFF6E862CyDrQvBSwJWAjMXAtc5m6klE6awMk8iX1w4T
PtcS2ElxTxllJ7e4zAQ27Yr7ihROaUgHLAeI2AbNncwHTyQNk0K8kDm6XVoKgyYV
qO0ifO4vGzqJGbYcha0VY7IHHV/D6g7aYcdUo0tpAoGBAIfmWPFqdKSuNahcqBEb
WJD90mL1cjgR/2qd36FAQV61uPNEqqh8RoCppZ/xOJvc3bbHgrGFvv5sebUDDWlj
W4OX2Bp3m7RNtoHaMyggT9/1hdgZ4ySyoR5drB5DSIQ6phiLAmoAB5lCu5MmE+cD
y2qmGlaXelo7/O0S8BrgAEfa
-----END PRIVATE KEY-----

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

        const token = `${payloadStr}:${signatureHex}`;

        return res.status(200).json({ success: true, token: token });

    } catch (err) {
        return res.status(200).json({ success: false, error: err.message });
    }
};
