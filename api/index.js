const crypto = require('crypto');
const https = require('https');

const FIREBASE_DB_URL = "https://modsirkit-a625b-default-rtdb.firebaseio.com";

// Default Fallback Keys agar Firebase mein set na ho
const DEFAULT_OWNER_KEY = "OWNER-SECRET-KEY-999";
const DEFAULT_ADMIN_KEY = "ADMIN-SECRET-KEY-123";

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
        const { key, uuid, localCrc, role } = body; // 'role' catch kar liya (owner ya admin)

        if (!key || !uuid) {
            return res.status(200).json({ success: false, error: "Key and UUID required!" });
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

        // ROLE KE HISAB SE SECRET KEY SELECT HOGI
        let activeSecretKey = DEFAULT_ADMIN_KEY;
        if (sysSettings) {
            if (role === 'owner') {
                activeSecretKey = sysSettings.ownerHmacKey || DEFAULT_OWNER_KEY;
            } else {
                activeSecretKey = sysSettings.adminHmacKey || DEFAULT_ADMIN_KEY;
            }
        }

        const exp = Math.floor(Date.now() / 1000) + 3600;
        const payloadData = { app: "com.modsirkit.app", exp: exp, uuid: uuid, role: role || "admin" };
        const payloadStr = JSON.stringify(payloadData);
        
        const hmac = crypto.createHmac('sha256', activeSecretKey);
        hmac.update(payloadStr);
        const signatureHex = hmac.digest('hex');
        const token = `${payloadStr}:${signatureHex}`;

        return res.status(200).json({ success: true, token: token });

    } catch (err) {
        return res.status(200).json({ success: false, error: err.message });
    }
};
