'use strict';

const crypto = require('crypto');
const admin = require('firebase-admin');

const FIREBASE_DB_URL = 'https://modsirkit-a625b-default-rtdb.firebaseio.com';
const APP_ID = 'com.alfas.xD';
const ALLOWED_ROLES = new Set(['user', 'admin', 'owner']);
const MAX_CLOCK_SKEW_SECONDS = 86400; // 24 hours flexibility for testing
const TOKEN_LIFETIME_SECONDS = 60 * 60;

function send(res, status, body) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  return res.status(status).json(body);
}

function getDatabase() {
  if (!admin.apps.length) {
    const rawServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
    if (!rawServiceAccount) {
      throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON is not configured');
    }

    const serviceAccount = JSON.parse(rawServiceAccount);
    if (typeof serviceAccount.private_key === 'string') {
      serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
    }

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: FIREBASE_DB_URL
    });
  }
  return admin.database();
}

function getSigningKey() {
  const raw = process.env.SERVER_PRIVATE_KEY;
  if (!raw) throw new Error('SERVER_PRIVATE_KEY is not configured');

  const pem = raw.replace(/\\n/g, '\n');
  const key = crypto.createPrivateKey(pem);
  const details = key.asymmetricKeyDetails || {};
  if (key.asymmetricKeyType !== 'rsa' || !details.modulusLength || details.modulusLength < 2048) {
    throw new Error('SERVER_PRIVATE_KEY must be an RSA key of at least 2048 bits');
  }
  return key;
}

function parseCrc32(value) {
  if (value === undefined || value === null) return null;

  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0 || value > 0xFFFFFFFF) return null;
    return value >>> 0;
  }

  const text = String(value).trim();
  if (!text) return null;

  // Handles Hex strings (e.g., '7292A330', '0x7292A330')
  if (/^(0x)?[0-9a-f]{1,8}$/i.test(text)) {
    const cleanHex = text.startsWith('0x') || text.startsWith('0X') ? text.slice(2) : text;
    return parseInt(cleanHex, 16) >>> 0;
  }

  // Handles Decimal strings (e.g., '1922212656')
  if (/^[0-9]{1,10}$/.test(text)) {
    const number = Number(text);
    if (!Number.isSafeInteger(number) || number < 0 || number > 0xFFFFFFFF) return null;
    return number >>> 0;
  }

  return null;
}

function crcMatches(keyData, globalIntegrity, clientCrc) {
  const actual = parseCrc32(clientCrc);
  // Checks key-specific CRC first, falls back to Admin Panel's Global Lib Config
  const expected = parseCrc32(keyData.expectedCrc32) 
                ?? parseCrc32(keyData.expectedCrc32Dec) 
                ?? parseCrc32(globalIntegrity.libCrcHash) 
                ?? parseCrc32(globalIntegrity.libCrcDecimal);
  return actual !== null && expected !== null && actual === expected;
}

function normalizeDevices(value) {
  if (Array.isArray(value)) {
    const result = {};
    value.forEach((device, index) => {
      if (device && typeof device === 'object' && typeof device.uuid === 'string') {
        result[device.uuid] = device;
      } else if (typeof device === 'string') {
        result[`legacy_${index}`] = {
          uuid: device,
          model: 'Device',
          lastLogin: 0
        };
      }
    });
    return result;
  }
  if (value && typeof value === 'object') return { ...value };
  return {};
}

function trustedRole(keyData) {
  const value = typeof keyData.role === 'string' ? keyData.role.toLowerCase() : 'user';
  return ALLOWED_ROLES.has(value) ? value : 'user';
}

function validFirebaseKey(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{5,50}$/.test(value);
}

function validUuid(value) {
  return typeof value === 'string' && value.length >= 8 && value.length <= 128 &&
    /^[A-Za-z0-9:_-]+$/.test(value);
}

function safeDeviceModel(value) {
  if (typeof value !== 'string') return 'Unknown Device';
  const cleaned = value.replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, 80);
  return cleaned || 'Unknown Device';
}

function isActiveKey(data) {
  return !!data && typeof data === 'object' && data.status === 'ACTIVE';
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return send(res, 405, { success: false, error: 'Method Not Allowed' });
  }

  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { key, uuid, deviceModel, localCrc, nonce, appId, clientTime } = body;

    console.log('Incoming login request:', { key, uuid, localCrc, appId, clientTime });

    if (!validFirebaseKey(key) || !validUuid(uuid) ||
        typeof nonce !== 'string' || !/^[0-9a-f]{64}$/i.test(nonce) ||
        appId !== APP_ID || typeof clientTime !== 'number' || !Number.isSafeInteger(clientTime)) {
      console.log('Validation failed for body fields');
      return send(res, 400, { success: false, error: 'Invalid login request' });
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    if (Math.abs(nowSeconds - clientTime) > MAX_CLOCK_SKEW_SECONDS) {
      console.log('Clock skew exceeded:', { nowSeconds, clientTime, diff: Math.abs(nowSeconds - clientTime) });
      return send(res, 401, { success: false, error: 'Login request expired; please retry' });
    }

    const signingKey = getSigningKey();
    const db = getDatabase();

    // Fetch key data and global integrity settings concurrently
    const keyRef = db.ref(`keys/${key}`);
    const integrityRef = db.ref('system_settings/lib_integrity');
    
    const [initialSnapshot, integritySnapshot] = await Promise.all([
      keyRef.once('value'),
      integrityRef.once('value')
    ]);

    const initialKeyData = initialSnapshot.val();
    const globalIntegrity = integritySnapshot.val() || {};

    if (!initialKeyData) {
      console.log('Key does not exist in DB:', key);
      return send(res, 401, { success: false, error: 'Key does not exist' });
    }
    if (!isActiveKey(initialKeyData)) {
      console.log('Key is inactive or revoked:', key);
      return send(res, 403, { success: false, error: 'Key is inactive or revoked' });
    }

    console.log('CRC check debug:', { localCrc, dbCrc: initialKeyData.expectedCrc32, globalCrc: globalIntegrity.libCrcHash });
    if (!crcMatches(initialKeyData, globalIntegrity, localCrc)) {
      console.log('CRC mismatch:', { client: localCrc });
      return send(res, 403, { success: false, error: 'Library version check failed' });
    }

    const nonceHash = crypto.createHash('sha256')
      .update(`${APP_ID}:${uuid}:${nonce}`)
      .digest('hex');
    const nonceRef = db.ref(`usedNonces/${nonceHash}`);
    const nonceTransaction = await nonceRef.transaction((current) => {
      if (current !== null) return;
      return {
        createdAt: Date.now(),
        app: APP_ID,
        uuidHash: crypto.createHash('sha256').update(uuid).digest('hex')
      };
    }, undefined, false);

    if (!nonceTransaction.committed) {
      console.log('Nonce already used');
      return send(res, 409, { success: false, error: 'Login request already used' });
    }

    const model = safeDeviceModel(deviceModel);
    let transactionFailure = '';
    const keyTransaction = await keyRef.transaction((current) => {
      transactionFailure = '';
      if (!current || typeof current !== 'object') {
        transactionFailure = 'KEY_NOT_FOUND';
        return;
      }
      if (!isActiveKey(current)) {
        transactionFailure = 'KEY_INACTIVE';
        return;
      }
      if (!crcMatches(current, globalIntegrity, localCrc)) {
        transactionFailure = 'CRC_MISMATCH';
        return;
      }

      const devices = normalizeDevices(current.devices);
      const maxDevicesValue = Number(current.maxDevices);
      const maxDevices = Number.isInteger(maxDevicesValue) && maxDevicesValue >= 1 && maxDevicesValue <= 100
        ? maxDevicesValue : 1;

      if (!devices[uuid] && Object.keys(devices).length >= maxDevices) {
        transactionFailure = 'DEVICE_LIMIT';
        return;
      }

      devices[uuid] = {
        uuid,
        model,
        lastLogin: Date.now()
      };
      current.devices = devices;
      return current;
    }, undefined, false);

    if (!keyTransaction.committed) {
      console.log('Key transaction failed with reason:', transactionFailure);
      if (transactionFailure === 'DEVICE_LIMIT') {
        return send(res, 403, { success: false, error: 'Device limit reached' });
      }
      if (transactionFailure === 'KEY_INACTIVE') {
        return send(res, 403, { success: false, error: 'Key is inactive or revoked' });
      }
      if (transactionFailure === 'CRC_MISMATCH') {
        return send(res, 403, { success: false, error: 'Library version check failed' });
      }
      if (transactionFailure === 'KEY_NOT_FOUND') {
        return send(res, 401, { success: false, error: 'Key does not exist' });
      }
      return send(res, 409, { success: false, error: 'Login conflict; please retry' });
    }

    const committedKeyData = keyTransaction.snapshot.val() || initialKeyData;
    const assignedRole = trustedRole(committedKeyData);
    const now = Math.floor(Date.now() / 1000);
    const payloadData = {
      app: APP_ID,
      iat: now,
      exp: now + TOKEN_LIFETIME_SECONDS,
      uuid,
      nonce,
      role: assignedRole
    };

    const payloadStr = JSON.stringify(payloadData);
    const signatureHex = crypto.sign('RSA-SHA256', Buffer.from(payloadStr, 'utf8'), signingKey).toString('hex');
    const token = `${payloadStr}:${signatureHex}`;

    console.log('Login successful for key:', key);
    return send(res, 200, { success: true, token });
  } catch (err) {
    console.error('Login API error:', err && err.message ? err.message : 'unknown');
    return send(res, 500, { success: false, error: 'Authentication service unavailable' });
  }
};
