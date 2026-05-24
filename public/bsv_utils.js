//use with     <script src="https://unpkg.com/@smartledger/bsv@3.4.0/bsv.bundle.js"></script>

// Pure functional crypto/key utilities built around bsv + Web Crypto

// ---------- Canonical JSON ----------
export function sortKeysDeep(value) {
  if (Array.isArray(value)) return value.map(sortKeysDeep);

  if (value && typeof value === 'object' && value.constructor === Object) {
    return Object.keys(value)
      .sort()
      .reduce((acc, key) => {
        acc[key] = sortKeysDeep(value[key]);
        return acc;
      }, {});
  }

  return value;
}

export function canonicalStringify(obj) {
  return JSON.stringify(sortKeysDeep(obj));
}

// ---------- Encoding helpers ----------
export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }

  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

export function bytesToBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }

  return btoa(binary);
}

export function base64ToBytes(base64) {
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }

  return out;
}

// ---------- Factory ----------
export function createSL({
  bsv,
  MnemonicClass = globalThis.bsvMnemonic || globalThis.Mnemonic || (globalThis.bsv && globalThis.bsv.Mnemonic),
  cryptoObj = globalThis.crypto,
} = {}) {
  if (!bsv) throw new Error('bsv instance is required');

  const BufferClass = bsv?.deps?.Buffer;
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  function requireMnemonic() {
    if (!MnemonicClass) throw new Error('Mnemonic module not loaded');
    return MnemonicClass;
  }

  function requireBuffer() {
    if (!BufferClass) throw new Error('BSV Buffer dependency not available');
    return BufferClass;
  }

  function requireWebCrypto() {
    if (!cryptoObj?.subtle) throw new Error('Web Crypto API not available');
    return cryptoObj;
  }

  return {
    bsv: () => bsv,

    getEnvironmentInfo() {
      return {
        bsvPresent: !!bsv,
        hasMessage: !!bsv?.Message,
        hasMnemonic: !!MnemonicClass,
        hasSmartLedger: !!bsv?.SmartLedger,
        mnemonicAvailable: {
          bsvMnemonic: !!globalThis.bsvMnemonic,
          globalMnemonic: !!globalThis.Mnemonic,
          bsvInternal: !!(globalThis.bsv && globalThis.bsv.Mnemonic),
        },
        version: `SmartLedger BSV v${bsv.version || 'unknown'}`,
      };
    },

    genMnemonic(strength = 256) {
      const MC = requireMnemonic();
      return MC.fromRandom(strength).phrase;
    },

    validateMnemonic(mnemonic) {
      try {
        const MC = requireMnemonic();
        new MC(mnemonic);
        return true;
      } catch {
        return false;
      }
    },

    mnemonicToSeed(mnemonic) {
      const MC = requireMnemonic();
      return new MC(mnemonic).toSeed();
    },

    derivePath(mnemonic, path) {
      const MC = requireMnemonic();
      const m = new MC(mnemonic);
      const hdPrivateKey = bsv.HDPrivateKey.fromSeed(m.toSeed());
      const derived = hdPrivateKey.deriveChild(path);

      return {
        path,
        wif: derived.privateKey.toWIF(),
        publicKey: derived.privateKey.toPublicKey().toString('hex'),
        address: derived.privateKey.toAddress().toString(),
      };
    },

    identityFromWif(wif) {
      const priv = bsv.PrivateKey.fromWIF(wif);
      return {
        wif,
        publicKey: priv.toPublicKey().toString('hex'),
        address: bsv.Address.fromPrivateKey(priv).toString(),
      };
    },

    deriveIdentity(mnemonic, path) {
      const derived = this.derivePath(mnemonic, path);
      const priv = bsv.PrivateKey.fromWIF(derived.wif);

      return {
        path,
        wif: derived.wif,
        publicKey: priv.toPublicKey().toString('hex'),
        address: bsv.Address.fromPrivateKey(priv).toString(),
      };
    },

    async encrypt(data, password) {
      const crypto = requireWebCrypto();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));

      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        textEncoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
      );

      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations: 100000,
          hash: 'SHA-256',
        },
        keyMaterial,
        {
          name: 'AES-GCM',
          length: 256,
        },
        false,
        ['encrypt']
      );

      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        textEncoder.encode(data)
      );

      const encryptedBytes = new Uint8Array(encrypted);
      const packed = new Uint8Array(salt.length + iv.length + encryptedBytes.length);

      packed.set(salt, 0);
      packed.set(iv, salt.length);
      packed.set(encryptedBytes, salt.length + iv.length);

      return bytesToBase64(packed);
    },

    async decrypt(encData, password) {
      try {
        const crypto = requireWebCrypto();
        const packed = base64ToBytes(encData);

        if (packed.length < 29) {
          throw new Error('Encrypted payload too short');
        }

        const salt = packed.slice(0, 16);
        const iv = packed.slice(16, 28);
        const encrypted = packed.slice(28);

        const keyMaterial = await crypto.subtle.importKey(
          'raw',
          textEncoder.encode(password),
          'PBKDF2',
          false,
          ['deriveKey']
        );

        const key = await crypto.subtle.deriveKey(
          {
            name: 'PBKDF2',
            salt,
            iterations: 100000,
            hash: 'SHA-256',
          },
          keyMaterial,
          {
            name: 'AES-GCM',
            length: 256,
          },
          false,
          ['decrypt']
        );

        const decrypted = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv },
          key,
          encrypted
        );

        return textDecoder.decode(decrypted);
      } catch (error) {
        if (error?.name === 'OperationError') {
          throw new Error('Invalid password or unreadable encrypted vault data.');
        }
        throw error;
      }
    },

    async hash(data, algo) {
      if (bsv?.crypto?.Hash) {
        try {
          const Buffer = requireBuffer();
          const buffer = Buffer.from(data, 'utf8');

          let hashResult;
          switch (algo) {
            case 'SHA256':
              hashResult = bsv.crypto.Hash.sha256(buffer);
              break;
            case 'SHA512':
              hashResult = bsv.crypto.Hash.sha512(buffer);
              break;
            case 'RIPEMD160':
              hashResult = bsv.crypto.Hash.ripemd160(buffer);
              break;
            default:
              throw new Error(`Unsupported hash algorithm: ${algo}`);
          }

          if (hashResult && typeof hashResult.toString === 'function') {
            return hashResult.toString('hex');
          }

          if (hashResult && typeof hashResult.length === 'number') {
            return Array.from(hashResult, (b) => b.toString(16).padStart(2, '0')).join('');
          }

          throw new Error('Unexpected hash result format');
        } catch (e) {
          throw new Error(`${algo} hashing failed: ${e.message}`);
        }
      }

      const crypto = requireWebCrypto();
      const bytes = textEncoder.encode(data);

      switch (algo) {
        case 'SHA256': {
          const hash = await crypto.subtle.digest('SHA-256', bytes);
          return bytesToHex(new Uint8Array(hash));
        }
        case 'SHA512': {
          const hash = await crypto.subtle.digest('SHA-512', bytes);
          return bytesToHex(new Uint8Array(hash));
        }
        case 'RIPEMD160':
          throw new Error('RIPEMD160 not supported without BSV library');
        default:
          throw new Error(`Unsupported hash algorithm: ${algo}`);
      }
    },

    async signMessage(message, wif) {
      const privateKey = bsv.PrivateKey.fromWIF(wif);
      return bsv.Message(message).sign(privateKey);
    },

    async verifySignature(message, signature, publicKeyHex) {
      try {
        const publicKey = bsv.PublicKey.fromString(publicKeyHex);
        const address = bsv.Address.fromPublicKey(publicKey);
        return bsv.Message(message).verify(address, signature);
      } catch {
        return false;
      }
    },

    async exportBackup({ mnemonic, identity, idPath, password }) {
      if (!mnemonic) throw new Error('Mnemonic is required');
      if (!identity?.wif) throw new Error('Identity with WIF is required');
      if (!password) throw new Error('Password is required');

      return {
        createdAt: new Date().toISOString(),
        idPath,
        encMnemonic: await this.encrypt(mnemonic, password),
        encWif: await this.encrypt(identity.wif, password),
        pubKey: identity.publicKey,
        address: identity.address,
      };
    },

    async openBackup(backup, password) {
      if (!backup || typeof backup !== 'object') {
        throw new Error('Backup object is required');
      }

      if (!backup.encMnemonic || !backup.encWif) {
        throw new Error('Backup missing encrypted fields');
      }

      const mnemonic = await this.decrypt(backup.encMnemonic, password);
      const wif = await this.decrypt(backup.encWif, password);
      const identity = this.identityFromWif(wif);

      return {
        mnemonic,
        identity,
        idPath: backup.idPath,
        createdAt: backup.createdAt,
        pubKeyMatchesBackup: !backup.pubKey || backup.pubKey === identity.publicKey,
        addressMatchesBackup: !backup.address || backup.address === identity.address,
      };
    },

    testCryptoAvailability() {
      const result = {
        nodeCrypto: {
          available: false,
          createHmacType: null,
          error: null,
        },
        bsvCrypto: {
          available: !!(bsv?.crypto?.Hash),
          sha256Type: typeof bsv?.crypto?.Hash?.sha256,
          sha512Type: typeof bsv?.crypto?.Hash?.sha512,
          sha256hmacType: typeof bsv?.crypto?.Hash?.sha256hmac,
          sha512hmacType: typeof bsv?.crypto?.Hash?.sha512hmac,
          hmacTest: null,
          error: null,
        },
        mnemonic: {
          available: !!MnemonicClass,
          generatedPreview: null,
          error: null,
        },
      };

      if (typeof require !== 'undefined') {
        try {
          const crypto = require('crypto');
          result.nodeCrypto.available = !!crypto;
          result.nodeCrypto.createHmacType = typeof crypto?.createHmac;
        } catch (e) {
          result.nodeCrypto.error = e.message;
        }
      }

      if (bsv?.crypto?.Hash) {
        try {
          const Buffer = requireBuffer();
          const testData = Buffer.from('test');
          const testKey = Buffer.from('key');
          const hmacResult = bsv.crypto.Hash.sha512hmac(testData, testKey);
          result.bsvCrypto.hmacTest = {
            ok: true,
            byteLength: hmacResult.length,
          };
        } catch (e) {
          result.bsvCrypto.hmacTest = { ok: false };
          result.bsvCrypto.error = e.message;
        }
      }

      try {
        const MC = requireMnemonic();
        const mnemonic = MC.fromRandom(128);
        result.mnemonic.generatedPreview = mnemonic.phrase.split(' ').slice(0, 3).join(' ');
      } catch (e) {
        result.mnemonic.error = e.message;
      }

      return result;
    },
  };
}
