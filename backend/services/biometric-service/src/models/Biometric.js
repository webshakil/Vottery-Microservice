export class Biometric {
    constructor(data) {
      this.id = data.id;
      this.user_id = data.user_id;
      this.device_id = data.device_id;
      this.biometric_type = data.biometric_type;
      this.biometric_hash = data.biometric_hash;
      this.public_key = data.public_key;
      this.credential_id = data.credential_id;
      this.is_active = data.is_active || true;
      this.created_at = data.created_at;
      this.updated_at = data.updated_at;
      
      // Join fields from devices table
      this.device_type = data.device_type;
    }
  
    static get tableName() {
      return 'vottery_biometrics';
    }
  
    static get columns() {
      return [
        'id', 'user_id', 'device_id', 'biometric_type', 
        'biometric_hash', 'public_key', 'credential_id',
        'is_active', 'created_at', 'updated_at'
      ];
    }
  
    static get biometricTypes() {
      return ['fingerprint', 'face', 'voice', 'iris', 'webauthn'];
    }
  
    toJSON() {
      return {
        id: this.id,
        userId: this.user_id,
        deviceId: this.device_id,
        type: this.biometric_type,
        hash: this.biometric_hash,
        publicKey: this.public_key,
        credentialId: this.credential_id,
        isActive: this.is_active,
        deviceType: this.device_type,
        createdAt: this.created_at,
        updatedAt: this.updated_at
      };
    }
  
    isWebAuthn() {
      return this.biometric_type === 'webauthn';
    }
  
    hasCredentials() {
      return !!(this.public_key && this.credential_id);
    }
  }