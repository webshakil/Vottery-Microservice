export class WebAuthnChallenge {
    constructor(data) {
      this.user_id = data.user_id;
      this.device_id = data.device_id || 0;
      this.challenge = data.challenge;
      this.expires_at = data.expires_at;
      this.created_at = data.created_at;
    }
  
    static get tableName() {
      return 'vottery_webauthn_challenges';
    }
  
    static get columns() {
      return ['user_id', 'device_id', 'challenge', 'expires_at', 'created_at'];
    }
  
    toJSON() {
      return {
        userId: this.user_id,
        deviceId: this.device_id,
        challenge: this.challenge,
        expiresAt: this.expires_at,
        createdAt: this.created_at
      };
    }
  
    isExpired() {
      return new Date() > new Date(this.expires_at);
    }
  
    static createExpiryDate(minutesFromNow = 5) {
      return new Date(Date.now() + minutesFromNow * 60 * 1000);
    }
  }
  
  // biometric-service/src/models/User.js
  // Referenced table from main application - basic model for reference
  export class User {
    constructor(data) {
      this.id = data.id;
      this.email = data.email;
      this.first_name = data.first_name;
      this.last_name = data.last_name;
      this.is_active = data.is_active;
      this.created_at = data.created_at;
      this.updated_at = data.updated_at;
    }
  
    static get tableName() {
      return 'vottery_users';
    }
  
    static get columns() {
      return [
        'id', 'email', 'first_name', 'last_name', 
        'is_active', 'created_at', 'updated_at'
      ];
    }
  
    toJSON() {
      return {
        id: this.id,
        email: this.email,
        firstName: this.first_name,
        lastName: this.last_name,
        isActive: this.is_active,
        createdAt: this.created_at,
        updatedAt: this.updated_at
      };
    }
  
    getFullName() {
      return `${this.first_name} ${this.last_name}`.trim();
    }
  }