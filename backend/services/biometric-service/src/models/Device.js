





// biometric-service/src/models/Device.js
export class Device {
    constructor(data) {
      this.id = data.id;
      this.user_id = data.user_id;
      this.device_fingerprint = data.device_fingerprint;
      this.device_type = data.device_type;
      this.browser_name = data.browser_name;
      this.browser_version = data.browser_version;
      this.os_name = data.os_name;
      this.os_version = data.os_version;
      this.screen_info = data.screen_info;
      this.ip_address = data.ip_address;
      this.location = data.location;
      this.capabilities = data.capabilities;
      this.device_details = data.device_details;
      this.trust_score = data.trust_score || 50;
      this.is_active = data.is_active || true;
      this.last_used = data.last_used;
      this.created_at = data.created_at;
      this.updated_at = data.updated_at;
    }
  
    static get tableName() {
      return 'vottery_devices';
    }
  
    static get columns() {
      return [
        'id', 'user_id', 'device_fingerprint', 'device_type', 
        'browser_name', 'browser_version', 'os_name', 'os_version',
        'screen_info', 'ip_address', 'location', 'capabilities',
        'device_details', 'trust_score', 'is_active', 'last_used',
        'created_at', 'updated_at'
      ];
    }
  
    toJSON() {
      return {
        id: this.id,
        userId: this.user_id,
        fingerprint: this.device_fingerprint,
        type: this.device_type,
        browser: {
          name: this.browser_name,
          version: this.browser_version
        },
        os: {
          name: this.os_name,
          version: this.os_version
        },
        screenInfo: this.screen_info,
        ipAddress: this.ip_address,
        location: this.location,
        capabilities: this.capabilities,
        deviceDetails: this.device_details,
        trustScore: this.trust_score,
        isActive: this.is_active,
        lastUsed: this.last_used,
        createdAt: this.created_at,
        updatedAt: this.updated_at
      };
    }
  }