// models/Organization.js
import { DataTypes, Model, Op } from 'sequelize';
import encryptionService from '../services/encryptionService.js';

class Organization extends Model {
  static init(sequelize) {
    return super.init(
      {
        id: {
          type: DataTypes.INTEGER,
          primaryKey: true,
          autoIncrement: true
        },
        name_encrypted: {
          type: DataTypes.TEXT,
          allowNull: false
        },
        type_encrypted: {
          type: DataTypes.TEXT,
          allowNull: true,
          comment: 'company, nonprofit, government, etc.'
        },
        registration_number_encrypted: {
          type: DataTypes.TEXT,
          allowNull: true
        },
        website: {
          type: DataTypes.STRING(255),
          allowNull: true,
          validate: {
            isUrl: {
              msg: 'Website must be a valid URL'
            }
          }
        },
        verification_status: {
          type: DataTypes.ENUM('pending', 'verified', 'rejected'),
          allowNull: false,
          defaultValue: 'pending',
          validate: {
            isIn: {
              args: [['pending', 'verified', 'rejected']],
              msg: 'Verification status must be pending, verified, or rejected'
            }
          }
        },
        created_by: {
          type: DataTypes.INTEGER,
          allowNull: false,
          references: {
            model: 'vottery_users',
            key: 'id'
          }
        },
        // Virtual fields for decrypted data
        name: {
          type: DataTypes.VIRTUAL,
          get() {
            return this.decryptField('name_encrypted');
          },
          set(value) {
            this.encryptField('name_encrypted', value);
          }
        },
        type: {
          type: DataTypes.VIRTUAL,
          get() {
            return this.decryptField('type_encrypted');
          },
          set(value) {
            this.encryptField('type_encrypted', value);
          }
        },
        registrationNumber: {
          type: DataTypes.VIRTUAL,
          get() {
            return this.decryptField('registration_number_encrypted');
          },
          set(value) {
            this.encryptField('registration_number_encrypted', value);
          }
        },
        // Computed virtual fields
        isVerified: {
          type: DataTypes.VIRTUAL,
          get() {
            return this.verification_status === 'verified';
          }
        },
        isPending: {
          type: DataTypes.VIRTUAL,
          get() {
            return this.verification_status === 'pending';
          }
        },
        isRejected: {
          type: DataTypes.VIRTUAL,
          get() {
            return this.verification_status === 'rejected';
          }
        }
      },
      {
        sequelize,
        modelName: 'Organization',
        tableName: 'organizations',
        timestamps: true,
        createdAt: 'created_at',
        updatedAt: 'updated_at',
        indexes: [
          {
            fields: ['created_by']
          },
          {
            fields: ['verification_status']
          },
          {
            fields: ['created_at']
          }
        ]
      }
    );
  }

  // Instance method to encrypt a field
  async encryptField(fieldName, value) {
    try {
      if (!value) {
        this.setDataValue(fieldName, null);
        return;
      }

      // Get organization's encryption key
      const orgKey = await this.getOrganizationEncryptionKey();
      const encryptedValue = encryptionService.encryptRSA(value, orgKey.publicKey);
      this.setDataValue(fieldName, encryptedValue);
    } catch (error) {
      throw new Error(`Encryption failed for ${fieldName}: ${error.message}`);
    }
  }

  // Instance method to decrypt a field
  decryptField(fieldName) {
    try {
      const encryptedValue = this.getDataValue(fieldName);
      if (!encryptedValue) return null;

      // Cache decrypted values to avoid infinite loops
      const cacheKey = `_decrypted_${fieldName}`;
      if (this[cacheKey] !== undefined) {
        return this[cacheKey];
      }

      // In production, implement proper key management and decryption
      this[cacheKey] = null; // Placeholder until key management is implemented
      return this[cacheKey];
    } catch (error) {
      console.error(`Decryption failed for ${fieldName}:`, error.message);
      return null;
    }
  }

  // Get organization's encryption key
  async getOrganizationEncryptionKey() {
    // This will be implemented when we create the EncryptionKey model
    return encryptionService.generateRSAKeyPair();
  }

  // Instance method to verify organization
  async verify() {
    try {
      this.verification_status = 'verified';
      await this.save();
      return this;
    } catch (error) {
      throw new Error(`Organization verification failed: ${error.message}`);
    }
  }

  // Instance method to reject organization
  async reject() {
    try {
      this.verification_status = 'rejected';
      await this.save();
      return this;
    } catch (error) {
      throw new Error(`Organization rejection failed: ${error.message}`);
    }
  }

  // Instance method to add member to organization
  async addMember(userId, role = 'member') {
    try {
      const OrganizationMember = this.sequelize.models.OrganizationMember;
      
      // Check if user is already a member
      const existingMember = await OrganizationMember.findOne({
        where: {
          organization_id: this.id,
          user_id: userId
        }
      });

      if (existingMember) {
        throw new Error('User is already a member of this organization');
      }

      const member = await OrganizationMember.create({
        organization_id: this.id,
        user_id: userId,
        role
      });

      return member;
    } catch (error) {
      throw new Error(`Failed to add member: ${error.message}`);
    }
  }

  // Instance method to remove member from organization
  async removeMember(userId) {
    try {
      const OrganizationMember = this.sequelize.models.OrganizationMember;
      
      const deleted = await OrganizationMember.destroy({
        where: {
          organization_id: this.id,
          user_id: userId
        }
      });

      if (!deleted) {
        throw new Error('Member not found in organization');
      }

      return true;
    } catch (error) {
      throw new Error(`Failed to remove member: ${error.message}`);
    }
  }

  // Instance method to get all members
  async getMembers() {
    try {
      const OrganizationMember = this.sequelize.models.OrganizationMember;
      
      return await OrganizationMember.findAll({
        where: { organization_id: this.id },
        include: [
          {
            model: this.sequelize.models.VotteryUser,
            as: 'user',
            include: [
              {
                model: this.sequelize.models.UserProfile,
                as: 'profile'
              }
            ]
          }
        ]
      });
    } catch (error) {
      throw new Error(`Failed to get organization members: ${error.message}`);
    }
  }

  // Instance method to check if user is member
  async isMember(userId) {
    try {
      const OrganizationMember = this.sequelize.models.OrganizationMember;
      
      const member = await OrganizationMember.findOne({
        where: {
          organization_id: this.id,
          user_id: userId
        }
      });

      return !!member;
    } catch (error) {
      throw new Error(`Failed to check membership: ${error.message}`);
    }
  }

  // Instance method to check if user is owner
  async isOwner(userId) {
    try {
      const OrganizationMember = this.sequelize.models.OrganizationMember;
      
      const member = await OrganizationMember.findOne({
        where: {
          organization_id: this.id,
          user_id: userId,
          role: 'owner'
        }
      });

      return !!member;
    } catch (error) {
      throw new Error(`Failed to check ownership: ${error.message}`);
    }
  }

  // Get public organization data
  getPublicData() {
    return {
      id: this.id,
      name: this.name,
      type: this.type,
      website: this.website,
      verification_status: this.verification_status,
      isVerified: this.isVerified,
      created_at: this.created_at
    };
  }

  // Get private organization data (for members/owners)
  getPrivateData() {
    return {
      id: this.id,
      name: this.name,
      type: this.type,
      registrationNumber: this.registrationNumber,
      website: this.website,
      verification_status: this.verification_status,
      isVerified: this.isVerified,
      isPending: this.isPending,
      isRejected: this.isRejected,
      created_by: this.created_by,
      created_at: this.created_at,
      updated_at: this.updated_at
    };
  }

  // Static method to create organization
  static async createOrganization(userId, organizationData) {
    try {
      const organization = await this.create({
        name: organizationData.name,
        type: organizationData.type,
        registrationNumber: organizationData.registrationNumber,
        website: organizationData.website,
        created_by: userId
      });

      // Add creator as owner
      await organization.addMember(userId, 'owner');

      return organization;
    } catch (error) {
      throw new Error(`Organization creation failed: ${error.message}`);
    }
  }

  // Static method to find organizations by user
  static async findByUser(userId) {
    try {
      const OrganizationMember = this.sequelize.models.OrganizationMember;
      
      const membershipRecords = await OrganizationMember.findAll({
        where: { user_id: userId },
        include: [
          {
            model: this,
            as: 'organization'
          }
        ]
      });

      return membershipRecords.map(record => ({
        organization: record.organization,
        role: record.role,
        joined_at: record.joined_at
      }));
    } catch (error) {
      throw new Error(`Failed to find user organizations: ${error.message}`);
    }
  }

  // Static method to find verified organizations
  static async findVerified(limit = 50, offset = 0) {
    try {
      return await this.findAndCountAll({
        where: { verification_status: 'verified' },
        limit,
        offset,
        order: [['created_at', 'DESC']]
      });
    } catch (error) {
      throw new Error(`Failed to find verified organizations: ${error.message}`);
    }
  }

  // Static method to find pending verification organizations
  static async findPendingVerification(limit = 50, offset = 0) {
    try {
      return await this.findAndCountAll({
        where: { verification_status: 'pending' },
        limit,
        offset,
        order: [['created_at', 'ASC']]
      });
    } catch (error) {
      throw new Error(`Failed to find pending organizations: ${error.message}`);
    }
  }

  // Static method to search organizations
  static async searchOrganizations(query, options = {}) {
    try {
      const {
        limit = 20,
        offset = 0,
        verificationStatus = null,
        organizationType = null
      } = options;

      const whereClause = {};
      
      if (verificationStatus) {
        whereClause.verification_status = verificationStatus;
      }

      // Note: In production, you'd need to implement encrypted search
      // This is a simplified version
      
      return await this.findAndCountAll({
        where: whereClause,
        limit,
        offset,
        order: [['created_at', 'DESC']]
      });
    } catch (error) {
      throw new Error(`Organization search failed: ${error.message}`);
    }
  }

  // Define associations
  static associate(models) {
    Organization.belongsTo(models.VotteryUser, {
      foreignKey: 'created_by',
      as: 'creator'
    });

    Organization.hasMany(models.OrganizationMember, {
      foreignKey: 'organization_id',
      as: 'members'
    });
  }
}

export default Organization;