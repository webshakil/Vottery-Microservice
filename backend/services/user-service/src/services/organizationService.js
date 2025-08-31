// services/organizationService.js
import Organization from '../models/Organization.js';
import OrganizationMember from '../models/OrganizationMember.js';
import VotteryUser from '../models/VotteryUser.js';
import encryptionService from './encryptionService.js';
import auditService from './auditService.js';
import { AppError } from '../utils/response.js';
import { ORGANIZATION_ROLES, VERIFICATION_STATUS } from '../utils/constants.js';

class OrganizationService {
  /**
   * Create new organization
   * @param {object} orgData 
   * @param {number} createdBy 
   * @returns {Promise<object>}
   */
  async createOrganization(orgData, createdBy) {
    try {
      const { name, type, registrationNumber, website } = orgData;

      // Encrypt sensitive data
      const encryptedData = {
        name_encrypted: await encryptionService.encrypt(name),
        type_encrypted: type ? await encryptionService.encrypt(type) : null,
        registration_number_encrypted: registrationNumber ? 
          await encryptionService.encrypt(registrationNumber) : null
      };

      // Create organization
      const organization = await Organization.create({
        ...encryptedData,
        website,
        verification_status: VERIFICATION_STATUS.PENDING,
        created_by: createdBy
      });

      // Add creator as owner
      await OrganizationMember.create({
        organization_id: organization.id,
        user_id: createdBy,
        role: ORGANIZATION_ROLES.OWNER
      });

      // Log activity
      await auditService.logActivity(
        createdBy,
        'ORGANIZATION_CREATE',
        'organization',
        organization.id,
        {
          organization_name: name,
          created_by: createdBy
        }
      );

      return await this.getDecryptedOrganization(organization.id);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Get organization by ID with decrypted data
   * @param {number} orgId 
   * @returns {Promise<object>}
   */
  async getOrganizationById(orgId) {
    try {
      const organization = await Organization.findByPk(orgId, {
        include: [{
          model: OrganizationMember,
          as: 'members',
          include: [{
            model: VotteryUser,
            as: 'user',
            attributes: ['id', 'email', 'username']
          }]
        }]
      });

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      return await this.getDecryptedOrganization(orgId);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Update organization
   * @param {number} orgId 
   * @param {object} updateData 
   * @param {number} updatedBy 
   * @returns {Promise<object>}
   */
  async updateOrganization(orgId, updateData, updatedBy) {
    try {
      const organization = await Organization.findByPk(orgId);
      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      // Check if user has permission to update
      const member = await this.getOrganizationMember(orgId, updatedBy);
      if (!member || !['owner', 'admin'].includes(member.role)) {
        throw new AppError('Insufficient permissions', 403);
      }

      // Encrypt sensitive fields if they're being updated
      const encryptedData = {};
      if (updateData.name) {
        encryptedData.name_encrypted = await encryptionService.encrypt(updateData.name);
      }
      if (updateData.type) {
        encryptedData.type_encrypted = await encryptionService.encrypt(updateData.type);
      }
      if (updateData.registrationNumber) {
        encryptedData.registration_number_encrypted = 
          await encryptionService.encrypt(updateData.registrationNumber);
      }

      // Update organization
      await organization.update({
        ...encryptedData,
        website: updateData.website !== undefined ? updateData.website : organization.website,
        updated_at: new Date()
      });

      // Log activity
      await auditService.logActivity(
        updatedBy,
        'ORGANIZATION_UPDATE',
        'organization',
        orgId,
        {
          updated_fields: Object.keys(updateData),
          updated_by: updatedBy
        }
      );

      return await this.getDecryptedOrganization(orgId);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Delete organization
   * @param {number} orgId 
   * @param {number} deletedBy 
   * @returns {Promise<boolean>}
   */
  async deleteOrganization(orgId, deletedBy) {
    try {
      const organization = await Organization.findByPk(orgId);
      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      // Check if user is owner
      const member = await this.getOrganizationMember(orgId, deletedBy);
      if (!member || member.role !== ORGANIZATION_ROLES.OWNER) {
        throw new AppError('Only organization owners can delete organizations', 403);
      }

      // Get organization name for logging (before deletion)
      const orgName = await encryptionService.decrypt(organization.name_encrypted);

      // Delete all members first
      await OrganizationMember.destroy({ where: { organization_id: orgId } });

      // Delete organization
      await organization.destroy();

      // Log activity
      await auditService.logActivity(
        deletedBy,
        'ORGANIZATION_DELETE',
        'organization',
        orgId,
        {
          organization_name: orgName,
          deleted_by: deletedBy
        }
      );

      return true;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Add member to organization
   * @param {number} orgId 
   * @param {number} userId 
   * @param {string} role 
   * @param {number} addedBy 
   * @returns {Promise<object>}
   */
  async addMember(orgId, userId, role, addedBy) {
    try {
      // Validate role
      if (!Object.values(ORGANIZATION_ROLES).includes(role)) {
        throw new AppError('Invalid organization role', 400);
      }

      // Check if organization exists
      const organization = await Organization.findByPk(orgId);
      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      // Check if user exists
      const user = await VotteryUser.findByPk(userId);
      if (!user) {
        throw new AppError('User not found', 404);
      }

      // Check if adder has permission
      const adderMember = await this.getOrganizationMember(orgId, addedBy);
      if (!adderMember || !['owner', 'admin'].includes(adderMember.role)) {
        throw new AppError('Insufficient permissions to add members', 403);
      }

      // Check if user is already a member
      const existingMember = await OrganizationMember.findOne({
        where: { organization_id: orgId, user_id: userId }
      });

      if (existingMember) {
        throw new AppError('User is already a member of this organization', 400);
      }

      // Add member
      const member = await OrganizationMember.create({
        organization_id: orgId,
        user_id: userId,
        role
      });

      // Log activity
      await auditService.logActivity(
        addedBy,
        'ORGANIZATION_MEMBER_ADD',
        'organization_member',
        member.id,
        {
          organization_id: orgId,
          user_id: userId,
          role,
          added_by: addedBy
        }
      );

      return await this.getOrganizationMemberById(member.id);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Remove member from organization
   * @param {number} orgId 
   * @param {number} userId 
   * @param {number} removedBy 
   * @returns {Promise<boolean>}
   */
  async removeMember(orgId, userId, removedBy) {
    try {
      const member = await OrganizationMember.findOne({
        where: { organization_id: orgId, user_id: userId }
      });

      if (!member) {
        throw new AppError('Member not found in organization', 404);
      }

      // Check if remover has permission
      const removerMember = await this.getOrganizationMember(orgId, removedBy);
      if (!removerMember) {
        throw new AppError('You are not a member of this organization', 403);
      }

      // Owners can remove anyone, admins can remove regular members
      // Users can only remove themselves
      const canRemove = 
        removerMember.role === ORGANIZATION_ROLES.OWNER ||
        (removerMember.role === ORGANIZATION_ROLES.ADMIN && member.role === ORGANIZATION_ROLES.MEMBER) ||
        removedBy === userId;

      if (!canRemove) {
        throw new AppError('Insufficient permissions to remove this member', 403);
      }

      // Cannot remove the last owner
      if (member.role === ORGANIZATION_ROLES.OWNER) {
        const ownerCount = await OrganizationMember.count({
          where: { organization_id: orgId, role: ORGANIZATION_ROLES.OWNER }
        });

        if (ownerCount <= 1) {
          throw new AppError('Cannot remove the last owner of the organization', 400);
        }
      }

      await member.destroy();

      // Log activity
      await auditService.logActivity(
        removedBy,
        'ORGANIZATION_MEMBER_REMOVE',
        'organization_member',
        member.id,
        {
          organization_id: orgId,
          user_id: userId,
          role: member.role,
          removed_by: removedBy
        }
      );

      return true;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Update member role
   * @param {number} orgId 
   * @param {number} userId 
   * @param {string} newRole 
   * @param {number} updatedBy 
   * @returns {Promise<object>}
   */
  async updateMemberRole(orgId, userId, newRole, updatedBy) {
    try {
      // Validate role
      if (!Object.values(ORGANIZATION_ROLES).includes(newRole)) {
        throw new AppError('Invalid organization role', 400);
      }

      const member = await OrganizationMember.findOne({
        where: { organization_id: orgId, user_id: userId }
      });

      if (!member) {
        throw new AppError('Member not found in organization', 404);
      }

      // Check if updater has permission (only owners can change roles)
      const updaterMember = await this.getOrganizationMember(orgId, updatedBy);
      if (!updaterMember || updaterMember.role !== ORGANIZATION_ROLES.OWNER) {
        throw new AppError('Only organization owners can change member roles', 403);
      }

      // Cannot demote the last owner
      if (member.role === ORGANIZATION_ROLES.OWNER && newRole !== ORGANIZATION_ROLES.OWNER) {
        const ownerCount = await OrganizationMember.count({
          where: { organization_id: orgId, role: ORGANIZATION_ROLES.OWNER }
        });

        if (ownerCount <= 1) {
          throw new AppError('Cannot demote the last owner of the organization', 400);
        }
      }

      const oldRole = member.role;
      await member.update({ role: newRole });

      // Log activity
      await auditService.logActivity(
        updatedBy,
        'ORGANIZATION_MEMBER_ROLE_UPDATE',
        'organization_member',
        member.id,
        {
          organization_id: orgId,
          user_id: userId,
          old_role: oldRole,
          new_role: newRole,
          updated_by: updatedBy
        }
      );

      return await this.getOrganizationMemberById(member.id);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Get organization members
   * @param {number} orgId 
   * @param {number} page 
   * @param {number} limit 
   * @returns {Promise<object>}
   */
  async getOrganizationMembers(orgId, page = 1, limit = 10) {
    try {
      const offset = (page - 1) * limit;

      const { count, rows } = await OrganizationMember.findAndCountAll({
        where: { organization_id: orgId },
        include: [{
          model: VotteryUser,
          as: 'user',
          attributes: ['id', 'email', 'username', 'status', 'created_at']
        }],
        limit,
        offset,
        order: [['joined_at', 'ASC']]
      });

      return {
        members: rows,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(count / limit),
          totalCount: count,
          limit
        }
      };
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Get user's organizations
   * @param {number} userId 
   * @returns {Promise<array>}
   */
  async getUserOrganizations(userId) {
    try {
      const memberships = await OrganizationMember.findAll({
        where: { user_id: userId },
        include: [{
          model: Organization,
          as: 'organization'
        }]
      });

      const organizations = [];
      for (const membership of memberships) {
        const decryptedOrg = await this.decryptOrganizationData(membership.organization);
        organizations.push({
          ...decryptedOrg,
          memberRole: membership.role,
          joinedAt: membership.joined_at
        });
      }

      return organizations;
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Update organization verification status
   * @param {number} orgId 
   * @param {string} status 
   * @param {number} verifiedBy 
   * @returns {Promise<object>}
   */
  async updateVerificationStatus(orgId, status, verifiedBy) {
    try {
      if (!Object.values(VERIFICATION_STATUS).includes(status)) {
        throw new AppError('Invalid verification status', 400);
      }

      const organization = await Organization.findByPk(orgId);
      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      const oldStatus = organization.verification_status;
      await organization.update({ 
        verification_status: status,
        updated_at: new Date()
      });

      // Log activity
      await auditService.logActivity(
        verifiedBy,
        'ORGANIZATION_VERIFICATION_UPDATE',
        'organization',
        orgId,
        {
          old_status: oldStatus,
          new_status: status,
          verified_by: verifiedBy
        }
      );

      return await this.getDecryptedOrganization(orgId);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Search organizations
   * @param {string} searchTerm 
   * @param {object} filters 
   * @param {number} page 
   * @param {number} limit 
   * @returns {Promise<object>}
   */
  async searchOrganizations(searchTerm, filters = {}, page = 1, limit = 10) {
    try {
      const offset = (page - 1) * limit;
      const whereClause = {};

      // Apply filters
      if (filters.verification_status) {
        whereClause.verification_status = filters.verification_status;
      }

      if (filters.created_by) {
        whereClause.created_by = filters.created_by;
      }

      // Get all organizations (need to decrypt names for search)
      const allOrgs = await Organization.findAll({
        where: whereClause,
        include: [{
          model: OrganizationMember,
          as: 'members',
          include: [{
            model: VotteryUser,
            as: 'user',
            attributes: ['id', 'email', 'username']
          }]
        }]
      });

      let filteredOrgs = [];

      // Decrypt and filter
      for (const org of allOrgs) {
        try {
          const decryptedName = await encryptionService.decrypt(org.name_encrypted);
          
          if (!searchTerm || decryptedName.toLowerCase().includes(searchTerm.toLowerCase())) {
            const decryptedOrg = await this.decryptOrganizationData(org);
            filteredOrgs.push(decryptedOrg);
          }
        } catch (error) {
          // Skip organizations with decryption errors
          continue;
        }
      }

      // Apply pagination
      const totalCount = filteredOrgs.length;
      const paginatedOrgs = filteredOrgs.slice(offset, offset + limit);

      return {
        organizations: paginatedOrgs,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(totalCount / limit),
          totalCount,
          limit
        }
      };
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Get organization statistics
   * @returns {Promise<object>}
   */
  async getOrganizationStatistics() {
    try {
      const [
        totalOrgs,
        verifiedOrgs,
        pendingOrgs,
        recentOrgs
      ] = await Promise.all([
        Organization.count(),
        Organization.count({ where: { verification_status: VERIFICATION_STATUS.VERIFIED } }),
        Organization.count({ where: { verification_status: VERIFICATION_STATUS.PENDING } }),
        Organization.count({
          where: {
            created_at: {
              [Op.gte]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
            }
          }
        })
      ]);

      return {
        total: totalOrgs,
        verified: verifiedOrgs,
        pending: pendingOrgs,
        recent: recentOrgs
      };
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  // Helper methods
  
  /**
   * Get organization member
   * @param {number} orgId 
   * @param {number} userId 
   * @returns {Promise<object|null>}
   */
  async getOrganizationMember(orgId, userId) {
    try {
      return await OrganizationMember.findOne({
        where: { organization_id: orgId, user_id: userId }
      });
    } catch (error) {
      return null;
    }
  }

  /**
   * Get organization member by ID
   * @param {number} memberId 
   * @returns {Promise<object>}
   */
  async getOrganizationMemberById(memberId) {
    try {
      const member = await OrganizationMember.findByPk(memberId, {
        include: [{
          model: VotteryUser,
          as: 'user',
          attributes: ['id', 'email', 'username']
        }, {
          model: Organization,
          as: 'organization'
        }]
      });

      if (!member) {
        throw new AppError('Organization member not found', 404);
      }

      // Decrypt organization data
      member.organization = await this.decryptOrganizationData(member.organization);

      return member;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Get decrypted organization data
   * @param {number} orgId 
   * @returns {Promise<object>}
   */
  async getDecryptedOrganization(orgId) {
    try {
      const organization = await Organization.findByPk(orgId, {
        include: [{
          model: OrganizationMember,
          as: 'members',
          include: [{
            model: VotteryUser,
            as: 'user',
            attributes: ['id', 'email', 'username']
          }]
        }]
      });

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      return await this.decryptOrganizationData(organization);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Decrypt organization data
   * @param {object} organization 
   * @returns {Promise<object>}
   */
  async decryptOrganizationData(organization) {
    try {
      const decryptedOrg = { ...organization.toJSON() };

      // Decrypt fields
      if (decryptedOrg.name_encrypted) {
        decryptedOrg.name = await encryptionService.decrypt(decryptedOrg.name_encrypted);
        delete decryptedOrg.name_encrypted;
      }

      if (decryptedOrg.type_encrypted) {
        decryptedOrg.type = await encryptionService.decrypt(decryptedOrg.type_encrypted);
        delete decryptedOrg.type_encrypted;
      }

      if (decryptedOrg.registration_number_encrypted) {
        decryptedOrg.registrationNumber = await encryptionService.decrypt(
          decryptedOrg.registration_number_encrypted
        );
        delete decryptedOrg.registration_number_encrypted;
      }

      return decryptedOrg;
    } catch (error) {
      throw new AppError('Error decrypting organization data', 500);
    }
  }
}

export default new OrganizationService();