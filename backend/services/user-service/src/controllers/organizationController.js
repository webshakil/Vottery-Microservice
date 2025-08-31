import { Op } from 'sequelize';
import { 
  Organization, 
  OrganizationMember, 
  VotteryUser, 
  UserProfile,
  Subscription 
} from '../models/index.js';
import { organizationService } from '../services/organizationService.js';
import { auditService } from '../services/auditService.js';
import { validateInput } from '../middleware/validation.js';
import { ApiResponse } from '../utils/response.js';
import { logger } from '../utils/logger.js';
import { USER_ACTIONS, HTTP_STATUS, ORG_ROLES } from '../utils/constants.js';

class OrganizationController {
  /**
   * Create organization
   */
  async createOrganization(req, res, next) {
    try {
      const userId = req.user.id;
      const organizationData = req.body;

      // Validate input
      const validation = validateInput(organizationData, 'createOrganization');
      if (!validation.isValid) {
        return ApiResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
      }

      // Check if user can create organizations
      const userProfile = await UserProfile.findOne({ where: { user_id: userId } });
      if (userProfile.account_type !== 'organization' && userProfile.subscription_status === 'free') {
        return ApiResponse.error(res, 'Upgrade to create organizations', HTTP_STATUS.FORBIDDEN);
      }

      // Generate unique slug
      const baseSlug = organizationData.name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
      let slug = baseSlug;
      let counter = 1;

      while (await Organization.findOne({ where: { slug } })) {
        slug = `${baseSlug}-${counter}`;
        counter++;
      }

      // Create organization
      const organization = await Organization.create({
        ...organizationData,
        slug,
        created_by: userId
      });

      // Add creator as owner
      await OrganizationMember.create({
        organization_id: organization.id,
        user_id: userId,
        role: 'owner',
        status: 'active',
        joined_at: new Date(),
        permissions: {
          can_create_elections: true,
          can_invite_members: true,
          can_manage_settings: true,
          can_view_analytics: true
        }
      });

      // Update member count
      await organization.update({ member_count: 1 });

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.ORG_CREATE,
        category: 'organization',
        severity: 'medium',
        resource_type: 'organization',
        resource_id: organization.id,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        new_values: organization.toJSON()
      });

      return ApiResponse.success(res, organization, 'Organization created successfully', HTTP_STATUS.CREATED);

    } catch (error) {
      logger.error('Error creating organization:', error);
      return next(error);
    }
  }

  /**
   * Get organization by ID
   */
  async getOrganization(req, res, next) {
    try {
      const { organizationId } = req.params;
      const userId = req.user.id;

      const organization = await Organization.findByPk(organizationId, {
        include: [{
          model: OrganizationMember,
          as: 'members',
          include: [{
            model: VotteryUser,
            as: 'user',
            include: [{
              model: UserProfile,
              as: 'profile',
              attributes: ['public_display_name', 'avatar_url']
            }]
          }],
          where: { status: 'active' },
          required: false
        }]
      });

      if (!organization) {
        return ApiResponse.error(res, 'Organization not found', HTTP_STATUS.NOT_FOUND);
      }

      // Check access permissions
      const membership = await OrganizationMember.findOne({
        where: {
          organization_id: organizationId,
          user_id: userId,
          status: 'active'
        }
      });

      // If not a member and organization settings require membership
      if (!membership && !organization.settings.privacy.member_list_visible) {
        // Only show public info
        const publicOrg = {
          id: organization.id,
          name: organization.name,
          description: organization.description,
          logo_url: organization.logo_url,
          website: organization.website,
          industry: organization.industry,
          organization_type: organization.organization_type,
          verification_status: organization.verification_status,
          member_count: organization.member_count
        };
        return ApiResponse.success(res, publicOrg, 'Organization retrieved successfully');
      }

      return ApiResponse.success(res, organization, 'Organization retrieved successfully');

    } catch (error) {
      logger.error('Error getting organization:', error);
      return next(error);
    }
  }

  /**
   * Update organization
   */
  async updateOrganization(req, res, next) {
    try {
      const { organizationId } = req.params;
      const userId = req.user.id;
      const updateData = req.body;

      // Check permissions
      const membership = await OrganizationMember.findOne({
        where: {
          organization_id: organizationId,
          user_id: userId,
          status: 'active',
          role: { [Op.in]: ['owner', 'admin'] }
        }
      });

      if (!membership && !req.user.hasPermission('organization.manage')) {
        return ApiResponse.error(res, 'Insufficient permissions', HTTP_STATUS.FORBIDDEN);
      }

      const organization = await Organization.findByPk(organizationId);

      if (!organization) {
        return ApiResponse.error(res, 'Organization not found', HTTP_STATUS.NOT_FOUND);
      }

      // Validate input
      const validation = validateInput(updateData, 'updateOrganization');
      if (!validation.isValid) {
        return ApiResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
      }

      const oldValues = organization.toJSON();
      await organization.update(updateData);

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.ORG_UPDATE,
        category: 'organization',
        severity: 'medium',
        resource_type: 'organization',
        resource_id: organizationId,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        old_values: oldValues,
        new_values: updateData
      });

      return ApiResponse.success(res, organization, 'Organization updated successfully');

    } catch (error) {
      logger.error('Error updating organization:', error);
      return next(error);
    }
  }

  /**
   * Delete organization
   */
  async deleteOrganization(req, res, next) {
    try {
      const { organizationId } = req.params;
      const userId = req.user.id;

      // Check if user is owner
      const ownership = await OrganizationMember.findOne({
        where: {
          organization_id: organizationId,
          user_id: userId,
          status: 'active',
          role: 'owner'
        }
      });

      if (!ownership && !req.user.hasPermission('organization.delete')) {
        return ApiResponse.error(res, 'Only organization owner can delete', HTTP_STATUS.FORBIDDEN);
      }

      const organization = await Organization.findByPk(organizationId);

      if (!organization) {
        return ApiResponse.error(res, 'Organization not found', HTTP_STATUS.NOT_FOUND);
      }

      // Check for active subscriptions
      const activeSubscription = await Subscription.findOne({
        where: {
          organization_id: organizationId,
          status: 'active'
        }
      });

      if (activeSubscription) {
        return ApiResponse.error(res, 'Cancel subscription before deleting organization', HTTP_STATUS.CONFLICT);
      }

      await organization.destroy();

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.ORG_DELETE,
        category: 'organization',
        severity: 'critical',
        resource_type: 'organization',
        resource_id: organizationId,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { deleted_organization: organization.toJSON() }
      });

      return ApiResponse.success(res, null, 'Organization deleted successfully');

    } catch (error) {
      logger.error('Error deleting organization:', error);
      return next(error);
    }
  }

  /**
   * Invite member to organization
   */
  async inviteMember(req, res, next) {
    try {
      const { organizationId } = req.params;
      const { user_email, role = 'member', permissions } = req.body;
      const userId = req.user.id;

      // Check permissions
      const membership = await OrganizationMember.findOne({
        where: {
          organization_id: organizationId,
          user_id: userId,
          status: 'active',
          role: { [Op.in]: ['owner', 'admin'] }
        }
      });

      if (!membership || !membership.permissions.can_invite_members) {
        return ApiResponse.error(res, 'Insufficient permissions to invite members', HTTP_STATUS.FORBIDDEN);
      }

      // Find user by email
      const invitedUser = await VotteryUser.findOne({ where: { email: user_email } });
      if (!invitedUser) {
        return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
      }

      // Check if user is already a member
      const existingMembership = await OrganizationMember.findOne({
        where: {
          organization_id: organizationId,
          user_id: invitedUser.id
        }
      });

      if (existingMembership) {
        return ApiResponse.error(res, 'User is already a member', HTTP_STATUS.CONFLICT);
      }

      // Check organization member limits
      const organization = await Organization.findByPk(organizationId);
      if (organization.max_members && organization.member_count >= organization.max_members) {
        return ApiResponse.error(res, 'Organization member limit reached', HTTP_STATUS.FORBIDDEN);
      }

      // Create member invitation
      const memberInvitation = await OrganizationMember.create({
        organization_id: organizationId,
        user_id: invitedUser.id,
        role,
        status: 'pending',
        invited_by: userId,
        permissions: permissions || {
          can_create_elections: role === 'admin' || role === 'moderator',
          can_invite_members: role === 'admin',
          can_manage_settings: role === 'admin',
          can_view_analytics: role === 'admin' || role === 'moderator'
        }
      });

      // TODO: Send invitation email

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.ORG_INVITE,
        category: 'organization',
        severity: 'low',
        resource_type: 'organization_member',
        resource_id: memberInvitation.id,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: {
          organization_id: organizationId,
          invited_user_id: invitedUser.id,
          invited_user_email: user_email,
          role
        }
      });

      return ApiResponse.success(res, memberInvitation, 'Member invited successfully', HTTP_STATUS.CREATED);

    } catch (error) {
      logger.error('Error inviting member:', error);
      return next(error);
    }
  }

  /**
   * Accept organization invitation
   */
  async acceptInvitation(req, res, next) {
    try {
      const { organizationId } = req.params;
      const userId = req.user.id;

      const membership = await OrganizationMember.findOne({
        where: {
          organization_id: organizationId,
          user_id: userId,
          status: 'pending'
        }
      });

      if (!membership) {
        return ApiResponse.error(res, 'Invitation not found', HTTP_STATUS.NOT_FOUND);
      }

      await membership.update({
        status: 'active',
        joined_at: new Date()
      });

      // Update organization member count
      const organization = await Organization.findByPk(organizationId);
      await organization.increment('member_count');

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.ORG_JOIN,
        category: 'organization',
        severity: 'low',
        resource_type: 'organization_member',
        resource_id: membership.id,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { organization_id: organizationId }
      });

      return ApiResponse.success(res, membership, 'Invitation accepted successfully');

    } catch (error) {
      logger.error('Error accepting invitation:', error);
      return next(error);
    }
  }

  /**
   * Leave organization
   */
  async leaveOrganization(req, res, next) {
    try {
      const { organizationId } = req.params;
      const userId = req.user.id;

      const membership = await OrganizationMember.findOne({
        where: {
          organization_id: organizationId,
          user_id: userId,
          status: 'active'
        }
      });

      if (!membership) {
        return ApiResponse.error(res, 'Membership not found', HTTP_STATUS.NOT_FOUND);
      }

      // Prevent owner from leaving if there are other members
      if (membership.role === 'owner') {
        const otherMembers = await OrganizationMember.count({
          where: {
            organization_id: organizationId,
            user_id: { [Op.ne]: userId },
            status: 'active'
          }
        });

        if (otherMembers > 0) {
          return ApiResponse.error(res, 'Transfer ownership before leaving', HTTP_STATUS.FORBIDDEN);
        }
      }

      await membership.update({
        status: 'inactive',
        left_at: new Date()
      });

      // Update organization member count
      const organization = await Organization.findByPk(organizationId);
      await organization.decrement('member_count');

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.ORG_LEAVE,
        category: 'organization',
        severity: 'low',
        resource_type: 'organization_member',
        resource_id: membership.id,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { organization_id: organizationId }
      });

      return ApiResponse.success(res, null, 'Left organization successfully');

    } catch (error) {
      logger.error('Error leaving organization:', error);
      return next(error);
    }
  }

  /**
   * Remove member from organization
   */
  async removeMember(req, res, next) {
    try {
      const { organizationId, memberId } = req.params;
      const userId = req.user.id;

      // Check permissions
      const requesterMembership = await OrganizationMember.findOne({
        where: {
          organization_id: organizationId,
          user_id: userId,
          status: 'active',
          role: { [Op.in]: ['owner', 'admin'] }
        }
      });

      if (!requesterMembership) {
        return ApiResponse.error(res, 'Insufficient permissions', HTTP_STATUS.FORBIDDEN);
      }

      const targetMembership = await OrganizationMember.findByPk(memberId);

      if (!targetMembership || targetMembership.organization_id !== organizationId) {
        return ApiResponse.error(res, 'Member not found', HTTP_STATUS.NOT_FOUND);
      }

      // Prevent removing owner unless requester is also owner
      if (targetMembership.role === 'owner' && requesterMembership.role !== 'owner') {
        return ApiResponse.error(res, 'Cannot remove organization owner', HTTP_STATUS.FORBIDDEN);
      }

      // Prevent self-removal (use leave endpoint instead)
      if (targetMembership.user_id === userId) {
        return ApiResponse.error(res, 'Use leave organization endpoint', HTTP_STATUS.BAD_REQUEST);
      }

      await targetMembership.update({
        status: 'inactive',
        left_at: new Date()
      });

      // Update organization member count
      const organization = await Organization.findByPk(organizationId);
      await organization.decrement('member_count');

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.ORG_REMOVE_MEMBER,
        category: 'organization',
        severity: 'medium',
        resource_type: 'organization_member',
        resource_id: memberId,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: {
          organization_id: organizationId,
          removed_user_id: targetMembership.user_id
        }
      });

      return ApiResponse.success(res, null, 'Member removed successfully');

    } catch (error) {
      logger.error('Error removing member:', error);
      return next(error);
    }
  }

  /**
   * Update member role
   */
  async updateMemberRole(req, res, next) {
    try {
      const { organizationId, memberId } = req.params;
      const { role, permissions } = req.body;
      const userId = req.user.id;

      // Check permissions
      const requesterMembership = await OrganizationMember.findOne({
        where: {
          organization_id: organizationId,
          user_id: userId,
          status: 'active',
          role: 'owner' // Only owners can update roles
        }
      });

      if (!requesterMembership && !req.user.hasPermission('organization.manage')) {
        return ApiResponse.error(res, 'Only organization owner can update roles', HTTP_STATUS.FORBIDDEN);
      }

      const targetMembership = await OrganizationMember.findByPk(memberId);

      if (!targetMembership || targetMembership.organization_id !== organizationId) {
        return ApiResponse.error(res, 'Member not found', HTTP_STATUS.NOT_FOUND);
      }

      // Prevent changing own role
      if (targetMembership.user_id === userId) {
        return ApiResponse.error(res, 'Cannot change your own role', HTTP_STATUS.FORBIDDEN);
      }

      const oldRole = targetMembership.role;
      const oldPermissions = targetMembership.permissions;

      await targetMembership.update({
        role,
        permissions: permissions || targetMembership.permissions
      });

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.ORG_UPDATE_ROLE,
        category: 'organization',
        severity: 'medium',
        resource_type: 'organization_member',
        resource_id: memberId,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        old_values: { role: oldRole, permissions: oldPermissions },
        new_values: { role, permissions }
      });

      return ApiResponse.success(res, targetMembership, 'Member role updated successfully');

    } catch (error) {
      logger.error('Error updating member role:', error);
      return next(error);
    }
  }

  /**
   * Get user organizations
   */
  async getUserOrganizations(req, res, next) {
    try {
      const userId = req.user.id;

      const memberships = await OrganizationMember.findAll({
        where: {
          user_id: userId,
          status: { [Op.in]: ['active', 'pending'] }
        },
        include: [{
          model: Organization,
          as: 'organization'
        }],
        order: [['joined_at', 'DESC']]
      });

      return ApiResponse.success(res, memberships, 'User organizations retrieved successfully');

    } catch (error) {
      logger.error('Error getting user organizations:', error);
      return next(error);
    }
  }
}

export default new OrganizationController();