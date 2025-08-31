// import { DataTypes, Model } from 'sequelize';

// class VotteryUserRole extends Model {
//   static init(sequelize) {
//     return super.init(
//       {
//         id: {
//           type: DataTypes.UUID,
//           defaultValue: DataTypes.UUIDV4,
//           primaryKey: true,
//           allowNull: false,
//         },
//         user_id: {
//           type: DataTypes.UUID,
//           allowNull: false,
//         },
//         role_id: {
//           type: DataTypes.UUID,
//           allowNull: false,
//         },
//         organization_id: {
//           type: DataTypes.UUID,
//           allowNull: true,
//           comment: 'Role scope - null for global roles',
//         },
//         granted_by: {
//           type: DataTypes.UUID,
//           allowNull: true,
//         },
//         granted_at: {
//           type: DataTypes.DATE,
//           allowNull: false,
//           defaultValue: DataTypes.NOW,
//         },
//         expires_at: {
//           type: DataTypes.DATE,
//           allowNull: true,
//           comment: 'Role expiration date - null for permanent roles',
//         },
//         is_active: {
//           type: DataTypes.BOOLEAN,
//           defaultValue: true,
//           allowNull: false,
//         },
//         conditions: {
//           type: DataTypes.JSON,
//           defaultValue: {},
//           allowNull: false,
//           comment: 'Additional conditions for role activation',
//         },
//         metadata: {
//           type: DataTypes.JSON,
//           defaultValue: {},
//           allowNull: false,
//         },
//       },
//       {
//         sequelize,
//         modelName: 'VotteryUserRole',
//         tableName: 'vottery_user_roles',
//         paranoid: true,
//         indexes: [
//           {
//             unique: true,
//             fields: ['user_id', 'role_id', 'organization_id'],
//             name: 'unique_user_role_org',
//           },
//         ],
//       }
//     );
//   }

//   // Instance methods
//   isExpired() {
//     if (!this.expires_at) {
//       return false;
//     }
//     return new Date() > this.expires_at;
//   }

//   isValid() {
//     return this.is_active && !this.isExpired();
//   }

//   async activate() {
//     this.is_active = true;
//     return await this.save();
//   }

//   async deactivate() {
//     this.is_active = false;
//     return await this.save();
//   }

//   async extend(durationInDays) {
//     if (!this.expires_at) {
//       // If no expiration, set it to duration from now
//       this.expires_at = new Date(Date.now() + durationInDays * 24 * 60 * 60 * 1000);
//     } else {
//       // Extend existing expiration
//       this.expires_at = new Date(this.expires_at.getTime() + durationInDays * 24 * 60 * 60 * 1000);
//     }
//     return await this.save();
//   }

//   async setExpiration(date) {
//     this.expires_at = date;
//     return await this.save();
//   }

//   async removePermanent() {
//     this.expires_at = null;
//     return await this.save();
//   }

//   getDaysUntilExpiration() {
//     if (!this.expires_at) {
//       return null;
//     }
    
//     const now = new Date();
//     const expiration = new Date(this.expires_at);
//     const diffTime = expiration - now;
//     return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
//   }

//   isExpiringWithin(days) {
//     const daysUntilExpiration = this.getDaysUntilExpiration();
//     if (daysUntilExpiration === null) {
//       return false;
//     }
//     return daysUntilExpiration <= days && daysUntilExpiration > 0;
//   }

//   getScope() {
//     return this.organization_id ? 'organization' : 'global';
//   }

//   isGlobal() {
//     return !this.organization_id;
//   }

//   isOrganizationScoped() {
//     return !!this.organization_id;
//   }

//   // Condition checking methods
//   checkConditions(context = {}) {
//     if (!this.conditions || Object.keys(this.conditions).length === 0) {
//       return true;
//     }

//     for (const [condition, value] of Object.entries(this.conditions)) {
//       if (!this.evaluateCondition(condition, value, context)) {
//         return false;
//       }
//     }

//     return true;
//   }

//   evaluateCondition(condition, value, context) {
//     switch (condition) {
//       case 'ip_whitelist':
//         return Array.isArray(value) && value.includes(context.ip_address);
      
//       case 'time_based':
//         if (value.start_time && value.end_time) {
//           const now = new Date();
//           const startTime = new Date(value.start_time);
//           const endTime = new Date(