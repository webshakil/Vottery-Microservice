import { Sequelize } from 'sequelize';
import databaseConfig from '../config/database.js';

import VotteryUser from './VotteryUser.js';
import UserProfile from './UserProfile.js';
import Role from './Role.js';
import UserRole from './UserRole.js';
import Organization from './Organization.js';
import OrganizationMember from './OrganizationMember.js';
import Subscription from './Subscription.js';
import UserActivityLog from './UserActivityLog.js';
import EncryptionKey from './EncryptionKey.js';
import DigitalSignature from './DigitalSignature.js';
import SecurityEvent from './SecurityEvent.js';

// Get the correct environment configuration
const environment = process.env.NODE_ENV || 'development';
const config = databaseConfig[environment];

// Create Sequelize instance with proper config
const sequelize = new Sequelize(config.database, config.username, config.password, {
  host: config.host,
  dialect: config.dialect,
  port: config.port,
  logging: config.logging,
  pool: config.pool,
  dialectOptions: config.dialectOptions,
  define: config.define
});

// Initialize all models
const models = {
  VotteryUser: VotteryUser.init(sequelize),
  UserProfile: UserProfile.init(sequelize),
  Role: Role.init(sequelize),
  UserRole: UserRole.init(sequelize),
  Organization: Organization.init(sequelize),
  OrganizationMember: OrganizationMember.init(sequelize),
  Subscription: Subscription.init(sequelize),
  UserActivityLog: UserActivityLog.init(sequelize),
  EncryptionKey: EncryptionKey.init(sequelize),
  DigitalSignature: DigitalSignature.init(sequelize),
  SecurityEvent: SecurityEvent.init(sequelize)
};

// Set up associations
Object.keys(models).forEach(modelName => {
  if (models[modelName].associate) {
    models[modelName].associate(models);
  }
});

export default {
  sequelize,
  Sequelize,
  ...models
};
// import { Sequelize } from 'sequelize';
// import config from '../config/database.js';

// import VotteryUser from './VotteryUser.js';
// import UserProfile from './UserProfile.js';
// import Role from './Role.js';
// import UserRole from './UserRole.js';
// import Organization from './Organization.js';
// import OrganizationMember from './OrganizationMember.js';
// import Subscription from './Subscription.js';
// import UserActivityLog from './UserActivityLog.js';
// import EncryptionKey from './EncryptionKey.js';
// import DigitalSignature from './DigitalSignature.js';
// import SecurityEvent from './SecurityEvent.js';

// const sequelize = new Sequelize(config.database, config.username, config.password, {
//   host: config.host,
//   dialect: config.dialect,
//   port: config.port,
//   logging: config.logging,
//   pool: config.pool,
//   dialectOptions: config.dialectOptions
// });

// // Initialize all models
// const models = {
//   VotteryUser: VotteryUser.init(sequelize),
//   UserProfile: UserProfile.init(sequelize),
//   Role: Role.init(sequelize),
//   UserRole: UserRole.init(sequelize),
//   Organization: Organization.init(sequelize),
//   OrganizationMember: OrganizationMember.init(sequelize),
//   Subscription: Subscription.init(sequelize),
//   UserActivityLog: UserActivityLog.init(sequelize),
//   EncryptionKey: EncryptionKey.init(sequelize),
//   DigitalSignature: DigitalSignature.init(sequelize),
//   SecurityEvent: SecurityEvent.init(sequelize)
// };

// // Set up associations
// Object.keys(models).forEach(modelName => {
//   if (models[modelName].associate) {
//     models[modelName].associate(models);
//   }
// });

// export default {
//   sequelize,
//   Sequelize,
//   ...models
// };

// const { Sequelize } = require('sequelize');
// const config = require('../config/database');

// const sequelize = new Sequelize(config.database, config.username, config.password, {
//   host: config.host,
//   dialect: config.dialect,
//   port: config.port,
//   logging: config.logging,
//   pool: config.pool,
//   dialectOptions: config.dialectOptions
// });

// // Import all models
// const VotteryUser = require('./VotteryUser');
// const UserProfile = require('./UserProfile');
// const Role = require('./Role');
// const UserRole = require('./UserRole');
// const Organization = require('./Organization');
// const OrganizationMember = require('./OrganizationMember');
// const Subscription = require('./Subscription');
// const UserActivityLog = require('./UserActivityLog');
// const EncryptionKey = require('./EncryptionKey');
// const DigitalSignature = require('./DigitalSignature');
// const SecurityEvent = require('./SecurityEvent');

// // Initialize all models
// const models = {
//   VotteryUser: VotteryUser.init(sequelize),
//   UserProfile: UserProfile.init(sequelize),
//   Role: Role.init(sequelize),
//   UserRole: UserRole.init(sequelize),
//   Organization: Organization.init(sequelize),
//   OrganizationMember: OrganizationMember.init(sequelize),
//   Subscription: Subscription.init(sequelize),
//   UserActivityLog: UserActivityLog.init(sequelize),
//   EncryptionKey: EncryptionKey.init(sequelize),
//   DigitalSignature: DigitalSignature.init(sequelize),
//   SecurityEvent: SecurityEvent.init(sequelize)
// };

// // Set up associations
// Object.keys(models).forEach(modelName => {
//   if (models[modelName].associate) {
//     models[modelName].associate(models);
//   }
// });

// // Export sequelize instance and models
// module.exports = {
//   sequelize,
//   Sequelize,
//   ...models
// };
