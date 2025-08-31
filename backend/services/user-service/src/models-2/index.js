import { Sequelize } from 'sequelize';
import VotteryUser from './VotteryUser.js';
import VotteryRole from './VotteryRole.js';
import VotteryUserRole from './VotteryUserRole.js';
//import VotteryOrganization from './VotteryOrganization.js';
import OrganizationMember from './OrganizationMember.js';
import VotterySubscription from './VotterySubscription.js';
import UserActivityLog from './UserActivityLog.js';
import EncryptionKey from './EncryptionKey.js';
import DigitalSignature from './DigitalSignature.js';
import SecurityEvent from './SecurityEvent.js';

// Initialize Sequelize connection
const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'postgres',
    logging: process.env.NODE_ENV === 'development' ? console.log : false,
    pool: {
      max: 10,
      min: 0,
      acquire: 30000,
      idle: 10000,
    },
    define: {
      timestamps: true,
      underscored: true,
      paranoid: true,
      freezeTableName: true,
    },
  }
);

// Initialize models
const models = {
  VotteryUser: VotteryUser(sequelize),
  VotteryRole: VotteryRole(sequelize),
  //VotteryUserRole: VotteryUserRole(sequelize),
  VotteryOrganization: VotteryOrganization(sequelize),
  OrganizationMember: OrganizationMember(sequelize),
  VotterySubscription: VotterySubscription(sequelize),
  UserActivityLog: UserActivityLog(sequelize),
  EncryptionKey: EncryptionKey(sequelize),
  DigitalSignature: DigitalSignature(sequelize),
  SecurityEvent: SecurityEvent(sequelize),
};

// Setup associations
Object.keys(models).forEach((modelName) => {
  if (models[modelName].associate) {
    models[modelName].associate(models);
  }
});

// Add sequelize instance and constructor to models
models.sequelize = sequelize;
models.Sequelize = Sequelize;

// Test database connection
const testConnection = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Database connection established successfully.');
  } catch (error) {
    console.error('❌ Unable to connect to the database:', error);
    process.exit(1);
  }
};

// Initialize database
const initializeDatabase = async () => {
  try {
    await testConnection();
    
    // Sync models in development only
    if (process.env.NODE_ENV === 'development') {
      await sequelize.sync({ alter: false });
      console.log('✅ Database models synchronized.');
    }
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    process.exit(1);
  }
};

export { sequelize, initializeDatabase };
export default models;