import { Sequelize } from 'sequelize';
import config from '../config/database';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

// Needed for __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const sequelize = new Sequelize(config.database, config.username, config.password, {
  host: config.host,
  dialect: config.dialect,
  port: config.port,
  logging: config.logging
});

async function runMigrations() {
  try {
    console.log('🚀 Starting Vottery User Service Database Migrations...');

    // Test database connection
    await sequelize.authenticate();
    console.log('✅ Database connection established');

    // Get all migration files
    const migrationsPath = path.join(__dirname, 'migrations');
    const migrationFiles = fs.readdirSync(migrationsPath)
      .filter(file => file.endsWith('.js'))
      .sort();

    console.log(`📁 Found ${migrationFiles.length} migration files`);

    // Run each migration
    for (const file of migrationFiles) {
      console.log(`📝 Running migration: ${file}`);
      const migration = await import(path.join(migrationsPath, file));
      
      try {
        await migration.default.up(sequelize.getQueryInterface(), Sequelize);
        console.log(`✅ Completed migration: ${file}`);
      } catch (error) {
        console.error(`❌ Failed migration: ${file}`, error.message);
        throw error;
      }
    }

    console.log('🎉 All migrations completed successfully!');

    // Run seeders
    console.log('🌱 Starting seeders...');
    
    const seedersPath = path.join(__dirname, 'seeders');
    if (fs.existsSync(seedersPath)) {
      const seederFiles = fs.readdirSync(seedersPath)
        .filter(file => file.endsWith('.js'))
        .sort();

      for (const file of seederFiles) {
        console.log(`🌱 Running seeder: ${file}`);
        const seeder = await import(path.join(seedersPath, file));
        
        try {
          await seeder.default.up(sequelize.getQueryInterface(), Sequelize);
          console.log(`✅ Completed seeder: ${file}`);
        } catch (error) {
          console.error(`❌ Failed seeder: ${file}`, error.message);
        }
      }
    }

    console.log('🎉 Database setup completed successfully!');
    
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    await sequelize.close();
  }
}

// Run migrations if called directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runMigrations();
}

export default runMigrations;

// const { Sequelize } = require('sequelize');
// const config = require('../config/database');
// const path = require('path');
// const fs = require('fs');

// const sequelize = new Sequelize(config.database, config.username, config.password, {
//   host: config.host,
//   dialect: config.dialect,
//   port: config.port,
//   logging: config.logging
// });

// async function runMigrations() {
//   try {
//     console.log('🚀 Starting Vottery User Service Database Migrations...');

//     // Test database connection
//     await sequelize.authenticate();
//     console.log('✅ Database connection established');

//     // Get all migration files
//     const migrationsPath = path.join(__dirname, 'migrations');
//     const migrationFiles = fs.readdirSync(migrationsPath)
//       .filter(file => file.endsWith('.js'))
//       .sort();

//     console.log(`📁 Found ${migrationFiles.length} migration files`);

//     // Run each migration
//     for (const file of migrationFiles) {
//       console.log(`📝 Running migration: ${file}`);
//       const migration = require(path.join(migrationsPath, file));
      
//       try {
//         await migration.up(sequelize.getQueryInterface(), Sequelize);
//         console.log(`✅ Completed migration: ${file}`);
//       } catch (error) {
//         console.error(`❌ Failed migration: ${file}`, error.message);
//         throw error;
//       }
//     }

//     console.log('🎉 All migrations completed successfully!');

//     // Run seeders
//     console.log('🌱 Starting seeders...');
    
//     const seedersPath = path.join(__dirname, 'seeders');
//     if (fs.existsSync(seedersPath)) {
//       const seederFiles = fs.readdirSync(seedersPath)
//         .filter(file => file.endsWith('.js'))
//         .sort();

//       for (const file of seederFiles) {
//         console.log(`🌱 Running seeder: ${file}`);
//         const seeder = require(path.join(seedersPath, file));
        
//         try {
//           await seeder.up(sequelize.getQueryInterface(), Sequelize);
//           console.log(`✅ Completed seeder: ${file}`);
//         } catch (error) {
//           console.error(`❌ Failed seeder: ${file}`, error.message);
//           // Don't throw on seeder errors, just log them
//         }
//       }
//     }

//     console.log('🎉 Database setup completed successfully!');
    
//   } catch (error) {
//     console.error('❌ Migration failed:', error);
//     process.exit(1);
//   } finally {
//     await sequelize.close();
//   }
// }

// // Run migrations if called directly
// if (require.main === module) {
//   runMigrations();
// }

// module.exports = { runMigrations };