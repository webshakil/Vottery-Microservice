import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { createConnection } from './config/database.js';
import morgan from 'morgan';   // <-- you forgot to import this
import dotenv from 'dotenv';
dotenv.config();

// Create express app FIRST
const app = express();

// Middleware: logging
app.use(morgan('dev'));

const PORT = process.env.PORT || 3002;

// Security middleware
app.use(helmet());
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: 'Too many requests from this IP'
});
app.use(limiter);

// Body parsing
//app.use(express.json({ limit: '10mb' }));
//app.use(express.json({ limit: '10mb', strict: false }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        service: 'user-management-service',
        timestamp: new Date().toISOString()
    });
});

// Import routes (AFTER app is created)
import userRoutes from './routes/userRoutes.js';
import profileRoutes from './routes/profileRoutes.js';
import biometricRoutes from './routes/biometricFallback.js';

app.use('/api/users', userRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/biometric', biometricRoutes);

// Start server
const startServer = async () => {
    try {
        await createConnection();
        console.log('✅ Database connected successfully');
        
        app.listen(PORT, () => {
            console.log(`🚀 User Management Service running on port ${PORT}`);
            console.log(`🏥 Health check: http://localhost:${PORT}/health`);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error.message);
        process.exit(1);
    }
};

startServer();

export default app;


// import express from 'express';
// import cors from 'cors';
// import helmet from 'helmet';
// import rateLimit from 'express-rate-limit';
// import { createConnection } from './config/database.js';

// // Import routes
// import userRoutes from './routes/userRoutes.js';
// import profileRoutes from './routes/profileRoutes.js';
// import dotenv from 'dotenv';
// dotenv.config();

// app.use(morgan('dev'));
// const PORT = process.env.PORT || 3002;

// // Security middleware
// app.use(helmet());
// app.use(cors({
//     origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
//     credentials: true
// }));

// // Rate limiting
// const limiter = rateLimit({
//     windowMs: 15 * 60 * 1000, // 15 minutes
//     max: 100, // limit each IP to 100 requests per windowMs
//     message: 'Too many requests from this IP'
// });
// app.use(limiter);

// // Body parsing
// app.use(express.json({ limit: '10mb' }));
// app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// // Health check
// app.get('/health', (req, res) => {
//     res.json({ 
//         status: 'OK', 
//         service: 'user-management-service',
//         timestamp: new Date().toISOString()
//     });
// });



// // Use routes
// app.use('/api/users', userRoutes);
// app.use('/api/profile', profileRoutes);

// // Test database connection on startup
// const startServer = async () => {
//     try {
//         const db = await createConnection();
//         console.log('✅ Database connected successfully');
        
//         app.listen(PORT, () => {
//             console.log(`🚀 User Management Service running on port ${PORT}`);
//             console.log(`🏥 Health check: http://localhost:${PORT}/health`);
//         });
//     } catch (error) {
//         console.error('❌ Failed to start server:', error.message);
//         process.exit(1);
//     }
// };

// startServer();

// export default app;
// import express from 'express';
// import cors from 'cors';
// import helmet from 'helmet';
// import rateLimit from 'express-rate-limit';
// import { createConnection } from './config/database.js';
// import dotenv from 'dotenv';
// dotenv.config();

// const app = express();
// const PORT = process.env.PORT || 3002;

// // Security middleware
// app.use(helmet());
// app.use(cors({
//     origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
//     credentials: true
// }));

// // Rate limiting
// const limiter = rateLimit({
//     windowMs: 15 * 60 * 1000, // 15 minutes
//     max: 100, // limit each IP to 100 requests per windowMs
//     message: 'Too many requests from this IP'
// });
// app.use(limiter);

// // Body parsing
// app.use(express.json({ limit: '10mb' }));
// app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// // Health check
// app.get('/health', (req, res) => {
//     res.json({ 
//         status: 'OK', 
//         service: 'user-management-service',
//         timestamp: new Date().toISOString()
//     });
// });

// // Test database connection on startup
// const startServer = async () => {
//     try {
//         const db = await createConnection();
//         console.log('✅ Database connected successfully');
        
//         app.listen(PORT, () => {
//             console.log(`🚀 User Management Service running on port ${PORT}`);
//             console.log(`🏥 Health check: http://localhost:${PORT}/health`);
//         });
//     } catch (error) {
//         console.error('❌ Failed to start server:', error.message);
//         process.exit(1);
//     }
// };

// startServer();

// export default app;