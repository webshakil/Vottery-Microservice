//latest
import transporter from '../config/email.js';
import { logger } from '../utils/logger.js';

export class EmailService {
  static async sendOTP(email, otp) {
    try {
      const mailOptions = {
        from: {
          name: 'Vottery',
          address: process.env.EMAIL_FROM || process.env.EMAIL_USER
        },
        to: email,
        subject: 'Vottery - Email Verification Code',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
              <h1 style="color: white; margin: 0;">Vottery</h1>
            </div>
            <div style="padding: 30px; background: #f9f9f9;">
              <h2 style="color: #333;">Email Verification</h2>
              <p style="color: #666; font-size: 16px;">
                Welcome to Vottery! Please use the verification code below to complete your authentication:
              </p>
              <div style="background: white; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                <h1 style="color: #667eea; font-size: 36px; margin: 0; letter-spacing: 8px;">${otp}</h1>
              </div>
              <p style="color: #666; font-size: 14px;">
                This code will expire in 5 minutes. If you didn't request this verification, please ignore this email.
              </p>
              <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
                <p style="color: #999; font-size: 12px; text-align: center;">
                  This is an automated message from Vottery. Please do not reply to this email.
                </p>
              </div>
            </div>
          </div>
        `
      };

      const result = await transporter.sendMail(mailOptions);
      logger.info(`Email OTP sent successfully to ${email}:`, result.messageId);
      return { success: true, messageId: result.messageId };
      
    } catch (error) {
      logger.error(`Failed to send email OTP to ${email}:`, error);
      throw new Error('Email sending failed');
    }
  }

  static async sendWelcomeEmail(email, userName) {
    try {
      const mailOptions = {
        from: {
          name: 'Vottery',
          address: process.env.EMAIL_FROM || process.env.EMAIL_USER
        },
        to: email,
        subject: 'Welcome to Vottery!',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
              <h1 style="color: white; margin: 0;">Welcome to Vottery!</h1>
            </div>
            <div style="padding: 30px; background: #f9f9f9;">
              <h2 style="color: #333;">Authentication Completed Successfully</h2>
              <p style="color: #666; font-size: 16px;">
                Congratulations! You have successfully completed the authentication process and can now access the Vottery platform.
              </p>
              <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3 style="color: #667eea;">What's Next?</h3>
                <ul style="color: #666;">
                  <li>Explore voting features in upcoming milestones</li>
                  <li>Your device and biometric data are securely registered</li>
                  <li>Access your dashboard anytime</li>
                </ul>
              </div>
              <div style="text-align: center; margin: 30px 0;">
                <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}" 
                   style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px;">
                  Access Dashboard
                </a>
              </div>
            </div>
          </div>
        `
      };

      const result = await transporter.sendMail(mailOptions);
      logger.info(`Welcome email sent successfully to ${email}:`, result.messageId);
      return { success: true, messageId: result.messageId };
      
    } catch (error) {
      logger.error(`Failed to send welcome email to ${email}:`, error);
      // Don't throw error for welcome email failure
      return { success: false, error: error.message };
    }
  }
}

// import nodemailer from 'nodemailer';
// import logger from '../utils/logger.js';

// export class EmailService {
//   constructor() {
//     this.transporter = nodemailer.createTransporter({
//       host: process.env.NODEMAILER_HOST,
//       port: parseInt(process.env.NODEMAILER_PORT),
//       secure: process.env.NODEMAILER_SECURE === 'true',
//       auth: {
//         user: process.env.NODEMAILER_USER,
//         pass: process.env.NODEMAILER_PASS
//       }
//     });

//     this.fromName = process.env.EMAIL_FROM_NAME || 'Vottery Team';
//     this.fromAddress = process.env.EMAIL_FROM_ADDRESS || 'noreply@vottery.com';
//   }

//   // Send OTP email
//   async sendOtp(email, otp, expiresInMinutes) {
//     try {
//       const mailOptions = {
//         from: `${this.fromName} <${this.fromAddress}>`,
//         to: email,
//         subject: 'Your Vottery Verification Code',
//         html: this.generateOtpEmailTemplate(otp, expiresInMinutes),
//         text: `Your Vottery verification code is: ${otp}. This code will expire in ${expiresInMinutes} minutes. If you didn't request this, please ignore this email.`
//       };

//       const result = await this.transporter.sendMail(mailOptions);
      
//       logger.info(`OTP email sent successfully to ${email.replace(/(.{2}).*@/, '$1***@')}`, {
//         messageId: result.messageId,
//         otp: otp.replace(/\d/g, '*') // Log masked OTP
//       });

//       return true;

//     } catch (error) {
//       logger.error('Error sending OTP email:', error);
//       return false;
//     }
//   }

//   // Generate HTML email template
//   generateOtpEmailTemplate(otp, expiresInMinutes) {
//     return `
//     <!DOCTYPE html>
//     <html>
//     <head>
//       <meta charset="utf-8">
//       <meta name="viewport" content="width=device-width, initial-scale=1">
//       <title>Vottery Verification Code</title>
//     </head>
//     <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
//       <div style="text-align: center; margin-bottom: 30px;">
//         <h1 style="color: #4F46E5; margin: 0;">Vottery</h1>
//         <p style="color: #6B7280; margin: 5px 0 0 0;">Secure Voting Platform</p>
//       </div>
      
//       <div style="background: #F9FAFB; border-radius: 8px; padding: 30px; margin-bottom: 30px;">
//         <h2 style="color: #1F2937; margin-top: 0;">Your Verification Code</h2>
//         <p style="color: #4B5563; margin-bottom: 20px;">
//           Please use the following verification code to complete your authentication:
//         </p>
        
//         <div style="background: #FFFFFF; border: 2px solid #E5E7EB; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
//           <span style="font-size: 32px; font-weight: bold; color: #4F46E5; letter-spacing: 8px;">${otp}</span>
//         </div>
        
//         <p style="color: #6B7280; font-size: 14px; margin-bottom: 0;">
//           This code will expire in <strong>${expiresInMinutes} minutes</strong>.
//         </p>
//       </div>
      
//       <div style="border-top: 1px solid #E5E7EB; padding-top: 20px;">
//         <p style="color: #6B7280; font-size: 12px; margin: 0;">
//           If you didn't request this verification code, please ignore this email. 
//           For security reasons, do not share this code with anyone.
//         </p>
//       </div>
      
//       <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #E5E7EB;">
//         <p style="color: #9CA3AF; font-size: 12px; margin: 0;">
//           © ${new Date().getFullYear()} Vottery. All rights reserved.
//         </p>
//       </div>
//     </body>
//     </html>
//     `;
//   }

//   // Test email configuration
//   async testConnection() {
//     try {
//       await this.transporter.verify();
//       logger.info('Email service connection verified');
//       return true;
//     } catch (error) {
//       logger.error('Email service connection failed:', error);
//       return false;
//     }
//   }
// }



