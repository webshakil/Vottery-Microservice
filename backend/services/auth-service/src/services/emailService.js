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
        subject: 'Vottery - Email or SMS Verification Code',
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