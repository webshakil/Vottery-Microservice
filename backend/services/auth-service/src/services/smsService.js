import twilioClient from '../config/sms.js';
import { logger } from '../utils/logger.js';

export class SMSService {

  static async sendOTP(phone, otp) {
    try {
      const message = await twilioClient.messages.create({
        body: `Your Vottery verification code is: ${otp}. This code expires in 5 minutes. Do not share this code with anyone.`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phone
      });
  
      logger.info(`SMS OTP sent successfully to ${phone}: ${message.sid}`);
      return { success: true, messageSid: message.sid };
      
    } catch (error) {
      // 👇 log Twilio’s detailed error message
      logger.error(`Failed to send SMS OTP to ${phone}: ${error.message}`, { error });
      throw new Error(error.message || 'SMS sending failed');
    }
  }

  static async sendWelcomeSMS(phone) {
    try {
      const message = await twilioClient.messages.create({
        body: `Welcome to Vottery! Your authentication is complete. Access your dashboard at ${process.env.FRONTEND_URL || 'vottery.com'}`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phone
      });

      logger.info(`Welcome SMS sent successfully to ${phone}:`, message.sid);
      return { success: true, messageSid: message.sid };
      
    } catch (error) {
      logger.error(`Failed to send welcome SMS to ${phone}:`, error);
      // Don't throw error for welcome SMS failure
      return { success: false, error: error.message };
    }
  }
}