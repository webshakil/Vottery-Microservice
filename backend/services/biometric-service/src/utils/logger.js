import { createWriteStream } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';

class Logger {
  constructor() {
    this.logDir = process.env.LOG_DIR || './logs';
    this.setupLogDir();
  }

  async setupLogDir() {
    try {
      await mkdir(this.logDir, { recursive: true });
    } catch (error) {
      console.error('Failed to create log directory:', error);
    }
  }

  formatMessage(level, message, meta = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      service: 'biometric-service',
      message,
      ...meta
    };
    return JSON.stringify(logEntry) + '\n';
  }

  writeLog(level, message, meta) {
    const formattedMessage = this.formatMessage(level, message, meta);
    
    // Console output
    console.log(formattedMessage.trim());
    
    // File output (if in production)
    if (process.env.NODE_ENV === 'production') {
      const logFile = path.join(this.logDir, `${level}.log`);
      const stream = createWriteStream(logFile, { flags: 'a' });
      stream.write(formattedMessage);
      stream.end();
    }
  }

  info(message, meta) {
    this.writeLog('info', message, meta);
  }

  error(message, meta) {
    this.writeLog('error', message, meta);
  }

  warn(message, meta) {
    this.writeLog('warn', message, meta);
  }

  debug(message, meta) {
    if (process.env.NODE_ENV === 'development') {
      this.writeLog('debug', message, meta);
    }
  }
}

export const logger = new Logger();