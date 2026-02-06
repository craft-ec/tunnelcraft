/**
 * LogService
 *
 * Structured logging for the mobile app.
 * Wraps console methods with tag-based filtering and level control.
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

class LogServiceClass {
  private minLevel: LogLevel = __DEV__ ? 'debug' : 'info';

  setMinLevel(level: LogLevel): void {
    this.minLevel = level;
  }

  debug(tag: string, message: string, data?: unknown): void {
    this.log('debug', tag, message, data);
  }

  info(tag: string, message: string, data?: unknown): void {
    this.log('info', tag, message, data);
  }

  warn(tag: string, message: string, data?: unknown): void {
    this.log('warn', tag, message, data);
  }

  error(tag: string, message: string, data?: unknown): void {
    this.log('error', tag, message, data);
  }

  private log(level: LogLevel, tag: string, message: string, data?: unknown): void {
    if (LOG_LEVELS[level] < LOG_LEVELS[this.minLevel]) {
      return;
    }

    const prefix = `[${tag}]`;

    switch (level) {
      case 'debug':
        data !== undefined ? console.debug(prefix, message, data) : console.debug(prefix, message);
        break;
      case 'info':
        data !== undefined ? console.log(prefix, message, data) : console.log(prefix, message);
        break;
      case 'warn':
        data !== undefined ? console.warn(prefix, message, data) : console.warn(prefix, message);
        break;
      case 'error':
        data !== undefined ? console.error(prefix, message, data) : console.error(prefix, message);
        break;
    }
  }
}

export const LogService = new LogServiceClass();
