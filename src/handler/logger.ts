import config from "../config/config.js";

// Define a type for the available color keys
type ColorKey = 'RED' | 'GREEN' | 'YELLOW' | 'RESET' | 'WHITE';

const colors: Record<ColorKey, string> = {
    RED: String.raw`\x1b[31m`,
    GREEN: String.raw`\x1b[32m`,
    YELLOW: String.raw`\x1b[33m`,
    RESET: String.raw`\x1b[0m`,
    WHITE: String.raw`\x1b[37m`,
};

function unescape(str: string): string {
    return str.replaceAll(String.raw`\x1b`, '\x1b');
}

const color_config: Record<ColorKey, string> = {
    RED: unescape(colors.RED),
    GREEN: unescape(colors.GREEN),
    YELLOW: unescape(colors.YELLOW),
    RESET: unescape(colors.RESET),
    WHITE: unescape(colors.WHITE),
};

function currentTime(): string {
    return new Intl.DateTimeFormat('de-DE', {
        timeZone: 'Europe/Berlin',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    }).format(new Date());
}

/**
 * Log an error message in Red
 */
function err(message: any): void {
    console.log(`${color_config.RED}[${currentTime()}] ${message}${color_config.RESET}`);
}

/**
 * Log a notification in Yellow
 */
function notify(message: any): void {
    console.log(`${color_config.YELLOW}[${currentTime()}] ${message}${color_config.RESET}`);
}

/**
 * Log a success message in Green
 */
function success(message: any): void {
    console.log(`${color_config.GREEN}[${currentTime()}] ${message}${color_config.RESET}`);
}

/**
 * Log a critical error and terminate the process
 */
function critical(message: any): void {
    console.log(`${color_config.RED}[${currentTime()}] CRITICAL: ${message}${color_config.RESET}`);
    process.exit(1);
}

/** 
 *  Log for warn
 */
function warn(message: any): void {
    console.log(`${color_config.YELLOW}[${currentTime()}] WARNING: ${message}${color_config.RESET}`);
}

/**
 * Log for debug messages, only if debug mode is enabled in config
 */
function debug(message: any): void {
    if(config.debug) {
        console.log(`${color_config.WHITE}[${currentTime()}] DEBUG: ${message}${color_config.RESET}`);
    }
}

export default {
    err,
    notify,
    success,
    critical,
    error: err,
    info: notify,
    warn,
    debug
};