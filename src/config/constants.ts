/**
 * Constantes de configuración del backend
 * Centraliza valores que antes estaban hardcodeados
 */

// Configuración de seguridad de contraseñas
export const PASSWORD_CONFIG = {
    MIN_LENGTH: 6,
    PBKDF2_ITERATIONS: 100000,
    SALT_LENGTH: 16,
    HASH_ALGORITHM: 'SHA-256' as const,
    KEY_LENGTH: 256,
} as const;

// Configuración de JWT
export const JWT_CONFIG = {
    ALGORITHM: 'HS256' as const,
    EXPIRATION: '1h', // JWT de corta duración (1 hora)
} as const;

// Configuración de Refresh Tokens
export const REFRESH_TOKEN_CONFIG = {
    TOKEN_LENGTH: 32, // bytes
    EXPIRATION_DAYS: 100, // 100 días
} as const;

// Roles de usuario (deben coincidir con la tabla role en la BD)
export const USER_ROLES = {
    ADMIN: 1,
    TEACHER: 2,
    DIRECTOR: 3,
    SELLER: 4,
} as const;

// Estados de usuario
export const USER_STATUS = {
    INACTIVE: 0,
    ACTIVE: 1,
} as const;

// Valores por defecto para registro de usuarios
export const USER_DEFAULTS = {
    ROLE_ID: USER_ROLES.TEACHER,
    IS_ACTIVE: USER_STATUS.INACTIVE,
} as const;

// Configuración de tokens de reset de contraseña
export const PASSWORD_RESET_CONFIG = {
    TOKEN_LENGTH: 32, // bytes
    EXPIRATION_HOURS: 24,
} as const;

// Configuración de OAuth 2.0
export const OAUTH_CONFIG = {
    GOOGLE: {
        AUTHORIZATION_URL: 'https://accounts.google.com/o/oauth2/v2/auth',
        TOKEN_URL: 'https://oauth2.googleapis.com/token',
        USERINFO_URL: 'https://www.googleapis.com/oauth2/v2/userinfo',
        SCOPES: ['openid', 'email', 'profile'],
        CALLBACK_PATH: '/auth/handler',
    },
    STATE_LENGTH: 32, // bytes para el state CSRF token
} as const;
