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
    EXPIRATION: '24h',
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
