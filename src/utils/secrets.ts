import type { Env } from '../index';

/**
 * Helper para obtener el SECRET JWT
 * En desarrollo: usa SECRET_DEV si existe
 * En producción: usa Secrets Store
 */
export async function getSecret(env: Env): Promise<string | null> {
    // Producción: usar Secrets Store
    if (env.SECRET) {
        try {
            return await env.SECRET.get();
        } catch (error) {
            console.error('Error obteniendo SECRET del Secrets Store:', error);
        }
    }
    
    return null;
}

/**
 * Helper para obtener Google Client ID
 * En desarrollo: usa GOOGLE_CLIENT_ID_DEV si existe
 * En producción: usa Secrets Store
 */
export async function getGoogleClientId(env: Env): Promise<string | null> {
    // Producción: usar Secrets Store
    if (env.GOOGLE_CLIENT_ID) {
        try {
            return await env.GOOGLE_CLIENT_ID.get();
        } catch (error) {
            console.error('Error obteniendo GOOGLE_CLIENT_ID del Secrets Store:', error);
        }
    }
    
    return null;
}

/**
 * Helper para obtener Google Client Secret
 * En desarrollo: usa GOOGLE_CLIENT_SECRET_DEV si existe
 * En producción: usa Secrets Store
 */
export async function getGoogleClientSecret(env: Env): Promise<string | null> {
    // Producción: usar Secrets Store
    if (env.GOOGLE_CLIENT_SECRET) {
        try {
            return await env.GOOGLE_CLIENT_SECRET.get();
        } catch (error) {
            console.error('Error obteniendo GOOGLE_CLIENT_SECRET del Secrets Store:', error);
        }
    }
    
    return null;
}
