import { Context, Next } from 'hono';
import { jwtVerify } from 'jose';
import type { Env } from '../index';
import { PASSWORD_CONFIG } from '../config/constants';

export async function hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const salt = crypto.getRandomValues(new Uint8Array(PASSWORD_CONFIG.SALT_LENGTH));
    
    const key = await crypto.subtle.importKey('raw', data, { name: 'PBKDF2' }, false, ['deriveBits']);
    const hashBuffer = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: PASSWORD_CONFIG.PBKDF2_ITERATIONS,
            hash: PASSWORD_CONFIG.HASH_ALGORITHM
        },
        key,
        PASSWORD_CONFIG.KEY_LENGTH
    );
    
    const hashArray = new Uint8Array(hashBuffer);
    const combined = new Uint8Array(salt.length + hashArray.length);
    combined.set(salt);
    combined.set(hashArray, salt.length);
    
    return Array.from(combined).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
        const combined = new Uint8Array(hash.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
        const salt = combined.slice(0, 16);
        const storedHash = combined.slice(16);
        
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const key = await crypto.subtle.importKey('raw', data, { name: 'PBKDF2' }, false, ['deriveBits']);
        
        const hashBuffer = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: PASSWORD_CONFIG.PBKDF2_ITERATIONS,
                hash: PASSWORD_CONFIG.HASH_ALGORITHM
            },
            key,
            PASSWORD_CONFIG.KEY_LENGTH
        );
        
        const hashArray = new Uint8Array(hashBuffer);
        if (hashArray.length !== storedHash.length) return false;
        
        let match = true;
        for (let i = 0; i < hashArray.length; i++) {
            if (hashArray[i] !== storedHash[i]) match = false;
        }
        return match;
    } catch (error) {
        console.error('Error al verificar contraseña:', error);
        return false;
    }
}

export interface AuthContext {
    userId: number;
    email: string;
    fullName: string | null;
    roleId: number;
    roleName: string;
    isActive: boolean;
}

export interface CursoFilter {
    where: string;
    params: any[];
}

declare module 'hono' {
    interface ContextVariableMap {
        user: AuthContext;
        cursoFilter: CursoFilter;
    }
}

export const authenticateUser = async (c: Context<{ Bindings: Env }>, next: Next) => {
    try {
        const authHeader = c.req.header('Authorization');
        
        if (!authHeader) {
            return c.json({ error: 'No se proporcionó token de autenticación' }, 401);
        }

        const jwtToken = authHeader.startsWith('Bearer ')
            ? authHeader.substring(7)
            : authHeader;

        const secret = await c.env.SECRET.get();
        if (!secret) {
            return c.json({ error: 'Configuración de secreto no encontrada' }, 500);
        }

        let userId: number;
        try {
            const secretKey = new TextEncoder().encode(secret);
            const { payload } = await jwtVerify(jwtToken, secretKey);
            
            userId = payload.user_id as number;
            
            if (!userId) {
                return c.json({ error: 'JWT no contiene user_id' }, 401);
            }
        } catch (jwtError: any) {
            console.error('Error al verificar JWT:', jwtError.message);
            return c.json({ error: 'JWT inválido o expirado', details: jwtError.message }, 401);
        }

        const user = await c.env.DB.prepare(
            `SELECT u.id, u.email, u.full_name, u.role_id, r.name as role_name, u.is_active
             FROM user_account u
             JOIN role r ON u.role_id = r.id
             WHERE u.id = ?`
        ).bind(userId).first();

        if (!user) {
            return c.json({ error: 'Usuario no encontrado' }, 404);
        }

        if (!user.is_active) {
            return c.json({ error: 'Usuario inactivo' }, 403);
        }

        c.set('user', {
            userId: user.id as number,
            email: user.email as string,
            fullName: user.full_name as string | null,
            roleId: user.role_id as number,
            roleName: user.role_name as string,
            isActive: Boolean(user.is_active)
        });

        await next();
    } catch (error: any) {
        console.error('Error en authenticateUser:', error);
        return c.json({ error: 'Error de autenticación', details: error.message }, 500);
    }
};

export const requireRoles = (allowedRoles: string[]) => {
    return async (c: Context<{ Bindings: Env }>, next: Next) => {
        const user = c.get('user');

        if (!user) {
            return c.json({ error: 'Usuario no autenticado. Usa authenticateUser antes de requireRoles' }, 401);
        }

        if (!allowedRoles.includes(user.roleName)) {
            return c.json({ 
                error: 'Acceso denegado',
                message: `Se requiere uno de estos roles: ${allowedRoles.join(', ')}`,
                yourRole: user.roleName
            }, 403);
        }

        await next();
    };
};

export const verifyCursoOwnership = async (c: Context<{ Bindings: Env }>, next: Next) => {
    const user = c.get('user');
    
    if (!user) {
        return c.json({ error: 'Usuario no autenticado' }, 401);
    }

    if (user.roleName === 'admin') {
        await next();
        return;
    }

    const cursoId = c.req.param('id');
    
    if (!cursoId) {
        return c.json({ error: 'ID de curso no proporcionado' }, 400);
    }

    const curso = await c.env.DB.prepare(
        'SELECT docente_id FROM curso WHERE id = ?'
    ).bind(cursoId).first();

    if (!curso) {
        return c.json({ error: 'Curso no encontrado' }, 404);
    }

    if (curso.docente_id !== user.userId) {
        return c.json({ 
            error: 'No tienes permiso para modificar este curso',
            message: 'Solo el docente asignado puede editar este curso'
        }, 403);
    }

    await next();
};

export const injectUserCursoFilter = async (c: Context<{ Bindings: Env }>, next: Next) => {
    const user = c.get('user');
    
    if (!user) {
        return c.json({ error: 'Usuario no autenticado' }, 401);
    }

    // Admins ven todos los cursos
    if (user.roleName === 'admin') {
    if (user.roleName === 'admin') {
        c.set('cursoFilter', { where: '', params: [] });
    } else {?', 
            params: [user.userId] 
        });
    }

    await next();
};
