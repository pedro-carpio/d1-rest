import { Context, Next } from 'hono';
import { jwtVerify } from 'jose';
import type { Env } from '../index';

/**
 * Extiende el contexto de Hono para incluir información del usuario autenticado
 */
export interface AuthContext {
    userId: number;
    firebaseUid: string;
    email: string | null;
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

/**
 * MIDDLEWARE 1: Autenticación de Usuario con JWT
 * 
 * Verifica el JWT firmado por el frontend y extrae el firebase_uid del payload.
 * El JWT está firmado con el mismo SECRET compartido entre frontend y backend.
 * 
 * Uso:
 * app.use('/api/*', authenticateUser);
 * 
 * Luego en las rutas puedes acceder a: c.get('user')
 */
export const authenticateUser = async (c: Context<{ Bindings: Env }>, next: Next) => {
    try {
        // Extraer el JWT del header X-Firebase-Token
        // El header Authorization ya fue validado por authMiddleware con BACKEND_API_TOKEN
        const jwtToken = c.req.header('X-Firebase-Token');
        
        if (!jwtToken) {
            return c.json({ error: 'No se proporcionó JWT en header X-Firebase-Token' }, 401);
        }

        // Obtener el secreto compartido
        const secret = await c.env.SECRET.get();
        if (!secret) {
            return c.json({ error: 'Configuración de secreto no encontrada' }, 500);
        }

        // Verificar y decodificar el JWT
        let firebaseUid: string;
        try {
            const secretKey = new TextEncoder().encode(secret);
            const { payload } = await jwtVerify(jwtToken, secretKey);
            
            firebaseUid = payload.firebase_uid as string;
            
            if (!firebaseUid) {
                return c.json({ error: 'JWT no contiene firebase_uid' }, 401);
            }
        } catch (jwtError: any) {
            console.error('Error al verificar JWT:', jwtError.message);
            return c.json({ error: 'JWT inválido o expirado', details: jwtError.message }, 401);
        }

        // Buscar el usuario en la base de datos
        const user = await c.env.DB.prepare(
            `SELECT u.id, u.firebase_uid, u.email, u.full_name, u.role_id, r.name as role_name, u.is_active
             FROM user_account u
             JOIN role r ON u.role_id = r.id
             WHERE u.firebase_uid = ?`
        ).bind(firebaseUid).first();

        if (!user) {
            return c.json({ error: 'Usuario no encontrado' }, 404);
        }

        if (!user.is_active) {
            return c.json({ error: 'Usuario inactivo' }, 403);
        }

        // Guardar información del usuario en el contexto
        c.set('user', {
            userId: user.id as number,
            firebaseUid: user.firebase_uid as string,
            email: user.email as string | null,
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

/**
 * MIDDLEWARE 2: Autorización por Roles (RBAC)
 * 
 * Verifica que el usuario tenga uno de los roles permitidos.
 * DEBE usarse DESPUÉS de authenticateUser.
 * 
 * Uso:
 * app.get('/admin/users', authenticateUser, requireRoles(['admin']), (c) => {...})
 * app.post('/curso', authenticateUser, requireRoles(['admin', 'teacher']), (c) => {...})
 */
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

/**
 * MIDDLEWARE 3: Verificación de Propiedad de Curso
 * 
 * Verifica que el profesor sea dueño del curso antes de permitir operaciones.
 * Útil para endpoints como: PATCH /curso/:id, DELETE /curso/:id
 * 
 * Uso:
 * app.patch('/curso/:id', authenticateUser, verifyCursoOwnership, (c) => {...})
 */
export const verifyCursoOwnership = async (c: Context<{ Bindings: Env }>, next: Next) => {
    const user = c.get('user');
    
    if (!user) {
        return c.json({ error: 'Usuario no autenticado' }, 401);
    }

    // Admins pueden editar cualquier curso
    if (user.roleName === 'admin') {
        await next();
        return;
    }

    // Para teachers, verificar que sean el docente del curso
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

/**
 * MIDDLEWARE 5: Filtrar Recursos por Usuario
 * 
 * Modifica automáticamente las queries para que solo devuelvan recursos del usuario.
 * Útil para GET /curso (solo devolver cursos donde el user es docente)
 * 
 * Este middleware INYECTA el filtro en el contexto para que la ruta lo use.
 * 
 * Uso:
 * app.get('/curso', authenticateUser, injectUserFilter, async (c) => {
 *   const filter = c.get('userFilter');
 *   // Usar filter en la query
 * })
 */
export const injectUserCursoFilter = async (c: Context<{ Bindings: Env }>, next: Next) => {
    const user = c.get('user');
    
    if (!user) {
        return c.json({ error: 'Usuario no autenticado' }, 401);
    }

    // Admins ven todos los cursos
    if (user.roleName === 'admin') {
        c.set('cursoFilter', { where: '', params: [] });
    } else {
        // Teachers solo ven sus cursos
        c.set('cursoFilter', { 
            where: 'WHERE docente_id = ?', 
            params: [user.userId] 
        });
    }

    await next();
};