import { Context, Next } from 'hono';
import { jwtVerify, importX509, JWTVerifyResult } from 'jose';
import type { Env } from '../index';

/**
 * Cache de claves públicas de Firebase para validar ID Tokens
 * Las claves se actualizan cada hora desde Google
 */
let firebasePublicKeys: Record<string, string> | null = null;
let keysLastFetched = 0;
const KEYS_CACHE_DURATION = 3600000; // 1 hora en milisegundos

/**
 * Obtiene las claves públicas de Firebase desde Google
 * https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com
 */
async function getFirebasePublicKeys(): Promise<Record<string, string>> {
    const now = Date.now();
    
    // Usar cache si está disponible y no ha expirado
    if (firebasePublicKeys && (now - keysLastFetched) < KEYS_CACHE_DURATION) {
        return firebasePublicKeys;
    }

    // Obtener nuevas claves
    const response = await fetch(
        'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'
    );

    if (!response.ok) {
        throw new Error('No se pudieron obtener las claves públicas de Firebase');
    }

    firebasePublicKeys = await response.json();
    keysLastFetched = now;
    
    return firebasePublicKeys as Record<string, string>;
}

/**
 * MIDDLEWARE -1: Validación de Firebase ID Token
 * 
 * Valida que el Firebase ID Token enviado en el header X-Firebase-ID-Token sea auténtico.
 * Verifica el token usando las claves públicas de Google (sin Firebase Admin SDK).
 * Extrae el uid verificado del token y lo guarda en el contexto.
 * 
 * Este middleware NO requiere BACKEND_API_TOKEN - la validación criptográfica es suficiente.
 * 
 * Uso:
 * app.post('/user/register', validateFirebaseToken, (c) => {
 *   const firebaseUid = c.get('firebaseUid');
 *   // El UID ya está verificado por Google
 * })
 */
export const validateFirebaseToken = async (c: Context<{ Bindings: Env }>, next: Next) => {
    try {
        const idToken = c.req.header('X-Firebase-ID-Token');
        
        if (!idToken) {
            return c.json({ 
                error: 'No se proporcionó Firebase ID Token',
                message: 'Debe enviar el token en el header X-Firebase-ID-Token'
            }, 401);
        }

        try {
            // Decodificar el header del token para obtener el kid (key ID)
            const [headerB64] = idToken.split('.');
            const headerJson = JSON.parse(atob(headerB64));
            const kid = headerJson.kid;

            if (!kid) {
                return c.json({ 
                    error: 'Token inválido',
                    message: 'El token no contiene kid (key ID)'
                }, 401);
            }

            // Obtener las claves públicas de Firebase
            const publicKeys = await getFirebasePublicKeys();
            const publicKeyPem = publicKeys[kid];

            if (!publicKeyPem) {
                return c.json({ 
                    error: 'Token inválido',
                    message: 'No se encontró la clave pública para este token'
                }, 401);
            }

            // Importar la clave pública X.509
            const publicKey = await importX509(publicKeyPem, 'RS256');

            // Verificar el JWT con la clave pública
            const { payload } = await jwtVerify(idToken, publicKey, {
                issuer: 'https://securetoken.google.com/my-tutors-herramientas',
                audience: 'my-tutors-herramientas',
            }) as JWTVerifyResult;

            // Verificar que el token no ha expirado (exp claim)
            const now = Math.floor(Date.now() / 1000);
            if (payload.exp && payload.exp < now) {
                return c.json({ 
                    error: 'Token expirado',
                    message: 'El Firebase ID Token ha expirado'
                }, 401);
            }

            // Guardar el UID verificado en el contexto
            c.set('firebaseUid', payload.sub || payload.user_id as string);
            c.set('firebaseEmail', (payload.email as string) || null);
            c.set('firebaseName', (payload.name as string) || null);
            
            await next();
        } catch (verifyError: any) {
            console.error('Error al verificar Firebase ID Token:', verifyError.message);
            return c.json({ 
                error: 'Token de Firebase inválido o expirado',
                details: verifyError.message
            }, 401);
        }
    } catch (error: any) {
        console.error('Error en validateFirebaseToken:', error);
        return c.json({ 
            error: 'Error al validar autenticación',
            details: error.message 
        }, 500);
    }
};

/**
 * MIDDLEWARE 0: Validación de BACKEND_API_TOKEN
 * 
 * Verifica que el header Authorization contenga el token secreto del backend.
 * Este es el primer nivel de autenticación para todos los endpoints.
 * 
 * Uso:
 * app.use('*', authMiddleware);
 */
export const authMiddleware = async (c: Context<{ Bindings: Env }>, next: Next) => {
    const secret = await c.env.SECRET.get();
    const authHeader = c.req.header('Authorization');
    
    if (!authHeader) {
        return c.json({ error: 'Unauthorized - No Authorization header' }, 401);
    }

    const token = authHeader.startsWith('Bearer ')
        ? authHeader.substring(7)
        : authHeader;

    if (token !== secret) {
        return c.json({ error: 'Unauthorized - Invalid token' }, 401);
    }

    return next();
};

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
        firebaseUid: string;
        firebaseEmail: string | null;
        firebaseName: string | null;
    }
}

/**
 * MIDDLEWARE 1: Autenticación de Usuario con JWT
 * 
 * Verifica el JWT firmado por el backend y extrae el firebase_uid del payload.
 * El JWT está firmado con el mismo SECRET compartido entre frontend y backend.
 * 
 * Este middleware NO requiere BACKEND_API_TOKEN - el JWT firmado es suficiente.
 * 
 * Uso:
 * app.use('/curso/*', authenticateUser);
 * 
 * Luego en las rutas puedes acceder a: c.get('user')
 */
export const authenticateUser = async (c: Context<{ Bindings: Env }>, next: Next) => {
    try {
        // Extraer el JWT del header X-Firebase-Token
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