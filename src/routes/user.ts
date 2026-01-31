import { Hono } from 'hono';
import { SignJWT } from 'jose';
import type { Env } from '../index';

const userRoutes = new Hono<{ Bindings: Env }>();

/**
 * Genera un JWT firmado con el firebase_uid
 * 
 * El JWT contiene:
 * - firebase_uid: identificador del usuario
 * - iat: timestamp de emisión
 * - exp: timestamp de expiración (1 hora)
 * 
 * @param firebaseUid - UID del usuario autenticado de Firebase
 * @param secret - Secreto compartido para firmar el JWT
 * @returns JWT firmado
 */
async function generateJWT(firebaseUid: string, secret: string): Promise<string> {
    const secretKey = new TextEncoder().encode(secret);

    const jwt = await new SignJWT({ firebase_uid: firebaseUid })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(secretKey);

    return jwt;
}

/**
 * POST /user/register
 * Registra un nuevo usuario en el sistema
 * 
 * Body JSON esperado:
 * {
 *   "firebase_uid": "string (requerido)",
 *   "email": "string (opcional)",
 *   "full_name": "string (opcional)",
 *   "role_id": number (requerido, 1=admin, 2=teacher, 3=director, 4=seller),
 *   "is_active": number (opcional, default: 1)
 * }
 */
userRoutes.post('/register', async (c) => {
    try {
        const body = await c.req.json();
        const { firebase_uid, email, full_name, role_id, is_active } = body;

        // Validaciones
        if (!firebase_uid || typeof firebase_uid !== 'string') {
            return c.json({ 
                error: 'firebase_uid es requerido y debe ser un string' 
            }, 400);
        }

        if (!role_id || typeof role_id !== 'number') {
            return c.json({ 
                error: 'role_id es requerido y debe ser un número (1=admin, 2=teacher, 3=director, 4=seller)' 
            }, 400);
        }

        // Verificar si el usuario ya existe
        const existingUser = await c.env.DB.prepare(
            'SELECT id FROM user_account WHERE firebase_uid = ?'
        ).bind(firebase_uid).first();

        if (existingUser) {
            return c.json({ 
                error: 'Usuario ya existe con este firebase_uid' 
            }, 409);
        }

        // Verificar que el role_id existe
        const roleExists = await c.env.DB.prepare(
            'SELECT id FROM role WHERE id = ?'
        ).bind(role_id).first();

        if (!roleExists) {
            return c.json({ 
                error: 'role_id no válido. Debe ser 1 (admin), 2 (teacher), 3 (director) o 4 (seller)' 
            }, 400);
        }

        // Insertar el nuevo usuario
        const result = await c.env.DB.prepare(
            `INSERT INTO user_account (firebase_uid, email, full_name, role_id, is_active) 
             VALUES (?, ?, ?, ?, ?)`
        )
        .bind(
            firebase_uid,
            email || null,
            full_name || null,
            role_id,
            is_active !== undefined ? is_active : 1
        )
        .run();

        // Obtener el usuario recién creado
        const newUser = await c.env.DB.prepare(
            'SELECT id, firebase_uid, email, full_name, role_id, is_active, created_at FROM user_account WHERE id = ?'
        ).bind(result.meta.last_row_id).first();

        // Generar JWT para el usuario registrado
        const secret = await c.env.SECRET.get();
        if (!secret) {
            return c.json({ error: 'Configuración de secreto no encontrada' }, 500);
        }
        const jwt = await generateJWT(firebase_uid, secret);

        return c.json({
            message: 'Usuario registrado exitosamente',
            user: newUser,
            token: jwt
        }, 201);

    } catch (error: any) {
        console.error('Error en /user/register:', error);
        return c.json({ 
            error: 'Error al registrar usuario',
            details: error.message 
        }, 500);
    }
});

/**
 * POST /user/login
 * Autentica un usuario existente y devuelve un JWT
 * 
 * Body JSON esperado:
 * {
 *   "firebase_uid": "string (requerido)"
 * }
 * 
 * Respuesta:
 * {
 *   "user": { ... },
 *   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 * }
 */
userRoutes.post('/login', async (c) => {
    try {
        const body = await c.req.json();
        const { firebase_uid } = body;

        // Validaciones
        if (!firebase_uid || typeof firebase_uid !== 'string') {
            return c.json({ 
                error: 'firebase_uid es requerido y debe ser un string' 
            }, 400);
        }

        // Buscar el usuario en la base de datos
        const user = await c.env.DB.prepare(
            `SELECT u.id, u.firebase_uid, u.email, u.full_name, u.role_id, r.name as role_name, u.is_active, u.created_at
             FROM user_account u
             JOIN role r ON u.role_id = r.id
             WHERE u.firebase_uid = ?`
        ).bind(firebase_uid).first();

        if (!user) {
            return c.json({ 
                error: 'Usuario no encontrado' 
            }, 404);
        }

        if (!user.is_active) {
            return c.json({ 
                error: 'Usuario inactivo. Contacta al administrador para activar tu cuenta.',
                user: {
                    id: user.id,
                    firebase_uid: user.firebase_uid,
                    email: user.email,
                    full_name: user.full_name,
                    role_id: user.role_id,
                    role_name: user.role_name,
                    is_active: user.is_active
                }
            }, 403);
        }

        // Generar JWT para el usuario
        const secret = await c.env.SECRET.get();
        if (!secret) {
            return c.json({ error: 'Configuración de secreto no encontrada' }, 500);
        }
        const jwt = await generateJWT(firebase_uid, secret);

        return c.json({
            user: {
                id: user.id,
                firebase_uid: user.firebase_uid,
                email: user.email,
                full_name: user.full_name,
                role_id: user.role_id,
                role_name: user.role_name,
                is_active: user.is_active,
                created_at: user.created_at
            },
            token: jwt
        });

    } catch (error: any) {
        console.error('Error en /user/login:', error);
        return c.json({ 
            error: 'Error al autenticar usuario',
            details: error.message 
        }, 500);
    }
});

/**
 * GET /user/me
 * Obtiene la información del usuario actual basado en el JWT
 * NO requiere query params - el firebase_uid se extrae del JWT verificado
 * 
 * REQUIERE: authenticateUser middleware (obtiene firebase_uid del JWT)
 */
userRoutes.get('/me', async (c) => {
    try {
        // El usuario ya fue autenticado por authenticateUser middleware
        const user = c.get('user');
        
        if (!user) {
            return c.json({ 
                error: 'Usuario no autenticado' 
            }, 401);
        }

        return c.json({ user });

    } catch (error: any) {
        console.error('Error en /user/me:', error);
        return c.json({ 
            error: 'Error al obtener usuario',
            details: error.message 
        }, 500);
    }
});

export default userRoutes;
