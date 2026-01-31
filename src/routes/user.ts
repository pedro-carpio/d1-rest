import { Hono } from 'hono';
import { SignJWT } from 'jose';
import type { Env } from '../index';
import { authenticateUser, hashPassword, verifyPassword } from '../middleware/auth';
import { JWT_CONFIG, PASSWORD_CONFIG, USER_DEFAULTS, USER_ROLES } from '../config/constants';

const userRoutes = new Hono<{ Bindings: Env }>();

/**
 * Genera un JWT firmado con el user_id
 * 
 * El JWT contiene:
 * - user_id: identificador del usuario
 * - iat: timestamp de emisión
 * - exp: timestamp de expiración (24 horas)
 * 
 * @param userId - ID del usuario autenticado
 * @param secret - Secreto compartido para firmar el JWT
 * @returns JWT firmado
 */
async function generateJWT(userId: number, secret: string): Promise<string> {
    const secretKey = new TextEncoder().encode(secret);

    const jwt = await new SignJWT({ user_id: userId })
        .setProtectedHeader({ alg: JWT_CONFIG.ALGORITHM })
        .setIssuedAt()
        .setExpirationTime(JWT_CONFIG.EXPIRATION)
        .sign(secretKey);

    return jwt;
}

/**
 * POST /user/register
 * Registra un nuevo usuario en el sistema
 * 
 * Body JSON esperado:
 * {
 *   "email": "string (requerido)",
 *   "password": "string (requerido, mínimo 6 caracteres)",
 *   "full_name": "string (opcional)",
 *   "role_id": number (opcional, default: 2 - teacher)
 * }
 */
userRoutes.post('/register', async (c) => {
    try {
        const body = await c.req.json();
        const { email, password, full_name, role_id } = body;

        // Validaciones
        if (!email || !password) {
            return c.json({ 
                error: 'Email y contraseña son requeridos' 
            }, 400);
        }

        if (password.length < PASSWORD_CONFIG.MIN_LENGTH) {
            return c.json({ 
                error: `La contraseña debe tener al menos ${PASSWORD_CONFIG.MIN_LENGTH} caracteres` 
            }, 400);
        }

        // Verificar si el email ya existe
        const existingUser = await c.env.DB.prepare(
            'SELECT id FROM user_account WHERE email = ?'
        ).bind(email.toLowerCase()).first();

        if (existingUser) {
            return c.json({ 
                error: 'El email ya está registrado' 
            }, 409);
        }

        // Hashear la contraseña
        const passwordHash = await hashPassword(password);

        // Verificar que el role_id existe (default: teacher)
        const finalRoleId = role_id || USER_DEFAULTS.ROLE_ID;
        const roleExists = await c.env.DB.prepare(
            'SELECT id FROM role WHERE id = ?'
        ).bind(finalRoleId).first();

        if (!roleExists) {
            return c.json({ 
                error: `role_id no válido. Debe ser ${USER_ROLES.ADMIN} (admin), ${USER_ROLES.TEACHER} (teacher), ${USER_ROLES.DIRECTOR} (director) o ${USER_ROLES.SELLER} (seller)` 
            }, 400);
        }

        // Insertar el nuevo usuario (inactivo por defecto)
        const result = await c.env.DB.prepare(
            `INSERT INTO user_account (email, password_hash, full_name, role_id, is_active) 
             VALUES (?, ?, ?, ?, ?)`
        )
        .bind(
            email.toLowerCase(),
            passwordHash,
            full_name || null,
            finalRoleId,
            USER_DEFAULTS.IS_ACTIVE
        )
        .run();

        // Obtener el usuario recién creado
        const newUser = await c.env.DB.prepare(
            `SELECT u.id, u.email, u.full_name, u.role_id, r.name as role_name, u.is_active, u.created_at 
             FROM user_account u
             JOIN role r ON u.role_id = r.id
             WHERE u.id = ?`
        ).bind(result.meta.last_row_id).first();

        return c.json({
            message: 'Usuario registrado exitosamente. Un administrador debe activar tu cuenta.',
            user: {
                id: newUser!.id,
                email: newUser!.email,
                full_name: newUser!.full_name,
                role_id: newUser!.role_id,
                role_name: newUser!.role_name,
                is_active: newUser!.is_active,
                created_at: newUser!.created_at
            }
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
 *   "email": "string (requerido)",
 *   "password": "string (requerido)"
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
        const { email, password } = body;

        // Validaciones
        if (!email || !password) {
            return c.json({ 
                error: 'Email y contraseña son requeridos' 
            }, 400);
        }

        // Buscar el usuario en la base de datos
        const user = await c.env.DB.prepare(
            `SELECT u.id, u.email, u.password_hash, u.full_name, u.role_id, r.name as role_name, u.is_active, u.created_at
             FROM user_account u
             JOIN role r ON u.role_id = r.id
             WHERE u.email = ?`
        ).bind(email.toLowerCase()).first();

        if (!user) {
            return c.json({ 
                error: 'Email o contraseña incorrectos' 
            }, 401);
        }

        // Verificar la contraseña
        const passwordValid = await verifyPassword(password, user.password_hash as string);
        
        if (!passwordValid) {
            return c.json({ 
                error: 'Email o contraseña incorrectos' 
            }, 401);
        }

        // Verificar que el usuario esté activo
        if (!user.is_active) {
            return c.json({ 
                error: 'Usuario inactivo. Contacta al administrador para activar tu cuenta.',
                user: {
                    id: user.id,
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
        const jwt = await generateJWT(user.id as number, secret);

        return c.json({
            user: {
                id: user.id,
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
 * 
 * Headers requeridos:
 *   Authorization: Bearer <JWT>
 */
userRoutes.get('/me', authenticateUser, async (c) => {
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
