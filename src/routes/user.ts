import { Hono } from 'hono';
import { SignJWT } from 'jose';
import type { Env } from '../index';
import { authenticateUser, hashPassword, verifyPassword, requireRoles } from '../middleware/auth';
import { JWT_CONFIG, PASSWORD_CONFIG, USER_DEFAULTS, USER_ROLES, PASSWORD_RESET_CONFIG } from '../config/constants';

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
 * Genera un token aleatorio seguro para reset de contraseña
 * @returns Token hexadecimal de 64 caracteres (32 bytes)
 */
function generateResetToken(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(PASSWORD_RESET_CONFIG.TOKEN_LENGTH));
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
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

/**
 * POST /user/admin/generate-reset-token
 * Genera un token de reset de contraseña para un usuario (solo admin)
 * 
 * Body JSON esperado:
 * {
 *   "user_id": number (requerido) - ID del usuario al que se le generará el token
 * }
 * 
 * Respuesta:
 * {
 *   "reset_token": "abc123...",
 *   "reset_link": "https://tu-frontend.com/reset-password?token=abc123...",
 *   "expires_at": "2026-02-01T12:00:00Z",
 *   "user": { ... }
 * }
 */
userRoutes.post('/admin/generate-reset-token', authenticateUser, requireRoles(['admin']), async (c) => {
    try {
        const body = await c.req.json();
        const { user_id } = body;

        if (!user_id) {
            return c.json({ 
                error: 'user_id es requerido' 
            }, 400);
        }

        // Verificar que el usuario existe
        const targetUser = await c.env.DB.prepare(
            `SELECT u.id, u.email, u.full_name, u.role_id, r.name as role_name 
             FROM user_account u
             JOIN role r ON u.role_id = r.id
             WHERE u.id = ?`
        ).bind(user_id).first();

        if (!targetUser) {
            return c.json({ 
                error: 'Usuario no encontrado' 
            }, 404);
        }

        // Invalidar tokens existentes del usuario
        await c.env.DB.prepare(
            'UPDATE password_reset_token SET used = 1 WHERE user_id = ? AND used = 0'
        ).bind(user_id).run();

        // Generar nuevo token
        const resetToken = generateResetToken();
        
        // Calcular fecha de expiración
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + PASSWORD_RESET_CONFIG.EXPIRATION_HOURS);

        // Guardar token en la base de datos
        await c.env.DB.prepare(
            `INSERT INTO password_reset_token (user_id, token, expires_at) 
             VALUES (?, ?, ?)`
        )
        .bind(user_id, resetToken, expiresAt.toISOString())
        .run();

        return c.json({
            message: 'Token de reset generado exitosamente',
            reset_token: resetToken,
            expires_at: expiresAt.toISOString(),
            expires_in_hours: PASSWORD_RESET_CONFIG.EXPIRATION_HOURS,
            user: {
                id: targetUser.id,
                email: targetUser.email,
                full_name: targetUser.full_name,
                role_id: targetUser.role_id,
                role_name: targetUser.role_name
            }
        }, 201);

    } catch (error: any) {
        console.error('Error en /user/admin/generate-reset-token:', error);
        return c.json({ 
            error: 'Error al generar token de reset',
            details: error.message 
        }, 500);
    }
});

/**
 * POST /user/reset-password
 * Permite al usuario cambiar su contraseña usando un token válido (endpoint público)
 * 
 * Body JSON esperado:
 * {
 *   "token": "string (requerido) - Token de reset recibido",
 *   "new_password": "string (requerido, mínimo 6 caracteres)"
 * }
 * 
 * Respuesta:
 * {
 *   "message": "Contraseña actualizada exitosamente",
 *   "user": { ... },
 *   "token": "JWT para iniciar sesión automáticamente"
 * }
 */
userRoutes.post('/reset-password', async (c) => {
    try {
        const body = await c.req.json();
        const { token, new_password } = body;

        // Validaciones
        if (!token || !new_password) {
            return c.json({ 
                error: 'Token y nueva contraseña son requeridos' 
            }, 400);
        }

        if (new_password.length < PASSWORD_CONFIG.MIN_LENGTH) {
            return c.json({ 
                error: `La contraseña debe tener al menos ${PASSWORD_CONFIG.MIN_LENGTH} caracteres` 
            }, 400);
        }

        // Buscar el token en la base de datos
        const resetToken = await c.env.DB.prepare(
            `SELECT rt.id, rt.user_id, rt.expires_at, rt.used,
                    u.id as user_id, u.email, u.full_name, u.role_id, r.name as role_name
             FROM password_reset_token rt
             JOIN user_account u ON rt.user_id = u.id
             JOIN role r ON u.role_id = r.id
             WHERE rt.token = ?`
        ).bind(token).first();

        if (!resetToken) {
            return c.json({ 
                error: 'Token de reset inválido' 
            }, 401);
        }

        // Verificar que el token no haya sido usado
        if (resetToken.used) {
            return c.json({ 
                error: 'Este token de reset ya fue utilizado' 
            }, 401);
        }

        // Verificar que el token no haya expirado
        const now = new Date();
        const expiresAt = new Date(resetToken.expires_at as string);
        
        if (now > expiresAt) {
            return c.json({ 
                error: 'El token de reset ha expirado. Solicita uno nuevo al administrador.' 
            }, 401);
        }

        // Hashear la nueva contraseña
        const newPasswordHash = await hashPassword(new_password);

        // Actualizar la contraseña del usuario
        await c.env.DB.prepare(
            'UPDATE user_account SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
        ).bind(newPasswordHash, resetToken.user_id).run();

        // Marcar el token como usado
        await c.env.DB.prepare(
            'UPDATE password_reset_token SET used = 1 WHERE id = ?'
        ).bind(resetToken.id).run();

        // Generar JWT para que el usuario inicie sesión automáticamente
        const secret = await c.env.SECRET.get();
        if (!secret) {
            return c.json({ error: 'Configuración de secreto no encontrada' }, 500);
        }
        const jwt = await generateJWT(resetToken.user_id as number, secret);

        return c.json({
            message: 'Contraseña actualizada exitosamente',
            user: {
                id: resetToken.user_id,
                email: resetToken.email,
                full_name: resetToken.full_name,
                role_id: resetToken.role_id,
                role_name: resetToken.role_name
            },
            token: jwt
        });

    } catch (error: any) {
        console.error('Error en /user/reset-password:', error);
        return c.json({ 
            error: 'Error al resetear contraseña',
            details: error.message 
        }, 500);
    }
});

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
