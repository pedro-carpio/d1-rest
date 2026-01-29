import { Hono } from 'hono';
import type { Env } from '../index';

const userRoutes = new Hono<{ Bindings: Env }>();

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

        return c.json({
            message: 'Usuario registrado exitosamente',
            user: newUser
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
 * GET /user/me
 * Obtiene la información del usuario actual basado en su firebase_uid
 * Query param: firebase_uid
 */
userRoutes.get('/me', async (c) => {
    try {
        const firebase_uid = c.req.query('firebase_uid');

        if (!firebase_uid) {
            return c.json({ 
                error: 'firebase_uid es requerido como query parameter' 
            }, 400);
        }

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
