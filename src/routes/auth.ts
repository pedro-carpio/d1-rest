import { Hono } from 'hono';
import { SignJWT } from 'jose';
import type { Env } from '../index';
import { OAUTH_CONFIG, JWT_CONFIG, USER_DEFAULTS, REFRESH_TOKEN_CONFIG } from '../config/constants';

const authRoutes = new Hono<{ Bindings: Env }>();

function generateState(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(OAUTH_CONFIG.STATE_LENGTH));
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateRefreshToken(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(REFRESH_TOKEN_CONFIG.TOKEN_LENGTH));
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function generateJWT(userId: number, secret: string): Promise<string> {
    const secretKey = new TextEncoder().encode(secret);
    const jwt = await new SignJWT({ user_id: userId })
        .setProtectedHeader({ alg: JWT_CONFIG.ALGORITHM })
        .setIssuedAt()
        .setExpirationTime(JWT_CONFIG.EXPIRATION)
        .sign(secretKey);
    return jwt;
}

function capitalizeName(name: string): string {
    return name
        .toLowerCase()
        .split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}

authRoutes.get('/google', async (c) => {
    try {
        const googleClientId = await c.env.GOOGLE_CLIENT_ID?.get();
        
        if (!googleClientId) {
            return c.json({ 
                error: 'Google OAuth no configurado',
                message: 'GOOGLE_CLIENT_ID no encontrado en los secretos'
            }, 500);
        }

        const state = generateState();
        const baseUrl = new URL(c.req.url).origin;
        const redirectUri = `${baseUrl}${OAUTH_CONFIG.GOOGLE.CALLBACK_PATH}`;

        const authUrl = new URL(OAUTH_CONFIG.GOOGLE.AUTHORIZATION_URL);
        authUrl.searchParams.set('client_id', googleClientId);
        authUrl.searchParams.set('redirect_uri', redirectUri);
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('scope', OAUTH_CONFIG.GOOGLE.SCOPES.join(' '));
        authUrl.searchParams.set('state', state);
        authUrl.searchParams.set('access_type', 'offline');
        authUrl.searchParams.set('prompt', 'consent');

        return c.redirect(authUrl.toString());

    } catch (error: any) {
        console.error('Error en /auth/google:', error);
        return c.json({ 
            error: 'Error al iniciar autenticación con Google',
            details: error.message 
        }, 500);
    }
});

authRoutes.get('/handler', async (c) => {
    try {
        const code = c.req.query('code');
        const error = c.req.query('error');

        if (error) {
            return c.json({ 
                error: 'Error de Google OAuth',
                details: error 
            }, 400);
        }

        if (!code) {
            return c.json({ 
                error: 'Código de autorización no proporcionado' 
            }, 400);
        }

        const googleClientId = await c.env.GOOGLE_CLIENT_ID?.get();
        const googleClientSecret = await c.env.GOOGLE_CLIENT_SECRET?.get();

        if (!googleClientId || !googleClientSecret) {
            return c.json({ 
                error: 'Google OAuth no configurado correctamente' 
            }, 500);
        }

        const baseUrl = new URL(c.req.url).origin;
        const redirectUri = `${baseUrl}${OAUTH_CONFIG.GOOGLE.CALLBACK_PATH}`;

        const tokenResponse = await fetch(OAUTH_CONFIG.GOOGLE.TOKEN_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                code,
                client_id: googleClientId,
                client_secret: googleClientSecret,
                redirect_uri: redirectUri,
                grant_type: 'authorization_code',
            }),
        });

        if (!tokenResponse.ok) {
            const errorData = await tokenResponse.json();
            return c.json({ 
                error: 'Error al obtener token de Google',
                details: errorData 
            }, 400);
        }

        const tokenData = await tokenResponse.json() as { access_token: string };

        const userinfoResponse = await fetch(OAUTH_CONFIG.GOOGLE.USERINFO_URL, {
            headers: {
                'Authorization': `Bearer ${tokenData.access_token}`,
            },
        });

        if (!userinfoResponse.ok) {
            return c.json({ 
                error: 'Error al obtener información de usuario de Google' 
            }, 400);
        }

        const userinfo = await userinfoResponse.json() as {
            email: string;
            name: string;
            picture?: string;
            verified_email?: boolean;
        };

        if (!userinfo.email) {
            return c.json({ 
                error: 'Google no proporcionó un email' 
            }, 400);
        }

        const email = userinfo.email.toLowerCase();
        const fullName = capitalizeName(userinfo.name || '');

        let user = await c.env.DB.prepare(
            `SELECT u.id, u.email, u.full_name, u.role_id, r.name as role_name, u.is_active
             FROM user_account u
             JOIN role r ON u.role_id = r.id
             WHERE u.email = ?`
        ).bind(email).first();

        let userId: number;

        if (!user) {
            const result = await c.env.DB.prepare(
                `INSERT INTO user_account (email, full_name, role_id, is_active) 
                 VALUES (?, ?, ?, ?)`
            )
            .bind(email, fullName, USER_DEFAULTS.ROLE_ID, 1)
            .run();

            userId = result.meta.last_row_id as number;

            user = await c.env.DB.prepare(
                `SELECT u.id, u.email, u.full_name, u.role_id, r.name as role_name, u.is_active
                 FROM user_account u
                 JOIN role r ON u.role_id = r.id
                 WHERE u.id = ?`
            ).bind(userId).first();
        } else {
            userId = user.id as number;

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
        }

        const secret = await c.env.SECRET.get();
        if (!secret) {
            return c.json({ error: 'Configuración de secreto no encontrada' }, 500);
        }

        const jwt = await generateJWT(userId, secret);
        const refreshToken = generateRefreshToken();
        
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_CONFIG.EXPIRATION_DAYS);

        const deviceInfo = c.req.header('User-Agent') || 'Google OAuth';

        await c.env.DB.prepare(
            `INSERT INTO refresh_token (user_id, token, expires_at, device_info) 
             VALUES (?, ?, ?, ?)`
        )
        .bind(userId, refreshToken, expiresAt.toISOString(), deviceInfo)
        .run();

        // Usar FRONTEND_URL configurada
        const frontendBaseUrl = c.env.FRONTEND_URL || 'http://localhost:4200';
        
        console.log('🔄 Redirigiendo OAuth a:', frontendBaseUrl);
        
        const frontendUrl = new URL('/auth/callback', frontendBaseUrl);
        frontendUrl.searchParams.set('token', jwt);
        frontendUrl.searchParams.set('refresh_token', refreshToken);
        
        return c.redirect(frontendUrl.toString());

    } catch (error: any) {
        console.error('Error en /__/auth/handler:', error);
        
        // Usar FRONTEND_URL configurada
        const frontendBaseUrl = c.env.FRONTEND_URL || 'http://localhost:4200';
        
        const frontendUrl = new URL('/login', frontendBaseUrl);
        frontendUrl.searchParams.set('error', 'oauth_failed');
        frontendUrl.searchParams.set('message', error.message);
        return c.redirect(frontendUrl.toString());
    }
});

export default authRoutes;
