import { Hono } from 'hono';
import { SignJWT } from 'jose';
import type { Env } from '../index';
import { OAUTH_CONFIG, JWT_CONFIG, USER_DEFAULTS, REFRESH_TOKEN_CONFIG } from '../config/constants';
import { getSecret, getGoogleClientId, getGoogleClientSecret } from '../utils/secrets';

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
        const googleClientId = await getGoogleClientId(c.env);
        
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
        console.log('🔵 [OAuth Handler] Iniciando callback de Google OAuth');
        
        const code = c.req.query('code');
        const error = c.req.query('error');
        const state = c.req.query('state');

        console.log('🔵 [OAuth Handler] Query params recibidos:', {
            hasCode: !!code,
            hasError: !!error,
            hasState: !!state,
            url: c.req.url
        });

        if (error) {
            console.error('🔴 [OAuth Handler] Error de Google:', error);
            throw new Error(`Error de Google OAuth: ${error}`);
        }

        if (!code) {
            console.error('🔴 [OAuth Handler] Código de autorización no proporcionado');
            throw new Error('Código de autorización no proporcionado');
        }

        const googleClientId = await getGoogleClientId(c.env);
        const googleClientSecret = await getGoogleClientSecret(c.env);

        console.log('🔵 [OAuth Handler] Configuración OAuth:', {
            hasClientId: !!googleClientId,
            hasClientSecret: !!googleClientSecret
        });

        if (!googleClientId || !googleClientSecret) {
            console.error('🔴 [OAuth Handler] Google OAuth no configurado correctamente');
            throw new Error('Google OAuth no configurado correctamente');
        }

        const baseUrl = new URL(c.req.url).origin;
        const redirectUri = `${baseUrl}${OAUTH_CONFIG.GOOGLE.CALLBACK_PATH}`;
        
        console.log('🔵 [OAuth Handler] Redirect URI:', redirectUri);

        console.log('🔵 [OAuth Handler] Intercambiando código por token...');
        
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

        console.log('🔵 [OAuth Handler] Respuesta de Google token:', {
            status: tokenResponse.status,
            ok: tokenResponse.ok
        });

        if (!tokenResponse.ok) {
            const errorData = await tokenResponse.json();
            console.error('🔴 [OAuth Handler] Error al obtener token:', errorData);
            throw new Error(`Error al obtener token de Google: ${JSON.stringify(errorData)}`);
        }

        const tokenData = await tokenResponse.json() as { access_token: string };
        console.log('✅ [OAuth Handler] Token de acceso obtenido');

        console.log('🔵 [OAuth Handler] Obteniendo información del usuario de Google...');
        
        const userinfoResponse = await fetch(OAUTH_CONFIG.GOOGLE.USERINFO_URL, {
            headers: {
                'Authorization': `Bearer ${tokenData.access_token}`,
            },
        });

        console.log('🔵 [OAuth Handler] Respuesta de userinfo:', {
            status: userinfoResponse.status,
            ok: userinfoResponse.ok
        });

        if (!userinfoResponse.ok) {
            console.error('🔴 [OAuth Handler] Error al obtener información de usuario');
            throw new Error('Error al obtener información de usuario de Google');
        }

        const userinfo = await userinfoResponse.json() as {
            email: string;
            name: string;
            picture?: string;
            verified_email?: boolean;
        };

        console.log('🔵 [OAuth Handler] Información del usuario:', {
            email: userinfo.email,
            name: userinfo.name,
            verified: userinfo.verified_email
        });

        if (!userinfo.email) {
            console.error('🔴 [OAuth Handler] Google no proporcionó email');
            throw new Error('Google no proporcionó un email');
        }

        const email = userinfo.email.toLowerCase();
        const fullName = capitalizeName(userinfo.name || '');
        
        console.log('🔵 [OAuth Handler] Buscando usuario en BD:', email);

        let user = await c.env.DB.prepare(
            `SELECT u.id, u.email, u.full_name, u.role_id, r.name as role_name, u.is_active
             FROM user_account u
             JOIN role r ON u.role_id = r.id
             WHERE u.email = ?`
        ).bind(email).first();

        let userId: number;

        if (!user) {
            console.log('🔵 [OAuth Handler] Usuario nuevo - creando cuenta');
            
            const result = await c.env.DB.prepare(
                `INSERT INTO user_account (email, full_name, role_id, is_active) 
                 VALUES (?, ?, ?, ?)`
            )
            .bind(email, fullName, USER_DEFAULTS.ROLE_ID, 1)
            .run();

            userId = result.meta.last_row_id as number;
            console.log('✅ [OAuth Handler] Usuario creado con ID:', userId);

            user = await c.env.DB.prepare(
                `SELECT u.id, u.email, u.full_name, u.role_id, r.name as role_name, u.is_active
                 FROM user_account u
                 JOIN role r ON u.role_id = r.id
                 WHERE u.id = ?`
            ).bind(userId).first();
        } else {
            console.log('🔵 [OAuth Handler] Usuario existente encontrado:', {
                id: user.id,
                email: user.email,
                is_active: user.is_active
            });
            
            userId = user.id as number;

            if (!user.is_active) {
                console.error('🔴 [OAuth Handler] Usuario inactivo');
                throw new Error('Usuario inactivo. Contacta al administrador para activar tu cuenta.');
            }
        }

        console.log('🔵 [OAuth Handler] Generando JWT...');
        
        const secret = await getSecret(c.env);
        if (!secret) {
            console.error('🔴 [OAuth Handler] Secreto no encontrado');
            throw new Error('Configuración de secreto no encontrada');
        }

        const jwt = await generateJWT(userId, secret);
        const refreshToken = generateRefreshToken();
        
        console.log('✅ [OAuth Handler] Tokens generados:', {
            jwtLength: jwt.length,
            refreshTokenLength: refreshToken.length
        });
        
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_CONFIG.EXPIRATION_DAYS);

        const deviceInfo = c.req.header('User-Agent') || 'Google OAuth';

        console.log('🔵 [OAuth Handler] Guardando refresh token en BD...');
        
        await c.env.DB.prepare(
            `INSERT INTO refresh_token (user_id, token, expires_at, device_info) 
             VALUES (?, ?, ?, ?)`
        )
        .bind(userId, refreshToken, expiresAt.toISOString(), deviceInfo)
        .run();

        console.log('✅ [OAuth Handler] Refresh token guardado');

        // Usar FRONTEND_URL configurada
        const frontendBaseUrl = c.env.FRONTEND_URL || 'http://localhost:4200';
        
        const frontendUrl = new URL('/auth/callback', frontendBaseUrl);
        frontendUrl.searchParams.set('token', jwt);
        frontendUrl.searchParams.set('refresh_token', refreshToken);
        
        const redirectUrl = frontendUrl.toString();
        
        console.log('🟢 [OAuth Handler] Redirigiendo a frontend:', {
            baseUrl: frontendBaseUrl,
            path: '/auth/callback',
            hasToken: true,
            hasRefreshToken: true,
            fullUrl: redirectUrl
        });
        
        return c.redirect(redirectUrl);

    } catch (error: any) {
        console.error('🔴 [OAuth Handler] ERROR CRÍTICO:', {
            message: error.message,
            stack: error.stack,
            name: error.name
        });
        
        // Usar FRONTEND_URL configurada
        const frontendBaseUrl = c.env.FRONTEND_URL || 'http://localhost:4200';
        
        const frontendUrl = new URL('/login', frontendBaseUrl);
        frontendUrl.searchParams.set('error', 'oauth_failed');
        frontendUrl.searchParams.set('message', error.message);
        
        const errorRedirectUrl = frontendUrl.toString();
        
        console.log('🔴 [OAuth Handler] Redirigiendo a error:', errorRedirectUrl);
        
        return c.redirect(errorRedirectUrl);
    }
});

export default authRoutes;
