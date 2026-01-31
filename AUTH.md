# Sistema de Autenticación

Sistema de autenticación propio con email/password, JWT de corta duración y refresh tokens de larga duración.

## Arquitectura

### Componentes

1. **Password Hashing**: PBKDF2 con 100,000 iteraciones, SHA-256, salt aleatorio de 16 bytes
2. **JWT**: Tokens de corta duración (1 hora) firmados con HS256
3. **Refresh Tokens**: Tokens de larga duración (100 días) para renovar JWTs sin reautenticación
4. **Password Reset**: Tokens de reset generados por admin (24 horas de validez)

### Flujo de Autenticación

```
Usuario → POST /user/register → Cuenta inactiva → Admin activa → POST /user/login → JWT + Refresh Token
                                                                                            ↓
                                                                                    JWT expira (1h)
                                                                                            ↓
                                                                         POST /user/refresh-token → Nuevo JWT
```

## Endpoints

### Públicos (sin autenticación)

#### `POST /user/register`
Crea una cuenta nueva.

**Modos de operación:**
- **Sin SECRET**: Crea cuenta teacher/director/seller (inactiva, requiere activación admin)
- **Con SECRET**: Crea cualquier rol incluyendo admin (activa inmediatamente)

**Body:**
```json
{
  "email": "usuario@ejemplo.com",
  "password": "contraseña",
  "full_name": "Nombre Completo",
  "role_id": 2  // opcional, default: 2 (teacher)
}
```

**Headers (opcional para admin):**
```
Authorization: Bearer {SECRET}
```

**Respuesta:**
```json
{
  "message": "Usuario registrado...",
  "user": {
    "id": 1,
    "email": "usuario@ejemplo.com",
    "full_name": "Nombre Completo",
    "role_id": 2,
    "role_name": "teacher",
    "is_active": 0,
    "created_at": "2026-01-31T..."
  }
}
```

---

#### `POST /user/login`
Autentica y retorna JWT + refresh token.

**Body:**
```json
{
  "email": "usuario@ejemplo.com",
  "password": "contraseña"
}
```

**Respuesta:**
```json
{
  "user": {
    "id": 1,
    "email": "usuario@ejemplo.com",
    "full_name": "Nombre Completo",
    "role_id": 2,
    "role_name": "teacher",
    "is_active": 1,
    "created_at": "2026-01-31T..."
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "a1b2c3d4e5f6...",
  "expires_in": "1h"
}
```

**Notas:**
- Guarda `token` (JWT) para requests autenticados
- Guarda `refresh_token` para renovar el JWT cuando expire
- Captura `User-Agent` para tracking de dispositivos

---

#### `POST /user/refresh-token`
Renueva el JWT usando un refresh token válido.

**Body:**
```json
{
  "refresh_token": "a1b2c3d4e5f6..."
}
```

**Respuesta:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": "1h"
}
```

**Errores:**
- `401`: Token inválido, revocado o expirado
- `403`: Usuario inactivo

---

#### `POST /user/revoke-token`
Revoca un refresh token específico (logout de un dispositivo).

**Body:**
```json
{
  "refresh_token": "a1b2c3d4e5f6..."
}
```

**Respuesta:**
```json
{
  "message": "Refresh token revocado exitosamente"
}
```

---

#### `POST /user/reset-password`
Cambia contraseña usando token de reset generado por admin.

**Body:**
```json
{
  "token": "abc123...",
  "new_password": "nuevaContraseña"
}
```

**Respuesta:**
```json
{
  "message": "Contraseña actualizada exitosamente",
  "user": { ... },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Notas:**
- El token de reset se marca como usado después del cambio
- Retorna un JWT para auto-login después del reset

---

### Protegidos (requieren JWT)

Todos los endpoints protegidos requieren header:
```
Authorization: Bearer {JWT}
```

#### `GET /user/me`
Retorna información del usuario actual.

**Respuesta:**
```json
{
  "user": {
    "userId": 1,
    "email": "usuario@ejemplo.com",
    "fullName": "Nombre Completo",
    "roleId": 2,
    "roleName": "teacher",
    "isActive": true
  }
}
```

---

#### `DELETE /user/logout-all`
Revoca todos los refresh tokens del usuario (cierra todas las sesiones).

**Respuesta:**
```json
{
  "message": "Todas las sesiones han sido cerradas exitosamente"
}
```

---

### Admin Only

Requieren JWT de usuario con rol `admin`.

#### `POST /user/admin/generate-reset-token`
Genera un token de reset de contraseña para cualquier usuario.

**Body:**
```json
{
  "user_id": 5
}
```

**Respuesta:**
```json
{
  "message": "Token de reset generado exitosamente",
  "reset_token": "abc123...",
  "expires_at": "2026-02-01T12:00:00Z",
  "expires_in_hours": 24,
  "user": {
    "id": 5,
    "email": "usuario@ejemplo.com",
    "full_name": "Nombre Completo",
    "role_id": 2,
    "role_name": "teacher"
  }
}
```

**Uso:**
1. Admin genera el token
2. Admin envía el token al usuario (email, WhatsApp, etc.)
3. Usuario usa el token en `/user/reset-password`

---

## Roles de Usuario

| ID | Nombre    | Descripción |
|----|-----------|-------------|
| 1  | admin     | Acceso total, puede crear otros admins |
| 2  | teacher   | Profesor, gestiona sus cursos |
| 3  | director  | Director de unidad educativa |
| 4  | seller    | Vendedor de suscripciones |

---

## Estados de Usuario

- `is_active = 0`: Usuario registrado pero inactivo (no puede hacer login)
- `is_active = 1`: Usuario activo (puede hacer login)

**Regla:**
- Registro público → `is_active = 0` (requiere activación admin)
- Registro con SECRET → `is_active = 1` (activo inmediatamente)

---

## Seguridad

### Password Hashing
- Algoritmo: PBKDF2
- Iteraciones: 100,000
- Hash: SHA-256
- Salt: 16 bytes aleatorios
- Output: 256 bits (32 bytes)
- Formato almacenado: `{salt}{hash}` en hexadecimal

### JWT
- Algoritmo: HS256
- Expiración: 1 hora
- Payload: `{ user_id: number, iat: timestamp, exp: timestamp }`
- Firma: SECRET del backend (Cloudflare Secrets Store)

### Refresh Tokens
- Longitud: 32 bytes (64 caracteres hexadecimales)
- Expiración: 100 días
- Almacenamiento: Tabla `refresh_token` en D1
- Revocación: Flag `revoked = 1`
- Tracking: `device_info` (User-Agent), `last_used_at`

### Password Reset Tokens
- Longitud: 32 bytes (64 caracteres hexadecimales)
- Expiración: 24 horas
- Uso único: Flag `used = 1` después del reset
- Generación: Solo admin
- Invalidación: Tokens viejos se marcan como usados al generar uno nuevo

---

## Configuración

Todas las constantes en `src/config/constants.ts`:

```typescript
export const PASSWORD_CONFIG = {
    MIN_LENGTH: 6,
    PBKDF2_ITERATIONS: 100000,
    SALT_LENGTH: 16,
    HASH_ALGORITHM: 'SHA-256',
    KEY_LENGTH: 256,
};

export const JWT_CONFIG = {
    ALGORITHM: 'HS256',
    EXPIRATION: '1h',
};

export const REFRESH_TOKEN_CONFIG = {
    TOKEN_LENGTH: 32,
    EXPIRATION_DAYS: 100,
};

export const PASSWORD_RESET_CONFIG = {
    TOKEN_LENGTH: 32,
    EXPIRATION_HOURS: 24,
};
```

---

## Migraciones

### 0008_password_hash
- Elimina `firebase_uid`
- Agrega `password_hash TEXT NOT NULL`
- Hace `email` UNIQUE y NOT NULL

### 0009_password_reset_tokens
- Tabla `password_reset_token`
- Campos: `user_id`, `token`, `expires_at`, `used`

### 0010_refresh_tokens
- Tabla `refresh_token`
- Campos: `user_id`, `token`, `expires_at`, `revoked`, `device_info`, `last_used_at`

---

## Ejemplos de Integración Frontend

### Login y almacenamiento de tokens
```typescript
const response = await fetch('/user/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password })
});

const { token, refresh_token, user } = await response.json();

// Almacenar en localStorage/sessionStorage
localStorage.setItem('jwt', token);
localStorage.setItem('refresh_token', refresh_token);
localStorage.setItem('user', JSON.stringify(user));
```

### Renovar JWT cuando expire
```typescript
async function refreshJWT() {
  const refreshToken = localStorage.getItem('refresh_token');
  
  const response = await fetch('/user/refresh-token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken })
  });
  
  const { token } = await response.json();
  localStorage.setItem('jwt', token);
  return token;
}

// Interceptor de requests
async function authenticatedFetch(url, options = {}) {
  let jwt = localStorage.getItem('jwt');
  
  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${jwt}`
    }
  });
  
  // Si el JWT expiró, renovar y reintentar
  if (response.status === 401) {
    jwt = await refreshJWT();
    return fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${jwt}`
      }
    });
  }
  
  return response;
}
```

### Logout (cerrar sesión actual)
```typescript
async function logout() {
  const refreshToken = localStorage.getItem('refresh_token');
  
  await fetch('/user/revoke-token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken })
  });
  
  localStorage.removeItem('jwt');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('user');
}
```

### Logout global (cerrar todas las sesiones)
```typescript
async function logoutAll() {
  const jwt = localStorage.getItem('jwt');
  
  await fetch('/user/logout-all', {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${jwt}` }
  });
  
  localStorage.removeItem('jwt');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('user');
}
```
