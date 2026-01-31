# Copilot Instructions: Cuaderno Pedagógico Backend

## Architecture Overview
Cloudflare Workers backend usando Hono framework y D1 (SQLite) con sistema de autenticación propio (email/password + OAuth 2.0).

- **Entry**: [src/index.ts](../src/index.ts) - Hono app con CORS y rutas
- **REST Logic**: [src/rest.ts](../src/rest.ts) - CRUD genérico (GET/POST/PATCH/DELETE)
- **Database**: Cloudflare D1 (SQLite) bound como `env.DB`
- **Auth**: Sistema propio con PBKDF2, JWT (1h), refresh tokens (100 días) y OAuth 2.0 (Google)
- **Secrets**: Cloudflare Secrets Store - `SECRET` (JWT), `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`

## Domain Model (Sistema Educativo Boliviano)

**Tablas principales:**
- `user_account`, `role` - Cuentas de usuario con roles (admin/teacher/director/seller)
- `curso` - Cursos escolares vinculados a profesores
- `estudiante`, `tutor`, `estudiante_tutor` - Estudiantes y tutores
- `refresh_token`, `password_reset_token` - Gestión de sesiones y recuperación de contraseña

**Conceptos clave:**
- Sistema trimestral (3 trimestres por año)
- Turnos duales: mañana/tarde
- Campos curriculares: COSMOS Y PENSAMIENTO, COMUNIDAD Y SOCIEDAD, VIDA TIERRA Y TERRITORIO, CIENCIA TECNOLOGIA Y PRODUCCION

## Development Workflow

### Local Development
```bash
pnpm dev              # Start local dev server with wrangler
```

### Database Migrations

Migrations are **manually applied** using wrangler CLI - no automated migration runner exists:

```bash
# Apply a migration to remote D1
wrangler d1 execute tutor-tools --remote --file=migrations/0007_pdc_structure/up.sql

# Apply to local D1
wrangler d1 execute tutor-tools --local --file=migrations/0007_pdc_structure/up.sql

# Create new local D1 database (first-time setup)
wrangler d1 create tutor-tools
# Copy database_id from output to wrangler.jsonc
```

**Migration structure**: `migrations/{number}_{name}/up.sql` and `down.sql`
- **Always** use `PRAGMA foreign_keys = ON;` at the top
- Track versions in `schema_migrations` table (created in 0000_schema/up.sql)
- Use `INSERT OR IGNORE INTO schema_migrations (version) VALUES ('xxxx_name');`
- Number migrations sequentially: `0001`, `0002`, etc.
- Test locally first, then apply to remote

### Deployment
```bash
pnpm run deploy       # Deploy to Cloudflare Workers
```

## Code Patterns & Conventions

### SQL Injection Prevention
**All identifiers** (table names, column names) go through `sanitizeIdentifier()` and `sanitizeKeyword()` in [rest.ts](../src/rest.ts):
```typescript
function sanitizeIdentifier(identifier: string): string {
    return identifier.replace(/[^a-zA-Z0-9_]/g, '');
}
function sanitizeKeyword(identifier: string): string {
    return '`'+sanitizeIdentifier(identifier)+'`';
}
```
**Always** use these functions when building dynamic SQL - never concatenate user input directly.

### REST API Patterns
The `/rest/{table}/{id?}` endpoint auto-generates CRUD operations:
- **GET** supports filtering (`?age=25`), sorting (`?sort_by=name&order=desc`), pagination (`?limit=10&offset=20`)
- **POST** creates records from JSON body
- **PATCH** updates by ID
- **DELETE** removes by ID

Example from code comments in [index.ts](../src/index.ts#L12-L25):
```typescript
// GET /rest/users?age=25&sort_by=name&order=desc
// POST /rest/users { "name": "John", "age": 30 }
// PATCH /rest/users/123 { "age": 31 }
// DELETE /rest/users/123
```

### Authentication Pattern
**Two-step auth check** in [index.ts](../src/index.ts#L45-L60):
1. Extract `Authorization` header (supports `Bearer <token>` or raw token)
2. Compare against System
Sistema de autenticación propio documentado en [AUTH.md](../AUTH.md):

**Endpoints públicos:**
- `GET /auth/google` - Inicia OAuth con Google
- `GET /__/auth/handler` - Callback de Google OAuth (unifica cuentas por email, mantiene ambos métodos)
- `POST /user/register` - Registro email/password (inactivo por defecto, activo si usa SECRET)
- `POST /user/login` - Login retorna JWT + refresh_token
- `POST /user/refresh-token` - Renueva JWT con refresh token
- `POST /user/revoke-token` - Revoca refresh token (logout dispositivo)
- `POST /user/reset-password` - Cambia contraseña con token de reset

**Métodos de autenticación:**
- Usuario con `password_hash` != NULL → puede login con email/password
- Usuario registrado vía OAuth → puede login con Google
- Un usuario puede tener **ambos métodos activos simultáneamente**

**Endpoints protegidos (requieren JWT):**
- `GET /user/me` - Perfil del usuario actual
- `DELETE /user/logout-all` - Cierra todas las sesiones
- `POST /user/admin/generate-reset-token` - Admin genera token de reset (solo admin)

**Endpoints genéricos:**
- `/rest/*` - CRUD genérico (público, sin autenticación)
- `/curso/*` - Gestión de cursos (requiere JWT)
- `/query` - SQL queries (público)

### Bindings
- `DB: D1Database`, `SECRET: SecretsStoreSecret`, `GOOGLE_CLIENT_ID: SecretsStoreSecret`, `GOOGLE_CLIENT_SECRET: SecretsStoreSecret`
- Hono context typed as `Context<{ Bindings: Env }>`
- Access bindings via `c.env.DB` or `env.DB` depending on context

## Configuration

### Wrangler Setup ([wrangler.jsonc](../wrangler.jsonc))
```jsonc
{
  "d1_databases": [{
    "benticación y Autorización

Ver documentación completa en [AUTH.md](../AUTH.md).

### Middleware Stack ([middleware/auth.ts](../src/middleware/auth.ts))

1. **`hashPassword(password)`**: Hashea contraseña con PBKDF2 (100k iteraciones, SHA-256)
2. **`verifyPassword(password, hash)`**: Verifica contraseña contra hash
3. **`authenticateUser`**: Extrae JWT del header `Authorization: Bearer {token}`, verifica firma, carga usuario en contexto
4. **`requireRoles(['admin', 'teacher'])`**: RBAC check - verifica rol del usuario
5. **`verifyCursoOwnership`**: Teachers solo editan sus propios cursos
6. **`injectUserCursoFilter`**: Auto-filtra queries (admin ve todo, teacher solo lo suyo)

**Critical**: Siempre usa `authenticateUser` antes de `requireRoles` o acceder a `c.get('user')`.

### AuthContext Type
```typescript
interface AuthContext {
  userId: number;
  email: string;
  fullName: string | null;
  roleId: number;
  roleName: string;  // 'admin' | 'teacher' | 'director' | 'seller'
  isActive: boolean;
}
```

### Configuración (src/config/constants.ts)
- `PASSWORD_CONFIG`: Parámetros de hashing (PBKDF2, 100k iteraciones)
- `JWT_CONFIG`: Configuración JWT (HS256, 1h expiración)
- `REFRESH_TOKEN_CONFIG`: Refresh tokens (100 días)
- `PASSWORD_RESET_CONFIG`: Tokens de reset (24 horas)
- `OAUTH_CONFIG`: URLs y scopes de Google OAuth 2.0
- `USER_ROLES`: IDs de roles (1=admin, 2=teacher, 3=director, 4=seller)
- `USER_DEFAULTS`: Valores por defecto (role=2, inactive=0)
Access in routes via `const user = c.get('user')` after authenticateUser.

### Custom Route Pattern ([routes/curso.ts](../src/routes/curso.ts), [routes/user.ts](../src/routes/user.ts))
Custom routes **extend** generic REST endpoints with:
- **Auto-filtering**: Teachers see only their courses via `injectUserCursoFilter` middleware
- **Auto-assignment**: Teachers auto-assigned as `docente_id` when creating courses
- **Firebase integration**: `/user/register` creates user records from Firebase UIDs
- **Role-based queries**: `/user/me?firebase_uid=xxx` fetches user profile for frontend

**Pattern**: Use custom routes for complex authorization logic, fall back to `/rest/*` for simple CRUD.

## Common Tasks

### Adding a New Table
1. Create migration in `migrations/{number}_{name}/up.sql`
2. Include foreign key constraints if needed
3. Apply with `wrangler d1 execute tutor-tools --remote --file=migrations/{number}_{name}/up.sql`
4. **No code changes needed** - REST endpoints auto-generate

### Adding Custom Routes
Create new route files in `src/routes/{domain}.ts` when you need:
1. **Role-based data filtering** (teachers see only their data)
2. * archivos en `src/routes/{domain}.ts` cuando necesites:
1. **Filtrado por rol** (teachers solo ven sus datos)
2. **Joins complejos** con lógica de negocio
3. **Autorización compleja** más allá de RBAC simple

Montar rutas en [index.ts](../src/index.ts):
```typescript
import myRoutes from './routes/my-domain';
app.route('/my-domain', myRoutes);
```

### Testing Endpoints
```bash
# Login
curl -X POST https://d1-rest.<YOUR-ID>.workers.dev/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email": "test@example.com", "password": "password123"}'

# Request autenticado
curl https://d1-rest.<YOUR-ID>.workers.dev/curso \
  -H 'Authorization: Bearer {JWT}'

# SQL query directo (público)
curl -X POST https://d1-rest.<YOUR-ID>.workers.dev/query \
  -H 'Content-Type: application/json' \
  -d '{"query": "SELECT * FROM estudiante WHERE curso_id = ?", "params": [1]}'
```
According to [README.md](../README.md), this REST API is **~3x faster** than the official D1 API (1,729 vs 574 bytes/sec) due to direct query execution without the overhead of the official API client.
