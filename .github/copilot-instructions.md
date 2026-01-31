# Copilot Instructions: Cuaderno Pedagógico Backend

## Architecture Overview
This is a **Cloudflare Workers** backend using **Hono** framework and **D1 (SQLite)** database. It provides a generic REST API that auto-generates CRUD endpoints for any table in the database, plus raw SQL query execution.

- **Entry**: [src/index.ts](../src/index.ts) - Hono app with CORS, auth middleware, and route definitions
- **REST Logic**: [src/rest.ts](../src/rest.ts) - Generic CRUD handlers (GET/POST/PATCH/DELETE)
- **Database**: Cloudflare D1 (SQLite) bound as `env.DB`
- **Auth**: Cloudflare Secrets Store bound as `env.SECRET` - validates Bearer token on all API routes

## Domain Model (Education Management System)

The database schema tracks a Bolivian education system with:
- **User accounts & roles** (0001): `user_account`, `role` - Teachers, administrators with role-based access
- **Courses** (0002): `curso` table - grade levels, shifts (morning/afternoon), linked to teachers via `docente_id`
- **Students & guardians** (0003): `estudiante`, `tutor`, `estudiante_tutor` (many-to-many)
- **Attendance & incidents** (0004): Daily tracking of student presence and behavioral notes
- **Observations** (0005): Health observations and general student notes
- **Pedagogical evaluations** (0007): `evaluacion_actividad`, `evaluacion_trimestral` - tracks "ser/saber/hacer" (be/know/do) dimensions across 4 curricular fields
- **PDC Planning** (0007): `pdc`, `pdc_fase`, `pdc_fase_perfil` - Curricular development planning with phases and student profiles

**Key domain concepts**:
- **Trimestral system**: School year divided into 3 trimesters
- **Dual shifts**: `turno_manana` (morning), `turno_tarde` (afternoon)
- **Curricular fields**: COSMOS Y PENSAMIENTO, COMUNIDAD Y SOCIEDAD, VIDA TIERRA Y TERRITORIO, CIENCIA TECNOLOGIA Y PRODUCCION

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
2. Compare against `env.SECRET.get()` (Secrets Store binding)
3. Return 401 if missing or mismatched

Apply `authMiddleware` to all protected routes.

### TypeScript Types
- Use `Env` interface for Cloudflare bindings: `DB: D1Database`, `SECRET: SecretsStoreSecret`
- Hono context typed as `Context<{ Bindings: Env }>`
- Access bindings via `c.env.DB` or `env.DB` depending on context

## Configuration

### Wrangler Setup ([wrangler.jsonc](../wrangler.jsonc))
```jsonc
{
  "d1_databases": [{
    "binding": "DB",              // Access as env.DB
    "database_name": "tutor-tools",
    "database_id": "ea265f2a-..." // Project-specific
  }],
  "secrets_store_secrets": [{
    "binding": "SECRET",          // Access as env.SECRET
    "store_id": "8c96922b...",
    "secret_name": "my-awesome-tutor"
  }]
}
```

## Authentication & Authorization

### Middleware Stack Pattern
All custom routes use a **three-layer auth system** ([middleware/auth.ts](../src/middleware/auth.ts)):

1. **authenticateUser**: Validates Firebase UID from `Authorization` header, loads user data into context
2. **requireRoles(['admin', 'teacher'])**: RBAC check - filters by role name
3. **verifyCursoOwnership**: Domain-specific authorization (teachers can only edit their own courses)

**Critical**: Always use `authenticateUser` before `requireRoles` or accessing `c.get('user')`.

### Auth Context Type
```typescript
interface AuthContext {
  userId: number;
  firebaseUid: string;
  email: string | null;
  fullName: string | null;
  roleId: number;
  roleName: string;  // 'admin' | 'teacher' | 'director' | 'seller'
  isActive: boolean;
}
```
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
2. **Multi-table joins** with business logic
3. **Firebase UID validation** (e.g., user registration)
4. **Complex authorization** beyond simple RBAC

Mount routes in [index.ts](../src/index.ts):
```typescript
import myRoutes from './routes/my-domain';
app.route('/my-domain', myRoutes);
```

### Testing REST Endpoints
Use the `/query` endpoint for complex queries:
```bash
curl -X POST https://d1-rest.<YOUR-ID>.workers.dev/query \
  -H 'Authorization: Bearer <SECRET>' \
  -H 'Content-Type: application/json' \
  -d '{"query": "SELECT * FROM estudiante WHERE curso_id = ?", "params": [1]}'
```

### Testing with Firebase Auth
Frontend sends Firebase UID as bearer token:
```bash
curl -H 'Authorization: Bearer {firebase_uid}' \
  https://d1-rest.<YOUR-ID>.workers.dev/curso
```
Backend validates against `user_account.firebase_uid` column.

### Performance Notes
According to [README.md](../README.md), this REST API is **~3x faster** than the official D1 API (1,729 vs 574 bytes/sec) due to direct query execution without the overhead of the official API client.
