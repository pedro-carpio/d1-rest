# Copilot Instructions: Cuaderno Pedagógico Backend

## Architecture Overview
This is a **Cloudflare Workers** backend using **Hono** framework and **D1 (SQLite)** database. It provides a generic REST API that auto-generates CRUD endpoints for any table in the database, plus raw SQL query execution.

- **Entry**: [src/index.ts](../src/index.ts) - Hono app with CORS, auth middleware, and route definitions
- **REST Logic**: [src/rest.ts](../src/rest.ts) - Generic CRUD handlers (GET/POST/PATCH/DELETE)
- **Database**: Cloudflare D1 (SQLite) bound as `env.DB`
- **Auth**: Cloudflare Secrets Store bound as `env.SECRET` - validates Bearer token on all API routes

## Domain Model (Education Management System)
The database schema tracks a Bolivian education system with:
- **User accounts & roles** (0001): Teachers, administrators with role-based access
- **Courses** (0002): `curso` table - grade levels, shifts (morning/afternoon), linked to teachers
- **Students & guardians** (0003): `estudiante`, `tutor`, `estudiante_tutor` (many-to-many)
- **Attendance & incidents** (0004): Daily tracking of student presence and behavioral notes
- **Observations** (0005): Health observations and general student notes
- **Pedagogical evaluations** (0007): `evaluacion_actividad`, `evaluacion_trimestral` - tracks "ser/saber/hacer" (be/know/do) dimensions across 4 curricular fields (COSMOS Y PENSAMIENTO, COMUNIDAD Y SOCIEDAD, VIDA TIERRA Y TERRITORIO, CIENCIA TECNOLOGIA Y PRODUCCION)

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
```

**Migration structure**: `migrations/{number}_{name}/up.sql` and `down.sql`
- Always use `PRAGMA foreign_keys = ON;` at the top
- Track versions in `schema_migrations` table
- Use `INSERT OR IGNORE INTO schema_migrations (version) VALUES ('xxxx_name');`

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

## Common Tasks

### Adding a New Table
1. Create migration in `migrations/{number}_{name}/up.sql`
2. Include foreign key constraints if needed
3. Apply with `wrangler d1 execute tutor-tools --remote --file=migrations/{number}_{name}/up.sql`
4. **No code changes needed** - REST endpoints auto-generate

### Testing REST Endpoints
Use the `/query` endpoint for complex queries:
```bash
curl -X POST https://d1-rest.<YOUR-ID>.workers.dev/query \
  -H 'Authorization: Bearer <SECRET>' \
  -H 'Content-Type: application/json' \
  -d '{"query": "SELECT * FROM estudiante WHERE curso_id = ?", "params": [1]}'
```

### Performance Notes
According to [README.md](../README.md), this REST API is **~3x faster** than the official D1 API (1,729 vs 574 bytes/sec) due to direct query execution without the overhead of the official API client.
