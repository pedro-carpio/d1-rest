import { Hono } from 'hono';
import type { Env } from '../index';
import { 
    authenticateUser, 
    requireRoles, 
    verifyCursoOwnership,
    injectUserCursoFilter 
} from '../middleware/auth';

const cursoRoutes = new Hono<{ Bindings: Env }>();

/**
 * GET /curso
 * Lista cursos según el rol del usuario:
 * - Admin: ve todos los cursos
 * - Teacher: solo ve sus cursos (donde es docente)
 */
cursoRoutes.get('/', authenticateUser, injectUserCursoFilter, async (c) => {
    try {
        const filter = c.get('cursoFilter');
        const user = c.get('user');

        const query = `
            SELECT c.*, u.full_name as docente_nombre
            FROM curso c
            JOIN user_account u ON c.docente_id = u.id
            ${filter.where}
            ORDER BY c.gestion DESC, c.nivel, c.seccion
        `;

        const cursos = await c.env.DB.prepare(query)
            .bind(...filter.params)
            .all();

        return c.json({
            cursos: cursos.results,
            total: cursos.results.length,
            user_role: user.roleName
        });

    } catch (error: any) {
        console.error('Error en GET /curso:', error);
        return c.json({ 
            error: 'Error al obtener cursos',
            details: error.message 
        }, 500);
    }
});

/**
 * POST /curso
 * Crea un nuevo curso
 * - Solo admin y teacher pueden crear cursos
 * - Teachers se auto-asignan como docente
 */
cursoRoutes.post('/', authenticateUser, requireRoles(['admin', 'teacher']), async (c) => {
    try {
        const body = await c.req.json();
        const user = c.get('user');

        // Teachers se auto-asignan, admins pueden asignar a cualquiera
        const docente_id = user.roleName === 'admin' && body.docente_id 
            ? body.docente_id 
            : user.userId;

        const { unidad_educativa, distrito_educativo, director, nivel, seccion, gestion, turno_manana, turno_tarde } = body;

        // Validaciones básicas
        if (!unidad_educativa || !distrito_educativo || !director || !nivel || !seccion || !gestion) {
            return c.json({ 
                error: 'Campos requeridos: unidad_educativa, distrito_educativo, director, nivel, seccion, gestion' 
            }, 400);
        }

        const result = await c.env.DB.prepare(
            `INSERT INTO curso (unidad_educativa, distrito_educativo, director, nivel, seccion, gestion, turno_manana, turno_tarde, docente_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
            unidad_educativa,
            distrito_educativo,
            director,
            nivel,
            seccion,
            gestion,
            turno_manana || 0,
            turno_tarde || 0,
            docente_id
        )
        .run();

        const newCurso = await c.env.DB.prepare(
            'SELECT * FROM curso WHERE id = ?'
        ).bind(result.meta.last_row_id).first();

        return c.json({
            message: 'Curso creado exitosamente',
            curso: newCurso
        }, 201);

    } catch (error: any) {
        console.error('Error en POST /curso:', error);
        return c.json({ 
            error: 'Error al crear curso',
            details: error.message 
        }, 500);
    }
});

/**
 * PATCH /curso/:id
 * Actualiza un curso existente
 * - Admin: puede editar cualquier curso
 * - Teacher: solo puede editar sus propios cursos
 */
cursoRoutes.patch('/:id', authenticateUser, verifyCursoOwnership, async (c) => {
    try {
        const cursoId = c.req.param('id');
        const body = await c.req.json();
        const user = c.get('user');

        // Construir query de actualización dinámicamente
        const allowedFields = ['unidad_educativa', 'distrito_educativo', 'director', 'nivel', 'seccion', 'gestion', 'turno_manana', 'turno_tarde'];
        const updates: string[] = [];
        const params: any[] = [];

        for (const field of allowedFields) {
            if (body[field] !== undefined) {
                updates.push(`${field} = ?`);
                params.push(body[field]);
            }
        }

        // Admin puede cambiar el docente_id
        if (user.roleName === 'admin' && body.docente_id !== undefined) {
            updates.push('docente_id = ?');
            params.push(body.docente_id);
        }

        if (updates.length === 0) {
            return c.json({ error: 'No hay campos para actualizar' }, 400);
        }

        updates.push('updated_at = CURRENT_TIMESTAMP');
        params.push(cursoId);

        await c.env.DB.prepare(
            `UPDATE curso SET ${updates.join(', ')} WHERE id = ?`
        ).bind(...params).run();

        const updatedCurso = await c.env.DB.prepare(
            'SELECT * FROM curso WHERE id = ?'
        ).bind(cursoId).first();

        return c.json({
            message: 'Curso actualizado exitosamente',
            curso: updatedCurso
        });

    } catch (error: any) {
        console.error('Error en PATCH /curso/:id:', error);
        return c.json({ 
            error: 'Error al actualizar curso',
            details: error.message 
        }, 500);
    }
});

/**
 * DELETE /curso/:id
 * Elimina un curso
 * - Solo admin puede eliminar cursos
 */
cursoRoutes.delete('/:id', authenticateUser, requireRoles(['admin']), async (c) => {
    try {
        const cursoId = c.req.param('id');

        // Verificar que no haya estudiantes en el curso
        const estudiantes = await c.env.DB.prepare(
            'SELECT COUNT(*) as count FROM estudiante WHERE curso_id = ?'
        ).bind(cursoId).first();

        if (estudiantes && (estudiantes.count as number) > 0) {
            return c.json({ 
                error: 'No se puede eliminar el curso porque tiene estudiantes asignados',
                estudiantes_count: estudiantes.count
            }, 400);
        }

        await c.env.DB.prepare(
            'DELETE FROM curso WHERE id = ?'
        ).bind(cursoId).run();

        return c.json({
            message: 'Curso eliminado exitosamente'
        });

    } catch (error: any) {
        console.error('Error en DELETE /curso/:id:', error);
        return c.json({ 
            error: 'Error al eliminar curso',
            details: error.message 
        }, 500);
    }
});

export default cursoRoutes;
