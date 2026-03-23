const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');
const router = express.Router();

const DEFAULT_TEMPLATES = [
  {
    name: 'Sprint Board',
    description: 'Agile sprint planning with backlog, in progress, review, and done columns',
    columns: JSON.stringify(['Backlog', 'To Do', 'In Progress', 'Review', 'Done']),
    color: '#6366f1',
    icon: 'zap',
    isDefault: true,
  },
  {
    name: 'Project Board',
    description: 'General project management with planning, active, and completed phases',
    columns: JSON.stringify(['Planning', 'To Do', 'In Progress', 'Testing', 'Completed']),
    color: '#10b981',
    icon: 'folder',
    isDefault: true,
  },
  {
    name: 'Personal Tasks',
    description: 'Simple personal task management board',
    columns: JSON.stringify(['To Do', 'In Progress', 'Done']),
    color: '#f59e0b',
    icon: 'user',
    isDefault: true,
  },
  {
    name: 'Bug Tracker',
    description: 'Track and manage bugs from report to resolution',
    columns: JSON.stringify(['Reported', 'Triaged', 'In Progress', 'Fixed', 'Verified']),
    color: '#ef4444',
    icon: 'bug',
    isDefault: true,
  },
];

async function seedDefaultTemplates() {
  try {
    const count = await prisma.boardTemplate.count({ where: { isDefault: true } });
    if (count === 0) {
      await prisma.boardTemplate.createMany({ data: DEFAULT_TEMPLATES });
      console.log('Default board templates seeded');
    }
  } catch (error) {
    console.error('Failed to seed templates:', error.message);
  }
}

router.use(auth);

// GET /api/templates - list templates
router.get('/', async (req, res) => {
  try {
    const templates = await prisma.boardTemplate.findMany({
      orderBy: { createdAt: 'asc' },
    });
    res.json({ templates });
  } catch (error) {
    console.error('List templates error:', error);
    res.status(500).json({ error: 'Failed to list templates' });
  }
});

// POST /api/templates - create template
router.post('/', async (req, res) => {
  try {
    const { name, description, columns, color, icon } = req.body;

    const template = await prisma.boardTemplate.create({
      data: {
        name,
        description: description || null,
        columns: typeof columns === 'string' ? columns : JSON.stringify(columns),
        color: color || '#6366f1',
        icon: icon || 'layout',
      },
    });

    res.status(201).json({ template });
  } catch (error) {
    console.error('Create template error:', error);
    res.status(500).json({ error: 'Failed to create template' });
  }
});

// POST /api/boards/from-template/:templateId - create board from template
router.post('/boards/from-template/:templateId', async (req, res) => {
  try {
    const { templateId } = req.params;
    const { name } = req.body;

    const template = await prisma.boardTemplate.findUnique({ where: { id: templateId } });
    if (!template) return res.status(404).json({ error: 'Template not found' });

    const columnNames = JSON.parse(template.columns);

    const board = await prisma.board.create({
      data: {
        name: name || template.name,
        description: template.description,
        color: template.color,
        template: template.name,
        ownerId: req.user.userId,
        columns: {
          create: columnNames.map((colName, index) => ({
            name: colName,
            position: index,
          })),
        },
      },
      include: { columns: { orderBy: { position: 'asc' } } },
    });

    // Add owner as board member
    await prisma.boardMember.create({
      data: { boardId: board.id, userId: req.user.userId, role: 'owner' },
    });

    res.status(201).json({ board });
  } catch (error) {
    console.error('Create board from template error:', error);
    res.status(500).json({ error: 'Failed to create board from template' });
  }
});

module.exports = router;
module.exports.seedDefaultTemplates = seedDefaultTemplates;
