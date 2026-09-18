CREATE TABLE IF NOT EXISTS seva (
  id TEXT PRIMARY KEY,

  title TEXT NOT NULL,

  description TEXT NOT NULL DEFAULT '',

  image_url TEXT NOT NULL DEFAULT '',

  icon TEXT NOT NULL DEFAULT '🕉️',

  active INTEGER NOT NULL DEFAULT 1,

  sort_order INTEGER NOT NULL DEFAULT 0,

  created_at TEXT NOT NULL,

  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_seva_active_sort
ON seva(active, sort_order);

CREATE INDEX IF NOT EXISTS idx_seva_created_at
ON seva(created_at);
