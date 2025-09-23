## Account

### Add indexes

```sql
-- Tags containment (tags @> ARRAY['foo'])
CREATE INDEX IF NOT EXISTS account_tags_gin ON account USING GIN (tags);

CREATE INDEX IF NOT EXISTS account_meta_gin ON account USING GIN (meta jsonb_path_ops);
```

## Namespace

### Add foreign key constraints

```sql
-- Link audit fields to account once a "system" account exists
ALTER TABLE namespace
  ADD CONSTRAINT namespace_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES account(id)
    ON UPDATE CASCADE
    ON DELETE RESTRICT;

ALTER TABLE namespace
  ADD CONSTRAINT namespace_updated_by_fkey
    FOREIGN KEY (updated_by) REFERENCES account(id)
    ON UPDATE CASCADE
    ON DELETE SET NULL;

```
