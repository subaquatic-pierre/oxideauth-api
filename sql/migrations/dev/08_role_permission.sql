-- migrations/08_role_permission.sql
CREATE TABLE IF NOT EXISTS
  role_permission (
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    CONSTRAINT rp_role_fk FOREIGN KEY (role_id) REFERENCES role (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT rp_permission_fk FOREIGN KEY (permission_id) REFERENCES permission (id) ON UPDATE CASCADE ON DELETE RESTRICT
  );

CREATE INDEX IF NOT EXISTS rp_role_idx ON role_permission (role_id);

CREATE INDEX IF NOT EXISTS rp_permission_idx ON role_permission (permission_id);

-- (Optional later) add a trigger to ensure role.namespace_id = permission.namespace_id.