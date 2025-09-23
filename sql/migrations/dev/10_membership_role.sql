-- migrations/10_membership_role.sql
CREATE TABLE IF NOT EXISTS
  membership_role (
    membership_id UUID NOT NULL,
    role_id UUID NOT NULL,
    PRIMARY KEY (membership_id, role_id),
    CONSTRAINT mr_membership_fk FOREIGN KEY (membership_id) REFERENCES membership (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT mr_role_fk FOREIGN KEY (role_id) REFERENCES role (id) ON UPDATE CASCADE ON DELETE RESTRICT
  );

CREATE INDEX IF NOT EXISTS mr_membership_idx ON membership_role (membership_id);

CREATE INDEX IF NOT EXISTS mr_role_idx ON membership_role (role_id);