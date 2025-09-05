UPDATE account AS t
SET
  name = COALESCE(v.name, t.name),
  acc_type = COALESCE(v.acc_type, t.acc_type),
  provider = COALESCE(v.provider, t.provider),
  provider_id = COALESCE(v.provider_id, t.provider_id),
  description = COALESCE(v.description, t.description),
  image_url = COALESCE(v.image_url, t.image_url),
  verified = COALESCE(v.verified, t.verified),
  enabled = COALESCE(v.enabled, t.enabled),
  namespace_id = COALESCE(v.namespace_id, t.namespace_id),
  project_id = COALESCE(v.project_id, t.project_id),
  meta = COALESCE(v.meta, t.meta),
  updated_by = COALESCE(v.updated_by, t.updated_by),
  updated_at = COALESCE(v.updated_at, t.updated_at)
FROM
  (
    VALUES
      (
        $1,
        $2,
        $3,
        $4,
        NULL,
        $5,
        NULL,
        $6,
        $7,
        NULL,
        NULL,
        $8,
        $9,
        $10
      ),
      (
        $11,
        NULL,
        $12,
        $13,
        NULL,
        $14,
        NULL,
        $15,
        $16,
        NULL,
        NULL,
        $17,
        $18,
        $19
      )
  ) AS v (
    id,
    name,
    acc_type,
    provider,
    provider_id,
    description,
    image_url,
    verified,
    enabled,
    namespace_id,
    project_id,
    meta,
    updated_by,
    updated_at
  )
WHERE
  t.id = v.id
RETURNING
  t.*