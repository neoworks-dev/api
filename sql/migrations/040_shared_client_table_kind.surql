-- Allow the "shared" client_table kind: org-wide, publicly readable, author-tracked
-- tables (no per-user subject_user_id scoping). Powers the OpenSchema public
-- registry + discussions. See dataplane shared-kind support.
DEFINE FIELD OVERWRITE kind ON client_table TYPE string
    ASSERT $value IN ["data", "relation", "helper", "shared"] READONLY;
