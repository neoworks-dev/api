-- ── owner_domain: a domain an owner proves control of (#36) ───────────────────
-- `token` is the value the owner publishes: as a DNS TXT record on the domain
-- itself or as the body of `/.well-known/neoworks-verification.txt`. A domain may
-- be added by several owners but only one of them can hold it verified. A
-- verified domain that fails `failed_checks` re-checks in a row loses its
-- verification.
DEFINE TABLE owner_domain SCHEMAFULL;
DEFINE FIELD owner           ON owner_domain TYPE record<user | organization> READONLY;
DEFINE FIELD domain          ON owner_domain TYPE string READONLY;
DEFINE FIELD method          ON owner_domain TYPE string ASSERT $value IN ['dns', 'wellKnown'];
DEFINE FIELD token           ON owner_domain TYPE string READONLY;
DEFINE FIELD verified        ON owner_domain TYPE bool DEFAULT false;
DEFINE FIELD verified_at     ON owner_domain TYPE option<datetime>;
DEFINE FIELD last_checked_at ON owner_domain TYPE option<datetime>;
DEFINE FIELD failed_checks   ON owner_domain TYPE int DEFAULT 0;
DEFINE FIELD created_at      ON owner_domain TYPE datetime VALUE $before OR time::now() READONLY;

DEFINE INDEX owner_domain_unique ON owner_domain FIELDS owner, domain UNIQUE;
DEFINE INDEX owner_domain_domain ON owner_domain FIELDS domain;
DEFINE INDEX owner_domain_verified ON owner_domain FIELDS verified;
