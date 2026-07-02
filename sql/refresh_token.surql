DEFINE TABLE refresh_token SCHEMAFULL;

DEFINE FIELD user ON refresh_token TYPE record<user>;
DEFINE FIELD client ON refresh_token TYPE record<client>;
DEFINE FIELD scopes ON refresh_token TYPE array<string>;
DEFINE FIELD expires_at ON refresh_token TYPE datetime;
DEFINE FIELD created_at ON refresh_token TYPE datetime DEFAULT time::now();
DEFINE FIELD revoked ON refresh_token TYPE bool DEFAULT false;
DEFINE FIELD used ON refresh_token TYPE bool DEFAULT false;

DEFINE INDEX refresh_token_user_idx ON refresh_token FIELDS user;
DEFINE INDEX refresh_token_client_idx ON refresh_token FIELDS client;
DEFINE INDEX refresh_token_expires_at_idx ON refresh_token FIELDS expires_at;
