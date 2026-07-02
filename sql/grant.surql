DEFINE TABLE grant SCHEMAFULL;

DEFINE FIELD user ON grant TYPE record<user>;
DEFINE FIELD client ON grant TYPE record<client>;
DEFINE FIELD scopes ON grant TYPE array<string>;
DEFINE FIELD enabled ON grant TYPE bool DEFAULT true;
DEFINE FIELD created_at ON grant TYPE datetime DEFAULT time::now();
DEFINE FIELD updated_at ON grant TYPE datetime DEFAULT time::now();

DEFINE INDEX grant_user_idx ON grant FIELDS user;
DEFINE INDEX grant_client_idx ON grant FIELDS client;
DEFINE INDEX grant_user_client_unique_idx ON grant FIELDS user, client UNIQUE;
