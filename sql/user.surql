DEFINE TABLE user SCHEMAFULL;

DEFINE FIELD first_name ON user TYPE string;

DEFINE FIELD last_name ON user TYPE string;

DEFINE FIELD email ON user TYPE string
    ASSERT string::is_email($value);

DEFINE FIELD password_hash ON user TYPE string;

DEFINE FIELD created_at ON user TYPE datetime
    DEFAULT time::now()
    READONLY;

DEFINE INDEX user_email_unique ON user FIELDS email UNIQUE;
