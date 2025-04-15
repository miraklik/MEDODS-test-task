CREATE TABLE users (
    ID BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE, 
    username VARCHAR(255) UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE INDEX users_username_idx ON users (username);

CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    token_hash TEXT NOT NULL,
    access_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens (user_id);
