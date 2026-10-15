CREATE TYPE user_status AS ENUM ('active', 'pending', 'suspended', 'deleted');

CREATE TABLE users (
                       id            UUID PRIMARY KEY,
                       email         VARCHAR(255) NOT NULL UNIQUE,

                       name          VARCHAR(255) NOT NULL,
                       password_hash VARCHAR(255) NOT NULL,
                       status        user_status NOT NULL DEFAULT 'pending',

                       created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                       updated_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE PROCEDURE update_updated_at_column();

