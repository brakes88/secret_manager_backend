CREATE TYPE encryption_method AS ENUM ('AES256', 'Chacha20', 'Blowfish', 'DESTripleDES');

CREATE TABLE
    users (
        id UUID NOT NULL PRIMARY KEY DEFAULT (uuidv7 ()),
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        encryption_method encryption_method NULL,
        keys BYTEA NULL,
        api_keys VARCHAR(255) NULL,
        db_connection JSON NULL,
        created_at TIMESTAMP
        WITH
            TIME ZONE DEFAULT NOW (),
            updated_at TIMESTAMP
        WITH
            TIME ZONE DEFAULT NOW ()
    );

CREATE INDEX users_email_idx ON users (email);