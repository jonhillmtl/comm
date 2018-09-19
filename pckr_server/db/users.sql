CREATE TABLE users (
    ip              CHAR(20),
    port            int NOT NULL,
    username        VARCHAR NOT NULL,
    updated_at      TIMESTAMP NOT NULL,
    login_token     VARCHAR NOT NULL
);