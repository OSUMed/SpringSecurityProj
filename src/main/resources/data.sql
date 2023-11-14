-- SQL to create and populate the 'authority' table
CREATE TABLE IF NOT EXISTS authority (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL
);

INSERT INTO authority (name) VALUES ('ROLE_USER');
INSERT INTO authority (name) VALUES ('ROLE_ADMIN');
INSERT INTO authority (name) VALUES ('ROLE_BLUE');
INSERT INTO authority (name) VALUES ('ROLE_RED');

-- SQL to create and populate the 'users' table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);

-- SQL to create the 'user_authorities' join table
CREATE TABLE IF NOT EXISTS user_authorities (
    user_id INT NOT NULL,
    authority_id INT NOT NULL,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_authority FOREIGN KEY (authority_id) REFERENCES authority(id)
);

-- Assuming you've encoded the passwords already
INSERT INTO users (username, password) VALUES ('user', '<encoded-password-for-user>');
INSERT INTO users (username, password) VALUES ('admin', '<encoded-password-for-admin>');

-- Linking users with authorities
INSERT INTO user_authorities (user_id, authority_id) SELECT (SELECT id FROM users WHERE username = 'user'), (SELECT id FROM authority WHERE name = 'ROLE_USER');
INSERT INTO user_authorities (user_id, authority_id) SELECT (SELECT id FROM users WHERE username = 'admin'), (SELECT id FROM authority WHERE name = 'ROLE_ADMIN');

-- SQL to create and populate the 'refresh_token' table
CREATE TABLE IF NOT EXISTS refresh_token (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    refresh_token VARCHAR(255) NOT NULL,
    expiration_date TIMESTAMP NOT NULL,
    CONSTRAINT fk_user_refresh FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Insert refresh token entries if required
-- INSERT INTO refresh_token (user_id, refresh_token, expiration_date) VALUES ((SELECT id FROM users WHERE username = 'user'), 'some-refresh-token', '2023-01-01 00:00:00');
