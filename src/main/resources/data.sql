-- Create the 'authority' table
CREATE TABLE IF NOT EXISTS authority (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL
);

-- Create the 'users' table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);

-- Create the 'user_authorities' table to link users with their authorities
CREATE TABLE IF NOT EXISTS user_authorities (
    user_id INT,
    authority_id INT,
    PRIMARY KEY (user_id, authority_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (authority_id) REFERENCES authority(id)
);

-- Insert authorities
INSERT INTO authority (name) VALUES ('ROLE_USER');
INSERT INTO authority (name) VALUES ('ROLE_ADMIN');
INSERT INTO authority (name) VALUES ('ROLE_BLUE');
INSERT INTO authority (name) VALUES ('ROLE_RED');

-- Insert users with encoded passwords
-- The example password 'password' is used here for demonstration purposes only
-- Use a secure password and encode it using BCryptPasswordEncoder in your actual application
INSERT INTO users (username, password) VALUES ('user', '$2a$10$EJG5zHd9UjQ.mL0H7eJ9QO5GjYzP5U1lLLvWzFpV.yLAhK6z9Q9DO'); -- password is "password" encoded
INSERT INTO users (username, password) VALUES ('admin', '$2a$10$EJG5zHd9UjQ.mL0H7eJ9QO5GjYzP5U1lLLvWzFpV.yLAhK6z9Q9DO'); -- password is "password" encoded
INSERT INTO users (username, password) VALUES ('blue_user', '$2a$10$EJG5zHd9UjQ.mL0H7eJ9QO5GjYzP5U1lLLvWzFpV.yLAhK6z9Q9DO'); -- password is "password" encoded
INSERT INTO users (username, password) VALUES ('red_user', '$2a$10$EJG5zHd9UjQ.mL0H7eJ9QO5GjYzP5U1lLLvWzFpV.yLAhK6z9Q9DO'); -- password is "password" encoded

-- Link users with their authorities
INSERT INTO user_authorities (user_id, authority_id) VALUES ((SELECT id FROM users WHERE username = 'user'), (SELECT id FROM authority WHERE name = 'ROLE_USER'));
INSERT INTO user_authorities (user_id, authority_id) VALUES ((SELECT id FROM users WHERE username = 'admin'), (SELECT id FROM authority WHERE name = 'ROLE_ADMIN'));
INSERT INTO user_authorities (user_id, authority_id) VALUES ((SELECT id FROM users WHERE username = 'blue_user'), (SELECT id FROM authority WHERE name = 'ROLE_BLUE'));
INSERT INTO user_authorities (user_id, authority_id) VALUES ((SELECT id FROM users WHERE username = 'red_user'), (SELECT id FROM authority WHERE name = 'ROLE_RED'));
INSERT INTO user_authorities (user_id, authority_id) VALUES ((SELECT id FROM users WHERE username = 'blue_user'), (SELECT id FROM authority WHERE name = 'ROLE_RED'));
