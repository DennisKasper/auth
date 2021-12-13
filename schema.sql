DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS user_role;
DROP TABLE IF EXISTS tokens;

CREATE TABLE users (
  id INTEGER NOT NULL PRIMARY KEY,
  name TEXT NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE roles (
  id INTEGER NOT NULL PRIMARY KEY,
  role TEXT NOT NULL
);

CREATE TABLE user_role (
  user_id INTEGER NOT NULL,
  role_id INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE tokens (
  id INTEGER NOT NULL PRIMARY KEY,
  token TEXT NOT NULL
);

INSERT INTO roles (id, role) VALUES
(1, 'admin'),
(2, 'editor');