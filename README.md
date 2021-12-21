# JWT Authentication

A lightweight [JWT](https://jwt.io/) access/refresh authtentication server implementation in Python using [quart](<https://pgjones.gitlab.io/quart/>). This project is inspired by [Fullstack Authentication](<https://github.com/flolu/auth>).

## SQLite Best Practice and Dependencies

This implementation follows [SQL Style Guide](https://www.sqlstyle.guide/) and requires sqlite3 >= 3.35.0. Check version

```bash
python -c "import sqlite3; print(sqlite3.sqlite_version)"
```

Find the latest version [here](<https://www.sqlite.org/download.html>).

## Generating Secrets

One may follow the best practices from the Python [secrets](<https://docs.python.org/3/library/secrets.html>) standard library to generate secure random keys.

```python
python -c "import secrets; print(secrets.token_urlsafe(16))"
```

## Getting Started

Tested with OS Manjaro Linux and Python 3.9.9.

Setting up the environment and install dependencies

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Setting up the environment variables (when build, change the secret keys)

```bash
make build-env
```

Initialize the database

```bash
quart db-init
```

Start the development server with `quart run`. The development server runs on http://localhost:5000. It also uses [quart-schema](<https://pgjones.gitlab.io/quart-schema/>) that provides an auto-generated API documentation http://localhost:5000/docs.

## Extending Database Roles

The implementation provides two default roles, `admin` and `editor` with the default set to `editor`. The default is set by the `DEFAULT_ROLE_ID` parameter.

One can easily extend the roles in the `schema.sql` file, e.g. extended by the role `owner`

```sql
INSERT INTO roles (id, role) VALUES
(1, 'admin'),
(2, 'editor'),
(3, 'owner');
```

Once edited reinitialize the database (all data will be lost).

## Example Usage

Uncomment the example usage section and reload the app. Create a user named `editor` with password `editor123`

```bash
curl -X 'POST' \
  'http://localhost:5000/auth/register' \
  -H 'accept: */*' \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "editor",
  "password": "editor123"
}'
```

Expected output

```bash
{
  "message": "User editor has been registered.",
  "success": true
}
```

Login the user and retreive the `accessToken` and `refreshToken`

```bash
curl -X 'POST' \
  'http://localhost:5000/auth/login' \
  -H 'accept: */*' \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "editor",
  "password": "editor123"
}'
```

Expected output
```bash
{
  "success": true,
  "user": {
    "accessToken": "<accessToken>",
    "id": 1,
    "name": "editor",
    "refreshToken": "<refreshToken>",
    "role": 2
  }
}
```

Request the resource with e.g. (substitute the accessToken)

```bash
curl -X GET \
  'http://localhost:5000/posts' \
  -H 'Accept: */*' \
  -H 'Content-Type: application/json' \
  -H 'authorization: Bearer <accessToken>'
```

Expected output

```bash
{
  "data": [
    {
      "id": 2,
      "text": "Post Editor",
      "username": "editor"
    }
  ],
  "success": true
}
```

Logout the user with (substitute the accessToken and refreshToken)

```bash
curl -X DELETE \
  'http://localhost:5000/auth/logout' \
  -H 'Accept: */*' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <accessToken>' \
  -d '{
    "token": "<refreshToken>"
  }'
```

Expected output

```bash
{
  "message": "You are logged out.", 
  "success": true
}
```

## Resources

[Using JWT for user authentication in Flask](<https://www.geeksforgeeks.org/using-jwt-for-user-authentication-in-flask/>)  
[Token-Based Authentication With Flask](<https://realpython.com/token-based-authentication-with-flask/#refactoring>)

## Todo

- [ ] Option PostgreSQL database
- [ ] Login with GitHub
- [ ] Frontend
- [ ] Production setup
- [ ] Admin-Panel
- [ ] Unit testing
- [ ] Dockerize
