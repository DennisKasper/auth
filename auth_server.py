import asyncio
import datetime
from functools import wraps
import os

from databases import Database
from pydantic.dataclasses import dataclass
from quart import Quart, request, g
from quart_schema import QuartSchema, validate_request, hide_route
import bcrypt
import jwt

from dotenv import load_dotenv
load_dotenv()

DEFAULT_ROLE_ID = 2    # default role
JWT_TOKEN_EXPIRATION = 60   # in minutes

GENSALT = 10

__version__ = '0.1.0'

app = Quart(__name__)
QuartSchema(app)

app.config.update({
    'DATABASE_URL': 'sqlite:///auth.sqlite3',
    'JWT_ACCESS_SECRET_KEY': os.environ.get('JWT_ACCESS_SECRET_KEY'),
    'JWT_REFRESH_SECRET_KEY': os.environ.get('JWT_REFRESH_SECRET_KEY')
})


@dataclass
class User:
    name: str
    password: str

@dataclass
class Token:
    token: str


# jwt verify decorator
def verify_jwt(func: callable) -> callable:
    @wraps(func)
    async def wrapper(*args: any, **kwargs: any):
        try:
            auth_header = request.headers['Authorization']
        except:
            return {'success': False, 'error': 'No Authorization header provided.'}

        try:
            token = auth_header.split(' ')[1]
        except IndexError:
            return {'success': False, 'error': 'Wrong token format. Must be "Bearer token"'}

        try:
            user = jwt.decode(
                token,
                app.config['JWT_ACCESS_SECRET_KEY'],
                algorithms=['HS256']
            )
            g.user = user
        except jwt.ExpiredSignatureError:
            return {'success': False, 'error': 'Signature has expired'}, 403
        except jwt.InvalidSignatureError:
            return {'success': False, 'error': 'Signature verification failed'}, 403
        except jwt.DecodeError:
            return {'success': False, 'error': 'Not enough segments'}, 403

        return await func(*args, **kwargs)
    
    return wrapper


@app.route('/', methods=['GET'])
async def index() -> str:
    count_users = await app.db.fetch_val('SELECT COUNT (*) from users')

    return f'User-Role JWT Athentication Server v{__version__}, {count_users} users registered.'


@app.route('/auth/register', methods=['POST'])
@validate_request(User)
async def register(data: User) -> dict[tuple[str, bool], tuple[str, str]]:
    hashed_pwd = bcrypt.hashpw(data.password.encode('utf-8'), bcrypt.gensalt(GENSALT))

    user_id = await app.db.fetch_val(
        '''INSERT INTO users (name, password)
           VALUES (:name, :password)
        RETURNING id''',
         values={'name': data.name, 'password': hashed_pwd}
    )

    role_id = DEFAULT_ROLE_ID     # default role

    await app.db.execute(
        '''INSERT INTO user_role (user_id, role_id)
           VALUES (:user_id, :role_id)''',
           values={'user_id': user_id, 'role_id': role_id}
    )

    return {
        'success': True,
        'message': f'User {data.name} has been registered.'
    }


@app.route('/auth/login', methods=['POST'])
@validate_request(User)
async def login(data: User):
    user = await app.db.fetch_one(
        '''SELECT id, name, password, role_id AS 'role'
             FROM users
                  INNER JOIN user_role
                  ON users.id = user_role.user_id
            WHERE users.name = (:name)''',
            values={'name': data.name}
    )

    if user is None:
        return {'success': False, 'error': 'User not found.'}, 401

    if not bcrypt.checkpw(data.password.encode('utf-8'), user.password):
        return {'success': False, 'error': 'Invalid password.'}, 403

    # user payload
    user = dict(user)
    user.pop('password')

    access_token, refresh_token = await asyncio.gather(
        generate_access_token(user),
        generate_refresh_token(user)
    )

    await app.db.execute(
        '''INSERT INTO tokens (token)
           VALUES (:token)''',
           values={'token': refresh_token}
    )

    return {
        'success': True,
        'user': {
            'id': user.get('id'),
            'name': user.get('name'),
            'accessToken': access_token,
            'refreshToken': refresh_token,
            'role': user.get('role')
        }
    }


@app.route('/auth/refresh-jwt', methods=['POST'])
@validate_request(Token)
async def refresh_token(data: Token):
    is_stored = await app.db.fetch_val(
        '''SELECT id
             FROM tokens
            WHERE token = :token''',
            values={'token': data.token}
    )

    if is_stored is None:
        return {'success': False, 'error': 'Refresh token is not stored.'}, 403

    try:
        user = jwt.decode(
            data.token,
            app.config['JWT_REFRESH_SECRET_KEY'],
            algorithms='HS256'
        )
    except jwt.exceptions.PyJWTError:
        return {'success': False, 'error': 'PyJWTError'}, 400

    await app.db.execute(
        '''DELETE FROM tokens
            WHERE token =:token''',
            values={'token': data.token}
    )

    access_token, refresh_token = await asyncio.gather(
        generate_access_token(user),
        generate_refresh_token(user)
    )

    await app.db.execute(
        '''INSERT INTO tokens (token)
           VALUES (:token)''',
           values={'token': refresh_token}
    )
    
    return {
        'success': True,
        'accessToken': access_token,
        'refreshToken': refresh_token
    }, 200


@app.route('/auth/logout', methods=['DELETE'])
@verify_jwt
@validate_request(Token)
async def logout(data: Token):
    is_stored = await app.db.fetch_val(
        '''SELECT id
             FROM tokens
            WHERE token = :token''',
            values={'token': data.token}
    )

    if is_stored is None:
        return {'success': False, 'error': 'Refresh token is not stored.'}, 403

    await app.db.execute(
        '''DELETE FROM tokens
            WHERE token = :token''',
            values={'token': data.token}
    )

    return {
        'success': True,
        'message': 'You are logged out.'
    }, 200


@app.before_serving
async def startup() -> None:
    app.db = await _create_db_connection()


@app.after_serving
async def shutdown() -> None:
    await app.db.disconnect()


async def _create_db_connection() -> Database:
    db = Database(app.config['DATABASE_URL'])
    await db.connect()

    return db

async def generate_access_token(payload: dict) -> str:
    new_payload = dict(payload)   # deep copy
    new_payload.update({'iat': datetime.datetime.utcnow()})
    new_payload.update({'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_TOKEN_EXPIRATION)})
    
    return jwt.encode(
        new_payload,
        key=app.config['JWT_ACCESS_SECRET_KEY'],
        algorithm='HS256'
    )

async def generate_refresh_token(payload: dict) -> str:
    new_payload = dict(payload)   # deep copy
    new_payload.update({'iat': datetime.datetime.utcnow()})
    
    return jwt.encode(
        new_payload,
        key=app.config['JWT_REFRESH_SECRET_KEY'],
        algorithm='HS256'
    )


@app.cli.command('db-init')
def db_init() -> None:
    async def _inner() -> None:
        db = await _create_db_connection()
        async with await app.open_resource('schema.sql', 'r') as file_:
            lines = await file_.read()
            for command in lines.split(';'):
                await db.execute(command)

    asyncio.run(_inner())




# # Example usage
# posts = [
#     {
#         'id': 1,
#         'username': 'admin',    # pwd: admin123
#         'text': 'Post Admin'
#     },
#     {
#         'id': 2,
#         'username': 'editor',    # pwd: editor123
#         'text': 'Post Editor'
#     }
# ]

# # Get posts only specific to user
# @app.route('/posts', methods=['GET'])
# @hide_route
# @verify_jwt
# async def get_posts():
#     user = g.pop('user')
#     user_posts = [post for post in posts if post.get('username') == user.get('name')]

#     return {'success': True, 'data': user_posts}

# # Delete post by id only if user is owner or admin
# @app.route('/posts/<int:id>', methods=['DELETE'])
# @hide_route
# @verify_jwt
# async def delelte_post(id: int) -> None:
#     await request.get_data()
#     user = g.pop('user')

#     if user.get('id') == id or user.get('isAdmin'):
#         # delete post in database...
#         return {'success': True, 'message': f'Post {id} has been deleted.'}
#     else:
#         return {'success': False, 'error': f'You are not allowed to delete post {id}'}