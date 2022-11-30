from flask import Blueprint, request, jsonify
from utils.bcrypt import hash_password, verify_password
from utils.database import get_connection, get_cursor_dict
from utils.jwt import generate_user_token

users = Blueprint('users', __name__)


@users.post('/api/user')
def create_user():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email = data['email']

    (conn, cursor) = get_cursor_dict()
    cursor.execute(
        'SELECT * FROM users WHERE username=%s OR email=%s',
        (username, email)
    )
    results = cursor.fetchall()

    if len(results) == 0:
        hash = hash_password(password).decode()
        cursor.execute(
            'INSERT INTO users (username, email, password) VALUES (%s, %s, %s) RETURNING *',
            (username, email, hash)
        )
        conn.commit()
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        token = generate_user_token(result['id'])
        return jsonify({'token': token, 'message': 'account registered'})

    cursor.close()
    conn.close()

    errors = []
    user_used = True
    email_used = False
    for result in results:
        if user_used and email_used:
            break

        if not user_used and result['username'] == username:
            errors.append('User used')
        if not email_used and result['email'] == email:
            errors.append('Email used')

    return jsonify({'error': errors})


@users.post('/api/login')
def login():
    data = request.get_json()
    user_or_email = data['userOrEmail']
    password = data['password']

    (conn, cursor) = get_cursor_dict()
    cursor.execute(
        'SELECT * FROM users WHERE username=%s OR email=%s',
        (user_or_email, user_or_email)
    )
    result = cursor.fetchone()

    if not result:
        cursor.close()
        conn.close()
        return jsonify({'error': 'User not exists'})

    if not verify_password(result['password'], password):
        cursor.close()
        conn.close()
        return jsonify({'error': 'Incorrect password'})

    cursor.close()
    conn.close()
    token = generate_user_token(result['id'])
    return jsonify({'token': token, 'message': 'account logged'})


@users.get('/api/user/<username>')
def get_by_username(username):
    (conn, cursor) = get_cursor_dict()
    cursor.execute(
        'SELECT * FROM users WHERE username=%s',
        (username, )
    )
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    
    return jsonify({
        'username': result['username'],
        'description': result['description'],
        'likes': result['likes'],
        'create_at': result['create_at']
    })


@users.get('/api/user/<username>/posts')
def get_user_posts(username):
    return f'Posts: {username}'
