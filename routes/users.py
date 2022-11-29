from flask import Blueprint, request, jsonify
from utils.bcrypt import hash_password, verify_password
from utils.database import get_connection

users = Blueprint('users', __name__)


@users.post('/api/user')
def create_user():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email = data['email']

    conn = get_connection()
    cursor = conn.cursor()
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
        results = cursor.fetchone()
        print(results)

    errors = []
    for result in results:
        if email in result:
            errors.append('Email used')

        if username in result:
            errors.append('User used')

    return jsonify({"errors": errors})


@users.get('/api/login')
def login():
    data = request.get_json()
    user_or_email = data['userOrEmail']
    password = data['password']

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM users WHERE username=%s OR email=%s',
        (user_or_email)
    )
    results = cursor.fetchall()
    if len(results) > 0:
        return jsonify({"error": "User not exists"})


@users.get('/api/user/<username>')
def get_by_username(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    result = cursor.fetchall()

    conn.close()
    print(result)

    return 'Usuario ' + username


@users.get('/api/user/<username>/posts')
def get_user_posts(username):
    return f'Posts: {username}'
