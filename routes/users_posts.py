from flask import Blueprint, request, jsonify
from utils.database import get_cursor_dict
from utils.jwt import decode_token

users_post = Blueprint('users_posts', __name__)


@users_post.get('/api/user/<username>/posts')
def get_user_posts(username):
    auth = request.headers.get('Authorization')
    if auth == None:
        return jsonify({'error': 'Unauthorized'}), 400

    (conn, cur) = get_cursor_dict()

    cur.execute(
        'SELECT * FROM users WHERE username=%s',
        (username, )
    )
    result = cur.fetchone()
    if result == None:
        cur.close()
        conn.close()
        return jsonify({'error': 'User not exists'}), 400

    user_id = result['id']
    cur.execute(
        'SELECT * FROM posts WHERE created_by=%s',
        (user_id, )
    )
    result = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify(result), 200


@users_post.post('/api/user/<username>/posts')
def create_user_post(username):
    auth = request.headers.get('Authorization')
    if auth == None:
        return jsonify({'error': 'Unauthorized'}), 400

    user_id = decode_token(auth)['id']

    data = request.get_json()
    print(data)
    message: str = None
    answer: str = None
    quote: str = None

    if data:
        if 'message' in data:
            message = data['message']
        if 'answer' in data:
            answer = data['answer']
        if 'quote' in data:
            quote = data['quote']

    if message == None or len(message) < 5:
        return jsonify({'error': 'Message to short (< 5 chars)'}), 200

    (conn, cur) = get_cursor_dict()

    cur.execute(
        'INSERT INTO posts (message, created_by, answer, quote) VALUES (%s, %s, %s, %s) RETURNING *',
        (message, user_id, answer or 0, quote or 0)
    )
    conn.commit()
    result = cur.fetchone()
    print(result)

    return jsonify(result), 201
