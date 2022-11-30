from bcrypt import hashpw, gensalt, checkpw


def hash_password(password: str):
    return hashpw(str.encode(password, 'utf-8'), gensalt(12))


def verify_password(hash: str, password: str):
    return checkpw(str.encode(password, 'utf-8'), str.encode(hash, 'utf-8'))
