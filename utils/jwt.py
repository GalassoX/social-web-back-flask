from jwt import encode, decode

number = 123456

secret = "g4l4$$0p3rr45"


def generate_user_token(id: int):
    return encode({"id": id}, secret, algorithm="HS256")
