from flask import Flask, jsonify
from routes.users import users

app = Flask(__name__)


@app.get('/ping')
def ping():
    return jsonify({'message': 'Pong!'})


app.register_blueprint(users)

if __name__ == '__main__':
    app.run(debug=True, port=4000)
