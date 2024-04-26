from flask import Flask, request, jsonify
from database import db
from loginmanager import login_manager
from models.user import User

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db.init_app(app=app)
login_manager.init_app(app=app)

# view login


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username and password:
        # Login
        return jsonify({"message": "Login com sucesso"}), 200
    else:
        return jsonify({"message": "Credenciais inválidas"}), 400


@app.route('/hello-world', methods=['GET'])
def hello_world():
    return 'Hello, World!'


if __name__ == '__main__':
    app.run(debug=True)
