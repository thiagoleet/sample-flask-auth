from flask import Flask, request, jsonify
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from models.user import User

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
login_manager = LoginManager()

db.init_app(app=app)
login_manager.init_app(app=app)

# view login
login_manager.login_view = 'login'


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username and password:
        # Login
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            return jsonify({"message": "Login com sucesso"}), 200

        return jsonify({"message": "Credenciais inválidas"}), 401


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout com sucesso"}), 200


@app.route('/user', methods=['POST'])
def create_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username and password:
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": f"Usuário {username} criado com sucesso"}), 201

    return jsonify({"message": "Dados inválidos"}), 400


@app.route('/user/<int:id_user>', methods=['GET'])
def read_user(id_user):
    user = User.query.get(id_user)
    if user:
        return jsonify({"id": user.id, "username": user.username}), 200

    return jsonify({"message": "Usuário não encontrado"}), 404


@app.route('/hello-world', methods=['GET'])
def hello_world():
    return 'Hello, World!'


if __name__ == '__main__':
    app.run(debug=True, port=3000)
