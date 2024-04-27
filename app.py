from flask import Flask, request, jsonify
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt
from models.user import User

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'
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
        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
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
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())

        user = User(username=username, password=hashed_password, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": f"Usuário {username} criado com sucesso"}), 201

    return jsonify({"message": "Dados inválidos"}), 400


@app.route('/user/<int:id_user>', methods=['GET'])
def read_user(id_user):
    user = User.query.get(id_user)
    if user:
        return jsonify({
            "id": user.id,
            "username": user.username,
            "role": user.role
        }), 200

    return jsonify({"message": "Usuário não encontrado"}), 404


@app.route('/user/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)

    if current_user.role == "user" and id_user != current_user.id:
        return jsonify({"message": "Operação não permitida"}), 403

    if user and data.get("password"):
        user.password = data.get('password', user.password)
        db.session.commit()

        return jsonify({"message": f"Usuário {id_user} atualizado com sucesso",
                        "user": {"id": user.id, "username": user.username}}), 202

    return jsonify({"message": "Usuário não encontrado"}), 404


@app.route('/user/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)

    if current_user.role != "admin":
        return jsonify({"message": "Operação não permitida"}), 403

    if id_user == current_user.id:
        return jsonify({"message": "Deleção não permitida"}), 403

    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuário {id_user} removido com sucesso"}), 204

    return jsonify({"message": "Usuário não encontrado"}), 404


if __name__ == '__main__':
    app.run(debug=True, port=3000)
