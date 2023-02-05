import os
from flask import Flask, jsonify, request
from flask_cors import CORS 
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy 
from models import db, User
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

BASEDIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASEDIR,"autenticacion.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["ENV"] = "development"
app.config["SECRET_KEY"] = "super_secret_key"
app.config["JWT_SECRET_KEY"] = "super_jwt_key"

db.init_app(app)
CORS(app)
Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


@app.route("/")
def home():
    return "prueba exitosa"

@app.route("/signup", methods=["POST"])
def signup():
    user = User()
    email = request.json.get("email")
    password = request.json.get("password")
    
    found_email = User.query.filter_by(email=email).first()

    if found_email is not None:
        return jsonify({
            "msg": "Ya existe un usuario registrado con este email"
        }), 400

    user.name = request.json.get("name")
    user.email = email
    password_hash = bcrypt.generate_password_hash(password)
    user.password = password_hash
    

    db.session.add(user)
    db.session.commit()

    return jsonify({
        "msg": "usuario registrado correctamente"
        }), 200

@app.route("/login", methods=["POST"])
def login():
    password = request.json.get("password")
    email = request.json.get("email")

    found_user = User.query.filter_by(email=email).first()

    if found_user is None:
        return jsonify ({
            "msg": "contraseña o rut invalido"
        }), 404
    
    if bcrypt.check_password_hash(found_user.password, password):
        access_token = create_access_token(identity=found_user.id)
        return jsonify({
            "access_token": access_token,
            "data": found_user.serialize(),
            "success": True
        }), 200
    
    else:
        return jsonify ({
            "msg": "contraseña o rut invalido"
        })



if __name__ == "__main__":
    app.run(host="localhost", port=33277)