import hashlib
import datetime

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prod.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Replace with your secret key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)  # Token expiration time

db = SQLAlchemy(app)
jwt = JWTManager(app)


def generate_password_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


class Countries(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    alpha2 = db.Column(db.Text, nullable=False)
    alpha3 = db.Column(db.Text, nullable=False)
    region = db.Column(db.Text, nullable=False)


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    country_code = db.Column(db.String(2), nullable=False)
    is_public = db.Column(db.Boolean, nullable=False)
    phone = db.Column(db.String(15), nullable=True)
    image = db.Column(db.String(255), nullable=True)

    def __init__(self, login, email, password, country_code, is_public, phone=None, image=None):
        self.login = login
        self.email = email
        self.password = generate_password_hash(password)
        self.country_code = country_code
        self.is_public = is_public
        self.phone = phone
        self.image = image


@app.route('/api/auth/sign-in', methods=['POST'])
def sign_in():
    data = request.json
    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        return jsonify({"reason": "Login and password are required"}), 400

    user = User.query.filter_by(login=login).first()

    if user and user.password == generate_password_hash(password):
        access_token = create_access_token(identity=user.id)
        return jsonify(token=access_token), 200
    else:
        return jsonify({"reason": "Invalid login or password"}), 401


@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.json
    print(data)

    required_fields = ['login', 'email', 'password', 'countryCode', 'isPublic']
    for field in required_fields:
        if field not in data:
            return jsonify({"reason": f"{field} is required"}), 400

    existing_user = User.query.filter(
        (User.login == data['login']) |
        (User.email == data['email']) |
        (User.phone == data.get('phone'))
    ).first()

    if existing_user:
        return jsonify({"reason": "User  with this login, email, or phone already exists"}), 409

    new_user = User(
        login=data['login'],
        email=data['email'],
        password=generate_password_hash(data['password']),
        country_code=data['countryCode'],
        is_public=data['isPublic'],
        phone=data.get('phone'),
        image=data.get('image')
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User  registered successfully"}), 201


@app.route('/api/countries', methods=['GET'])
def get_countries():
    regions = request.args.getlist('region')

    if not regions:
        countries = Countries.query.order_by(Countries.alpha2).all()
    else:
        countries = Countries.query.filter(Countries.region.in_(regions)).order_by(Countries.alpha2).all()

    if not countries:
        return jsonify({"reason": "Invalid region"}), 400

    return jsonify([{
        "name": country.name,
        "alpha2": country.alpha2,
        "alpha3": country.alpha3,
        "region": country.region
    } for country in countries])


@app.route('/api/countries/<alpha2_code>', methods=['GET'])
def get_countries_by_alpha2_code(alpha2_code):
    countries = Countries.query.filter(Countries.alpha2.in_([alpha2_code])).all()

    if not countries:
        return jsonify({"reason": "Invalid region"}), 404

    return jsonify([{
        "name": country.name,
        "alpha2": country.alpha2,
        "alpha3": country.alpha3,
        "region": country.region
    } for country in countries])


@app.route('/api/ping', methods=['GET'])
def send():
    return "ok", 200


if __name__ == "__main__":
    app.run(debug=True)
