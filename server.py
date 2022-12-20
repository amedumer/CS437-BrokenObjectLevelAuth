from sqlite3 import IntegrityError
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from faker import Faker

fake = Faker()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messages.db'
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
db = SQLAlchemy(app)
jwt = JWTManager(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    roles = db.Column(db.String(80), nullable=False)
    messages = db.relationship('Message', backref='author', lazy=True)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


def add_test_data():
    userCount = 5
    for i in range(userCount):
        user = User(username=f'user{i}', password=f'password{i}', roles='user')
        db.session.add(user)

        for _ in range(15):
            message = Message(content=fake.text(max_nb_chars=40), author=user)
            db.session.add(message)
    try:
        db.session.commit()
    except:
        print("DB Already exists")


@app.route('/api/login', methods=['POST'])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username == None or password == None:
        return {"error": "Missing fields in the form"}, 401

    user = User.query.filter_by(username=request.form['username']).first()
    if user and user.password == request.form['password']:
        access_token = create_access_token(identity=user.id)
        return {'access_token': access_token}
    else:
        return 'Invalid username or password', 401


@app.route('/', methods=['GET'])
def homepage():
    return {"message": "Welcome to our CS437 assignent!", "availableRoutes": ["/api/messages/<int:user_id>/<int:message_id>", "/api/login"]}


@app.route('/api/messages/<int:user_id>/<int:message_id>', methods=['GET'])
@jwt_required()
def get_message(user_id, message_id):
    # claims = get_jwt()
    # VULNERABILITY: No check on the user ID, allowing any user to retrieve any message
    message = Message.query.get(message_id)
    if message == None:
        return {"error": "Not Found"}, 404
    if message.user_id != user_id:
        return {"error": "Not Found"}, 404
    return {"message": message.content, "author": user_id, "id": message.id}, 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        add_test_data()
    app.run(debug=True)
