# Flask modules
from flask import request
from flask_jwt_extended import create_access_token

# App modules
from app import app
from app.models.user import User

@app.route('/api/login', methods=['POST'])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username == None or password == None:
        return {"error": "Missing fields in the form"}, 401

    user = User.query.filter_by(username=request.form['username']).first()
    if user and user.password == request.form['password']:
        access_token = create_access_token(identity=user.id)
        return {'access_token': access_token, 'id':user.id}
    else:
        return 'Invalid username or password', 401