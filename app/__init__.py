# Import Flask 
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

# Inject Flask magic
app = Flask(__name__)
jwt = JWTManager(app)

# Load configuration
app.config.from_object('app.config.Config')

# Construct the DB Object (SQLAlchemy interface)
db = SQLAlchemy (app)

# Import routing to render the pages
from app.views import *