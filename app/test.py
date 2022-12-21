import os

basedir = os.path.abspath(os.path.dirname(__file__))
project_dir = os.path.dirname(basedir)

PROJECT_URI = os.path.dirname(basedir)
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(PROJECT_URI, 'db.sqlite3')

print(SQLALCHEMY_DATABASE_URI)