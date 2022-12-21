import os

# Grabs the folder where the script runs.
basedir = os.path.abspath(os.path.dirname(__file__))

class Config():
	
    # Set up the App SECRET_KEY
    SECRET_KEY = 'S_U_perS3crEt_KEY#9999'

    # This will create a file in <app> FOLDER
    PROJECT_URI = os.path.dirname(basedir)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(PROJECT_URI, 'db.sqlite3')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'erS3crEt_KEY849'
    