from app import app, db
from app.import_fake import add_test_data

with app.app_context():
    db.create_all()
    add_test_data(db)