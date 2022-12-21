from faker import Faker
from app.models.message import Message
from app.models.user import User

fake = Faker()

def add_test_data(db):
    userCount = 5
    for i in range(1, userCount+1):
        user = User(username=f'user{i}', password=f'password{i}', roles='user')
        db.session.add(user)

        for _ in range(15):
            message = Message(content=fake.text(max_nb_chars=40), author=user)
            db.session.add(message)
    try:
        db.session.commit()
    except:
        print("DB Already exists")