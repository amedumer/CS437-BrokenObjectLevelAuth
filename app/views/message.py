# Flask modules
from flask_jwt_extended import jwt_required

# App modules
from app import app
from app.models.message import Message

@app.route('/api/messages/<int:user_id>/<int:message_id>', methods=['GET'])
@jwt_required()
def get_message(user_id, message_id):
    message = Message.query.get(message_id)
    if message == None:
        return {"error": "Not Found"}, 404
    if message.user_id != user_id:
        return {"error": "Not Found"}, 404
    return {"message": message.content, "author": user_id, "id": message.id}, 200