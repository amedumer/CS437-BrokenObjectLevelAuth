# Flask modules
from flask_jwt_extended import jwt_required

# App modules
from app import app
from app.models.message import Message

@app.route('/api/messages/<user_id>/<message_id>', methods=['GET'])
@jwt_required()
def get_message(user_id, message_id):
    # claims = get_jwt()
    # VULNERABILITY: No check on the user ID, allowing any user to retrieve any message
    message = Message.query.filter_by(id=message_id).first()
    if message == None:
        return {"error": "Not Found"}, 404
    if message.user_id != user_id:
        return {"error": "Not Found"}, 404
    return {"message": message.content, "author": user_id, "id": message.id}, 200