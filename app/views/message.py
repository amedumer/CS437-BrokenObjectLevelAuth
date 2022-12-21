# Flask modules
from flask_jwt_extended import jwt_required

# Flask module for authorization check
from flask_jwt_extended import get_jwt_identity

# App modules
from app import app
from app.models.message import Message

@app.route('/api/messages/<int:user_id>/<int:message_id>', methods=['GET'])
@jwt_required()
def get_message(user_id, message_id):
    # Check for authorization

    # ======== PROTECTION 1: AUTHORIZATION CHECK ========
    # if get_jwt_identity() != user_id:
    #     return {"error": "Not Authorized."}, 401
    # ======== PROTECTION 1: AUTHORIZATION CHECK ========
    
    message = Message.query.get(message_id)
    if message == None:
        return {"error": "Not Found"}, 404
    if message.user_id != user_id:
        return {"error": "Not Found"}, 404
    return {"message": message.content, "author": user_id, "id": message.id}, 200