from app import app

@app.route('/', methods=['GET'])
def homepage():
    return {"message": "Welcome to our CS437 assignent!", "availableRoutes": ["/api/messages/<int:user_id>/<int:message_id>", "/api/login"]}