
# CS437-BrokenObjectLevelAuth
You are asked to create a vulnerable messaging API where private user messages can be seen by all the users. Vulnerability can be triggered by changing the user or resource IDs.

## Group members:
- Yasin Ughur - 28554
- Ahmet Ömer Kayabaşı - 27840
- Dora Akbulut - 26863
  

# Part 1

We undertook Responsibility 1: Broken Object Level Authorization Failure and Protection

  

## Vulnerability

We were asked to implement a vulnerable API that lets authenticated users to retrieve the messages of other users by changing the `id` field of the request.

  

Here is the vulnerable code:

```python
# Flask modules
from flask_jwt_extended import jwt_required
from flask_jwt_extended import get_jwt_identity
# App modules
from app import app
from app.models.message import Message

@app.route('/api/messages/<int:user_id>/<int:message_id>', methods=['GET'])
@jwt_required()
def  get_message(user_id, message_id):
	message = Message.query.get(message_id)
	if message == None:
		return {"error": "Not Found"}, 404
	if message.user_id != user_id:
		return {"error": "Not Found"}, 404
	return {"message": message.content, "author": user_id, "id": message.id}, 200
```

As it can be seen clearly, if a user can guess the `id` of other users and their messages, they can easily access those messages.

  

### Screenshots

Figure 1 and 2 display user1 with `id=1` logging in, receiving the `access_token` and performing a request on their message. Figure 3 displays the vulnerability as user1 accesses a message from the user with `id=2`.

  

*Figure 1: Login as user1.*

<img  width="866"  alt="figure01"  src="https://user-images.githubusercontent.com/60580158/210064256-30d744b0-4245-47fe-9b4c-89b047b5b62f.png">

  
  

*Figure 2: Retrieve user1's own message.*

<img  width="878"  alt="figure02"  src="https://user-images.githubusercontent.com/60580158/210064319-a047be30-a846-4ba2-9d6e-7ca9f4e5957d.png">

  
  

*Figure 3: Retrieve another user's (user2) message.*

<img  width="877"  alt="figure03"  src="https://user-images.githubusercontent.com/60580158/210064333-733163fa-633d-4d12-bb54-047c0581e322.png">

  
  

## Protection 1: Use unpredictable IDs

It's common to use consecutive numbers, 1, 2, 3, etc. This means IDs are very predictable, and an attacker can simply go through numbers in order, trying to find objects. Other predictable patterns also make it easy for an attacker. A good example is formatted date/time strings. These might be used as part of a file name for files uploaded by a user. Files count as objects too, and their file name would be the ID. So if a file named belonging to another user can be guessed and the file accessed, that's another instance of our vulnerability. We can, however, use something more unpredictable for an ID. GUIDs work well.

We are using SQLite as database and sqlachemy for creating database with ORM approach. However, in SQLite there is not functionality for creating UUID. Therefore, we created our own UUID approach in ```helpers/guid.py```. 

```python
from  sqlalchemy.types  import  TypeDecorator, CHAR
from  sqlalchemy.dialects.postgresql  import  UUID
import  uuid

class  GUID(TypeDecorator):
	impl = CHAR
	cache_ok = True
	
	def  load_dialect_impl(self, dialect):
		if  dialect.name == "postgresql":
			return  dialect.type_descriptor(UUID())
		else:
			return  dialect.type_descriptor(CHAR(32))

	def  process_bind_param(self, value, dialect):
		if  value  is  None:
			return  value
		elif  dialect.name == "postgresql":
			return  str(value)
		else:
			if  len(value) != 32:
				return  None
			if  not  isinstance(value, uuid.UUID):
				return  "%.32x" % uuid.UUID(value).int
		else:
			return  "%.32x" % value.int

	def  _uuid_value(self, value):
		if  value  is  None:
			return  value
		else:
			if  not  isinstance(value, uuid.UUID):
				value = uuid.UUID(value)
			return  value

	def  process_result_value(self, value, dialect):
		return  self._uuid_value(value)

	def  sort_key_function(self, value):
		return  self._uuid_value(value)

```
Here we inherited from sqlalchemy TypeDecorator class for creating our own type. TypeDecorator allows the creation of types which add additional functionality to an existing type. 
  

### Screenshots

In User Model *(Figure 4)* and Message Model *(Figure 5)*, we changed data type of ID column from integer to GUID() type. In *Figure 6*, we requested message with id ```3218f27caacd4259a514ae3f69d456ac``` of user with id ```a376cc13-788d-4e3f-8228-044c73d43494```.

*Figure 4: User Model.*
<img  width="878"  alt="figure02"  src="https://user-images.githubusercontent.com/44711227/210065339-da6d8321-98c8-4f79-a896-1fa610ea9326.png">
  
*Figure 5: Message Model.*
<img  width="878"  alt="figure02"  src="https://user-images.githubusercontent.com/44711227/210065513-eaf06d95-4532-4619-a086-7b96754ceeb0.png">  

*Figure 6: Request from Postman.*
<img  width="878"  alt="figure02"  src="https://user-images.githubusercontent.com/44711227/210072562-9adef88c-4651-44d9-a99a-308807a37c1c.png">  
 

## Protection 2: Check Authorization

In order to protect the messages of our users from malicious users, we can check whether the user is authorized to access a message when they send a request.

Here is the code with protection:

```python
# Flask modules
from flask_jwt_extended import jwt_required
from flask_jwt_extended import get_jwt_identity

# App modules
from app import app
from app.models.message import Message
  

@app.route('/api/messages/<int:user_id>/<int:message_id>', methods=['GET'])
@jwt_required()
def  get_message(user_id, message_id):
	# ======== PROTECTION 1: AUTHORIZATION CHECK ========
	# Check for authorization
	if get_jwt_identity() != user_id:
		return {"error": "Not Authorized."}, 401
	# ======== PROTECTION 1: AUTHORIZATION CHECK ========

	message = Message.query.get(message_id)
	if message == None:
		return {"error": "Not Found"}, 404
	if message.user_id != user_id:
		return {"error": "Not Found"}, 404
	return {"message": message.content, "author": user_id, "id": message.id}, 200
```

  

We can see that we check the `id` of the user sending the request, and compare it with the id related to the `access_token` they have provided.

  

### Screenshots

*Figure 7* and  *8* display user1 with `id=1` logging in, receiving the `access_token` and performing a request on their message. *Figure 9* demonstrates the error user1 receives upon attempting to retrieve another users' messages.

  

*Figure 7: user1 logs in.*
<img  width="867"  alt="figure07"  src="https://user-images.githubusercontent.com/60580158/210064357-460073e4-7a2a-4954-8fa2-e639db2c1a22.png">

  
  

*Figure 8: user1 accesses their own message.*
<img  width="874"  alt="figure08"  src="https://user-images.githubusercontent.com/60580158/210064371-5c378ac5-87ff-45d4-a994-2213793d715c.png">

  
  

*Figure 9: user1 cannot access the messages of user2 or user3.*
<img  width="864"  alt="figure09"  src="https://user-images.githubusercontent.com/60580158/210064386-85be4617-dfcf-4d91-aa9a-ef95d481652e.png">

  
  

## Sources

- https://auth0.com/blog/developing-restful-apis-with-python-and-flask/

- https://auth0.com/blog/forbidden-unauthorized-http-status-codes/

[Link to the demonstration video](https://www.google.com)


# Part 2

## 1. Bandit (MacOS)

*Figure 10* shows the output of Bandit after analyzing our code. It has found that our secret key is hard-coded, but we judge that is not in the scope of our project, and it was a decision we made to implement the project faster.

*Figure 10: Output of the Bandit Static Code Analyzer*
<img  width="961"  alt="figure10"  src="https://user-images.githubusercontent.com/60580158/210064403-19763859-0045-4ec6-ba7e-e22441ba5dc8.png">

## 2. PYT (Python Taint)

As it can be seen *Figure 11*, PYT could not find the desired vulnerability.

*Figure 11: Output of the PYT Static Code Analyzer*
<img  width="840"  alt="figure11"  src="https://user-images.githubusercontent.com/60580158/210064413-113b1f64-e133-459c-900c-79aa979cbe36.png">

## 3. Rough-Auditing-Tool-for-Security

As it can be seen *Figure 12*, RATS could not find the desired vulnerability.

*Figure 12: Output of the Rough-Auditing-Tool-for-Security Static Code Analyzer*
<img  width="475"  alt="figure12"  src="https://user-images.githubusercontent.com/60580158/210064420-1050bcea-6583-409b-ad83-e07a57488a7a.png">

  
  

## 4. Prospector (MacOS)

As it can be seen in *Figure 13*, Prospector could not find the desired vulnerability but only some lints.

*Figure 13: Output of the Prospector Static Code Analyzer*
<img  width="1144"  alt="figure13"  src="https://user-images.githubusercontent.com/60580158/210064430-84de07f8-d5ab-4a7f-96ab-b84f0d8ef924.png">

## 5. DLint (MacOS)

The static code analyzer we have found is [Dlint](https://github.com/dlint-py/dlint)
As explained on its GitHub repository,

> "Dlint is a tool for encouraging best coding practices and helping ensure Python code is secure."

As it can be seen in *Figure 14*, Dlint did not find any vulnerabilities in our code. It only found some lint violations.

*Figure 14: Output of the Dlint Static Code Analyzer*
<img  width="998"  alt="figure14"  src="https://user-images.githubusercontent.com/60580158/210064441-453df127-6202-4db5-a4fb-35b4b30ad528.png">

Output of dlint to a file:
```

[1m./app/config.py[m[36m:[m6[36m:[m1[36m:[m [1m[31mE302[m expected 2 blank lines, found 1
[1m./app/config.py[m[36m:[m7[36m:[m1[36m:[m [1m[31mW191[m indentation contains tabs
[1m./app/config.py[m[36m:[m7[36m:[m1[36m:[m [1m[31mW293[m blank line contains whitespace
[1m./app/config.py[m[36m:[m8[36m:[m1[36m:[m [1m[31mE101[m indentation contains mixed spaces and tabs
[1m./app/config.py[m[36m:[m9[36m:[m1[36m:[m [1m[31mE101[m indentation contains mixed spaces and tabs
[1m./app/config.py[m[36m:[m11[36m:[m1[36m:[m [1m[31mE101[m indentation contains mixed spaces and tabs
[1m./app/config.py[m[36m:[m12[36m:[m1[36m:[m [1m[31mE101[m indentation contains mixed spaces and tabs
[1m./app/config.py[m[36m:[m13[36m:[m1[36m:[m [1m[31mE101[m indentation contains mixed spaces and tabs
[1m./app/config.py[m[36m:[m13[36m:[m80[36m:[m [1m[31mE501[m line too long (84 > 79 characters)
[1m./app/config.py[m[36m:[m14[36m:[m1[36m:[m [1m[31mE101[m indentation contains mixed spaces and tabs
[1m./app/config.py[m[36m:[m15[36m:[m1[36m:[m [1m[31mE101[m indentation contains mixed spaces and tabs
[1m./app/config.py[m[36m:[m16[36m:[m1[36m:[m [1m[31mE101[m indentation contains mixed spaces and tabs
[1m./app/config.py[m[36m:[m16[36m:[m1[36m:[m [1m[31mW293[m blank line contains whitespace
[1m./app/config.py[m[36m:[m16[36m:[m5[36m:[m [1m[31mW292[m no newline at end of file
[1m./app/__init__.py[m[36m:[m1[36m:[m15[36m:[m [1m[31mW291[m trailing whitespace
[1m./app/__init__.py[m[36m:[m14[36m:[m16[36m:[m [1m[31mE211[m whitespace before '('
[1m./app/__init__.py[m[36m:[m17[36m:[m1[36m:[m [1m[31mF403[m 'from app.views import *' used; unable to detect undefined names
[1m./app/__init__.py[m[36m:[m17[36m:[m1[36m:[m [1m[31mF401[m 'app.views.*' imported but unused
[1m./app/__init__.py[m[36m:[m17[36m:[m1[36m:[m [1m[31mE402[m module level import not at top of file
[1m./app/__init__.py[m[36m:[m17[36m:[m24[36m:[m [1m[31mW292[m no newline at end of file
[1m./app/test.py[m[36m:[m7[36m:[m80[36m:[m [1m[31mE501[m line too long (80 > 79 characters)
[1m./app/test.py[m[36m:[m9[36m:[m31[36m:[m [1m[31mW292[m no newline at end of file
[1m./app/import_fake.py[m[36m:[m7[36m:[m1[36m:[m [1m[31mE302[m expected 2 blank lines, found 1
[1m./app/import_fake.py[m[36m:[m8[36m:[m6[36m:[m [1m[31mN806[m variable 'userCount' in function should be lowercase
[1m./app/import_fake.py[m[36m:[m18[36m:[m5[36m:[m [1m[31mE722[m do not use bare 'except'
[1m./app/import_fake.py[m[36m:[m19[36m:[m35[36m:[m [1m[31mW292[m no newline at end of file
[1m./app/models/user.py[m[36m:[m9[36m:[m71[36m:[m [1m[31mW292[m no newline at end of file
[1m./app/models/message.py[m[36m:[m7[36m:[m78[36m:[m [1m[31mW292[m no newline at end of file
[1m./app/views/auth.py[m[36m:[m9[36m:[m1[36m:[m [1m[31mE302[m expected 2 blank lines, found 1
[1m./app/views/auth.py[m[36m:[m14[36m:[m17[36m:[m [1m[31mE711[m comparison to None should be 'if cond is None:'
[1m./app/views/auth.py[m[36m:[m14[36m:[m37[36m:[m [1m[31mE711[m comparison to None should be 'if cond is None:'
[1m./app/views/auth.py[m[36m:[m20[36m:[m51[36m:[m [1m[31mE231[m missing whitespace after ':'
[1m./app/views/auth.py[m[36m:[m22[36m:[m51[36m:[m [1m[31mW292[m no newline at end of file
[1m./app/views/home.py[m[36m:[m3[36m:[m1[36m:[m [1m[31mE302[m expected 2 blank lines, found 1
[1m./app/views/home.py[m[36m:[m5[36m:[m80[36m:[m [1m[31mE501[m line too long (140 > 79 characters)
[1m./app/views/home.py[m[36m:[m5[36m:[m141[36m:[m [1m[31mW292[m no newline at end of file
[1m./app/views/__init__.py[m[36m:[m1[36m:[m1[36m:[m [1m[31mF401[m 'app.views.auth' imported but unused
[1m./app/views/__init__.py[m[36m:[m1[36m:[m1[36m:[m [1m[31mF401[m 'app.views.home' imported but unused
[1m./app/views/__init__.py[m[36m:[m1[36m:[m1[36m:[m [1m[31mF401[m 'app.views.message' imported but unused
[1m./app/views/__init__.py[m[36m:[m1[36m:[m42[36m:[m [1m[31mW292[m no newline at end of file
[1m./app/views/message.py[m[36m:[m3[36m:[m1[36m:[m [1m[31mF401[m 'flask_jwt_extended.get_jwt_identity' imported but unused
[1m./app/views/message.py[m[36m:[m9[36m:[m1[36m:[m [1m[31mE302[m expected 2 blank lines, found 1
[1m./app/views/message.py[m[36m:[m18[36m:[m1[36m:[m [1m[31mW293[m blank line contains whitespace
[1m./app/views/message.py[m[36m:[m20[36m:[m16[36m:[m [1m[31mE711[m comparison to None should be 'if cond is None:'
[1m./app/views/message.py[m[36m:[m24[36m:[m80[36m:[m [1m[31mE501[m line too long (81 > 79 characters)
[1m./app/views/message.py[m[36m:[m24[36m:[m82[36m:[m [1m[31mW292[m no newline at end of file
```

*Figure 15* shows how each tool performed against the vulnerability we were responsible with. None of the tools could detect the vulnerability.

*Figure 15: Effectiveness of each tool*
| Tool | Effectiveness |
| -------------------------------- | -------------------------------------------- |
| Bandit | Broken Object Level Authorization not found. |
| PYT (Python Taint) | Broken Object Level Authorization not found. |
| Rough-Auditing-Tool-for-Security | Broken Object Level Authorization not found. |
| Prospector | Broken Object Level Authorization not found. |
| Dlint | Broken Object Level Authorization not found. |

  
  
  

# Responsibilities of the team members in each part


| Name  | Responsibility in Part 1 | Responsibility in Part 2 |
| ------------- | ------------- | ------------- |
| Dora Akbulut  | Implementing the Authorization protection, writing the report.  | Using Bandit, Dlint and Prospector code analyzers, writing the report. |
| Ahmed Ömer Kayabaşı  | Implementing the Flask server with the vulnerable code, writing the report.  | Using PYT and RATS code analyzers, writing the report. |
| Yasin Ughur  | Re-structuring the codebase, implementing the Unpredictable IDs protection, writing the report.  | Writing the report and recording the video |
