from flask import Flask,session
from flask_bcrypt import Bcrypt
app = Flask(__name__)
app.secret_key ='stoplookingformykeyorelse'
bcrypt = Bcrypt(app)     # we are creating an object called bcrypt,
