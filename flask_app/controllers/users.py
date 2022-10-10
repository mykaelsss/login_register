from crypt import methods
from flask_app import app
from flask import render_template,redirect,request,session
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)     # we are creating an object called bcrypt,
# which is made by invoking the function Bcrypt with our app as an argument



@app.route('/')
def register_login():
    return render_template("register_login.html")

@app.route('/register/user', methods=['POST'])
def register_user():

    if not User.is_valid(request.form):
        return redirect('/')
    session['user_id'] = User.register_user(request.form)
    return redirect("/dashboard")

@app.route('/dashboard')
def dashboard():
    if "user_id" not in session:
        return redirect('/')

    data ={
        "id": session['user_id']
    }

    return render_template("dashboard.html", logged_user = User.get_by_id(data))


@app.route('/login/user', methods=['POST'])
def login():
    if not User.validate_login(request.form):
        return redirect('/')
    user = User.get_by_email(request.form)
    session['user_id'] = user.id
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
