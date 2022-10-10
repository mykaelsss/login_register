
from flask_app.config.mysqlconnection import connectToMySQL
import re



from flask import flash
from flask_app import bcrypt
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
password_pattern = re.compile(r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$")
class User:
    db = "login_register_db"
    def __init__(self,data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']



    @classmethod
    def register_user(cls,data):
        query = "INSERT INTO users(first_name, last_name, email, password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s);"
        data = {
            **data,
            "password":  bcrypt.generate_password_hash(data['password']).decode('utf-8')
        }
        return connectToMySQL(cls.db).query_db(query,data)

    @classmethod
    def get_by_email(cls, data):
        query = "SELECT * FROM users WHERE email = %(email)s; "
        results =connectToMySQL(cls.db).query_db(query,data)
        if results:
            return cls(results[0])

    @classmethod
    def get_by_id(cls, data):
        query = "SELECT * FROM users WHERE id = %(id)s; "
        results =connectToMySQL(cls.db).query_db(query,data)
        if results:
            return cls(results[0])

    @staticmethod
    def is_valid(user):
        is_valid = True
        if len(user['first_name']) < 2:
            flash("First name must be at least two characters long.", 'register')
            is_valid = False
        if len(user['last_name']) < 2:
            flash("Last name must be at least two characters long.", 'register')
            is_valid = False
        if not EMAIL_REGEX.match(user['email']):
            flash("Invalid Email!", 'register')
            is_valid = False
        if User.get_by_email(user):
            flash("Email already in use.", 'register')
            is_valid = False
        if not password_pattern.match(user['password']):
            flash("Password must be at least 8 characters long, contain at least one uppercase letter, one number and special character.", 'register')
            is_valid = False
        if user['password'] != user['confirm_password']:
            flash("Password and confirm password must match.", 'register')
            is_valid = False
        return is_valid

    @staticmethod
    def validate_login(data):
        user = User.get_by_email(data)
        print(user)
        if not user:
            flash("Invalid Login", 'login')
            return False
        if not bcrypt.check_password_hash(user.password, data['password']):
            flash("Invalid Login", 'login')
            return False
        return True
