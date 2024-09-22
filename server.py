from flask import Flask, request, jsonify, redirect, send_file, make_response
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import random

app = Flask(__name__)
CORS(app)

# Configure Flask app
app.config['MONGO_URI'] = "mongodb+srv://amar:amarnath123@cluster0.nely4hw.mongodb.net/?retryWrites=true&w=majority"
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'bodduamarnath2023@gmail.com'
app.config['MAIL_PASSWORD'] = 'zkolppmibcfnuzbs'

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
mail = Mail(app)


class UserModel():
    @staticmethod
    def save_user(name, phno, email, date, address, password, waterid, form):
        mongo.db.users.insert({
            'name': name,
            'phno': phno,
            'email': email,
            'date': date,
            'address': address,
            'password': password,
            'waterid': waterid,
            'form': form
        })

    @staticmethod
    def find_user(email, password):
        return mongo.db.users.find_one({'email': email, 'password': password})


class GovModel():
    @staticmethod
    def find_gov(email):
        return mongo.db.govusers.find_one({'email': email, 'password': password})


class MailModel():
    @staticmethod
    def save_email(email):
        mongo.db.subscribers.insert({'email': email})

    @staticmethod
    def find_email(email):
        return mongo.db.subscribers.find_one({'email': email})


class OTPModel():
    @staticmethod
    def save_otp(email, otp, expiry):
        mongo.db.otp.insert({
            'email': email,
            'otp': otp,
            'expiry': expiry
        })

    @staticmethod
    def find_otp(email, otp):
        return mongo.db.otp.find_one({'email': email, 'otp': otp})



@app.route('/')
def index():
    user_email = request.cookies.get('userEmail')
    if user_email:
        return send_file('html/dashboard.html')
    else:
        return send_file('html/index1.html')


@app.route('/govlogin/<email>/<password>', methods=['GET'])
def gov_login(email, password):
    try:
        user = GovModel.objects.get(email=email)

        if user:
            if user.password == password:
                return jsonify(success=True, message='Login successful'), 200
            else:
                return jsonify(success=False, message='Incorrect password'), 400
        else:
            return jsonify(success=False, message='User does not exist'), 400

    except Exception as e:
        print('Error querying the database:', str(e))
        return jsonify(success=False, message='Internal server error'), 500


@app.route('/otp/<email>', methods=['GET'])
def generate_otp(email):
    generated_otp = random.randint(1000, 9999)
    otp_expiry = datetime.now() + timedelta(minutes=5)

    try:
        if UserModel.objects(email=email).first():
            return jsonify(success=False, message='User already exists'), 400

        new_otp = OTPModel(email=email, otp=generated_otp, expiry=otp_expiry)
        new_otp.save()

        mail_body = f'The OTP for password request is: {generated_otp}'
        send_email(email, 'OTP for Verification', mail_body)

        return jsonify(success=True), 200

    except Exception as e:
        print('Error saving OTP:', str(e))
        return jsonify(success=False, message='Failed to generate OTP.'), 500


@app.route('/validate/<email>/<password>/<otp>', methods=['GET'])
def validate_user(email, password, otp):
    try:
        existing_otp = OTPModel.objects.get(email=email, otp=otp)

        if not existing_otp or existing_otp.expiry < datetime.now():
            return jsonify(success=False, message='Invalid OTP or OTP expired'), 400

        new_user = UserModel(name='', phno=None, email=email, date=str(datetime.now()),
                             address='', password=password, waterid=0, form=0)
        new_user.save()

        response = make_response(jsonify(success=True, message='User registered successfully'), 200)
        response.set_cookie('userEmail', email, httponly=True)
        return response

    except Exception as e:
        print('Error validating OTP:', str(e))
        return jsonify(success=False, message='Failed to validate OTP.'), 500


@app.route('/dashboard')
def dashboard():
    user_email = request.cookies.get('userEmail')
    if user_email:
        return send_file('html/dashboard.html')
    else:
        return redirect('/')


@app.route('/dashboard/<email>', methods=['GET'])
def check_form_completion(email):
    form = 1
    try:
        exist = UserModel.objects.get(email=email, form=form)
        if exist:
            return redirect('/dashboard')
        else:
            return send_file('html/form.html')
    except Exception as e:
        print('Error querying the database:', str(e))
        return jsonify(success=False, message='Internal server error'), 500


@app.route('/govdashboard')
def gov_dashboard():
    return send_file('html/govdashboard.html')


@app.route('/logout')
def logout():
    response = make_response(redirect('/'))
    response.delete_cookie('userEmail')
    return response


@app.route('/gov')
def gov_login_page():
    return send_file('html/logingov.html')


@app.route('/login/<email>/<password>', methods=['GET'])
def login(email, password):
    try:
        user = UserModel.objects.get(email=email, password=password)

        if not user:
            existing_user = UserModel.objects(email=email).first()
            if existing_user:
                return jsonify(success=False, message='Incorrect password'), 400
            else:
                return jsonify(success=False, message='User does not exist'), 400

        response = make_response(jsonify(success=True, message='Login successful'), 200)
        response.set_cookie('userEmail', email, httponly=True, max_age=3600)
        return response

    except Exception as e:
        print('Error querying the database:', str(e))
        return jsonify(success=False, message='Internal server error'), 500


@app.route('/adddetails/<name>/<id>/<phno>/<address>', methods=['GET'])
def add_user_details(name, id, phno, address):
    try:
        id1 = request.cookies.get('userEmail')
        if not id1:
            return jsonify(success=False, message='Not authenticated'), 401

        user1 = UserModel.objects(email=id1).update(name=name, waterid=id, phno=phno, address=address, form=1)
        if user1:
            return jsonify(success=True, message='Successfully updated'), 200
        else:
            return jsonify(success=False, message='Not updated'), 400

    except Exception as e:
        print('Error updating user details:', str(e))
        return jsonify(success=False, message='Internal server error'), 500


@app.route('/fetch', methods=['GET'])
def fetch_user_details():
    email = request.cookies.get('userEmail')
    if email:
        existing_user = UserModel.objects.get(email=email)
        if existing_user:
            return jsonify(success=True, message=existing_user, email=email), 200
        else:
            return jsonify(success=False, message='Not updated'), 400
    else:
        return redirect('/')


@app.route('/subscribe/<email>', methods=['GET'])
def subscribe(email):
    try:
        x = email
        if MailModel.objects(email=x).first():
            return jsonify(success=False, message='Already subscribed'), 400

        new1 = MailModel(email=x)
        new1.save()

        mail_body = 'Thank you for subscribing'
        send_email(x, 'Mail Confirmation for Updates', mail_body)

        return jsonify(success=True, message='User subscribed successfully'), 200

    except Exception as e:
        print('Error subscribing user:', str(e))
        return jsonify(success=False, message='Internal server error'), 500


if __name__ == '__main__':
    app.run(debug=True)
