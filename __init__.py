from datetime import timedelta, datetime
from tokenize import generate_tokens
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, Response, jsonify
from registerForms import registerForm, verifyForm, faceForm, faceForm2
from editform import editform
from loginForm import loginForm, verifyForm2
from resetpwForm import resetpwForm
from cfmEmailForm import cfmEmailForm
from unlockForm import unlockForm
from ProfilePictureForm import ProfilePictureForm
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_mysqldb import MySQL
import MySQLdb.cursors
from datetime import datetime, timedelta
import pyotp
from email.message import EmailMessage
import smtplib
import ssl
from flask_apscheduler import APScheduler
import csv
# Face Recognition
import cv2
import os
from deepface import DeepFace
import time
import cryptography
from cryptography.fernet import Fernet
import json
from collections import defaultdict
from functools import wraps
# oAuth
import os
import pathlib
import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from google.auth.transport.requests import Request as GoogleAuthRequest
from werkzeug.datastructures import CombinedMultiDict
# SMS
from twilio.rest import Client

# Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = "urkey"
app.config['RECAPTCHA_PUBLIC_KEY'] = 'urkey'
app.config['RECAPTCHA_PRIVATE_KEY'] = 'urkey'

WTF_CSRF_ENABLED = True
WTF_CSRF_SECRET_KEY = 'verysecretkey'  # CSRF Token
csrf = CSRFProtect(app)
app.secret_key = "urkey"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # to allow Http traffic for local dev

GOOGLE_CLIENT_ID = "urclientid"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email",
            "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

# MySQL Database
mysql = MySQL(app)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'sysproject'
app.config['MYSQL_DB'] = 'sysproject'
app.config['MYSQL_PORT'] = 3306
app.permanent_session_lifetime = timedelta(minutes=60)
session_out = app.permanent_session_lifetime
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# OTP Email Details
email_sender = 'uremail'
email_sender_pw = 'urpw'
email_subject = 'OTP Code'
# OTP SMS Details
account_sid = 'uraccountSID'
auth_token = 'urauthtoken'
twilio_number = 'urnum'
#Geolocation
SINGAPORE_LAT_MIN = 1.15
SINGAPORE_LAT_MAX = 1.47
SINGAPORE_LON_MIN = 103.59
SINGAPORE_LON_MAX = 104.03
# Set the maximum number of login attempts
MAX_LOGIN_ATTEMPTS = 3

# Delete OTP
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()


@scheduler.task('interval', id='remove_otp', seconds=60)
def remove_otp():
    with app.app_context():
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('DELETE FROM otp WHERE userid > 0 AND otp_expire < NOW()')  # This deletes the entire row
        cursor.execute(
            'DELETE FROM otplogin WHERE (userid > 0 AND otp_expire < NOW()) OR (userid > 0 AND verified = TRUE)')  # This deletes the entire row
        mysql.connection.commit()
        cursor.close()


@app.route('/')
def home():
    if 'loggedin' in session and session['admin'] == "no":
        # User is logged in, show them the home page  
        return render_template('home.html', username=session['username'])
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    form = loginForm(request.form)
    form2 = verifyForm2(request.form)
    ip_address = request.form.get('ip_address', '')

    # Fetch geolocation information based on IP address
    response = requests.get(f"http://ip-api.com/json/{ip_address}")
    data = response.json()
    latitude = float(data['lat'])
    longitude = float(data['lon'])
    if request.method == 'POST':
        if form2.validate_on_submit():
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            userid = session['userid']
            username = session['username']
            email = session['email']
            otpinput = form2.otpinput.data
            cursor.execute('SELECT otp FROM otplogin WHERE email = %s', (email,))
            otpcode = cursor.fetchone()['otp']
            if otpinput == str(otpcode):
                session['loggedin'] = True
                session['userid'] = userid
                session['username'] = username
                session['admin'] = "no"
                cursor.execute('UPDATE otplogin SET verified = TRUE WHERE email = %s', (email,))
                mysql.connection.commit()
                flash('Welcome %s' % username)
                return redirect(url_for("home"))
            else:
                return render_template('verify.html', form=form2, email=email, error=True)

    if request.method == 'POST':
        # Check if "username" and "password" POST requests exist (user submitted form)
        if form.validate_on_submit():

            # Create variables for easy access
            username = form.username.data
            password = form.password.data

            # Retrieve the IP address of the user
            ip_address = request.remote_addr

            # Check if account exists using MySQL
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM user WHERE username = %s', (username,))

            # Fetch one record and return result
            account = cursor.fetchone()

            if account is not None and (SINGAPORE_LAT_MIN <= latitude <= SINGAPORE_LAT_MAX) and (
                    SINGAPORE_LON_MIN <= longitude <= SINGAPORE_LON_MAX):
                user_hashpwd = account.get('password')
                email = account.get('email')
                userid = account.get('userid')
                pw_expiry = account.get('pw_expiry')
                admin = account.get('admin')
                num_locked = account.get('num_locked')
                if user_hashpwd is not None and Bcrypt().check_password_hash(user_hashpwd, password):
                    account_is_lock = account['is_locked']
                    now = datetime.now()
                    # Check is the account locked. Create session data, we can access this data in other routes
                    if not account_is_lock and now < pw_expiry and admin == 'no' and num_locked <= 2:
                        session['userid'] = userid
                        session['username'] = username
                        session['email'] = email
                        print(latitude)
                        print(longitude)
                        # LOG ACCOUNT LOGIN
                        useragent = request.user_agent.string
                        cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
                        account = cursor.fetchone()
                        userid = account['userid']
                        log_datetime = datetime.now()
                        log_category = "Login"
                        log_activity = "User has Login"
                        log_status = "Successful"
                        cursor.execute(
                            'INSERT INTO userlog (log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                            (log_datetime, log_category, log_activity, ip_address, log_status, useragent, userid)
                        )
                        mysql.connection.commit()
                        # OTP
                        key = pyotp.random_base32()
                        otp = pyotp.TOTP(key, interval=300)
                        otpcode = str(otp.now())
                        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                        otp_expire = datetime.now() + timedelta(minutes=1)
                        otp_expire_time = otp_expire.strftime('%H:%M:%S')
                        cursor.execute('INSERT INTO otplogin (email, otp, otp_expire) VALUES (%s, %s, %s)',
                                       (email, otpcode, otp_expire,))
                        mysql.connection.commit()
                        cursor.close()
                        # OTP Email
                        msg = EmailMessage()
                        msg['From'] = email_sender
                        msg['To'] = email
                        msg['Subject'] = email_subject
                        msg.set_content('This OTP is valid for 1 minute It will expire at {}\nYour OTP is: {}'.format(
                            otp_expire_time, otpcode))
                        context = ssl.create_default_context()
                        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                            smtp.login(email_sender, email_sender_pw)
                            smtp.sendmail(email_sender, email, msg.as_string())
                        return render_template('verify.html', form=form2, email=email)
                    elif now > pw_expiry and admin == 'no':
                        cursor.execute('UPDATE user SET is_locked = TRUE WHERE username = %s', (username,))
                        mysql.connection.commit()
                        # LOG FAILED LOGIN
                        useragent = request.user_agent.string
                        cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
                        account = cursor.fetchone()
                        userid = account['userid']
                        log_datetime = datetime.now()
                        log_category = "Login"
                        log_activity = "Password has Expired"
                        log_status = "Unsuccessful"
                        cursor.execute(
                            'INSERT INTO userlog (log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                            (log_datetime, log_category, log_activity, ip_address, log_status, useragent, userid)
                        )
                        mysql.connection.commit()
                        flash('Password has expired. Please key in your email to reset password.')
                        return redirect(url_for('cfmEmail'))
                    elif admin == 'yes':
                        session['loggedin'] = True
                        session['userid'] = userid
                        session['username'] = username
                        session['admin'] = admin
                        return redirect(url_for('admin'))
                    elif account_is_lock and num_locked <= 2:
                        flash('Exceeded maximum login attempts. Account is locked. Please click on unlock password.')
                        return render_template('login.html', form=form)
                    elif account_is_lock and num_locked == 3:
                        flash('Exceeded maximun unlock attempts. Please contact admin to unlock account')
                        return render_template('login.html', form=form)
                else:
                    # LOG FAILED LOGIN
                    useragent = request.user_agent.string
                    cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
                    account = cursor.fetchone()
                    userid = account['userid']
                    log_datetime = datetime.now()
                    log_category = "Login"
                    log_activity = "Failed Login"
                    log_status = "Unsuccessful"
                    cursor.execute(
                        'INSERT INTO userlog (log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                        (log_datetime, log_category, log_activity, ip_address, log_status, useragent, userid)
                    )
                    mysql.connection.commit()
                    # Increment the login attempts counter
                    session['login_attempts'] = session.get('login_attempts', 0) + 1

                    if session.get('login_attempts', 0) >= MAX_LOGIN_ATTEMPTS:
                        num_locked += 1
                        cursor.execute('UPDATE user SET is_locked = TRUE, num_locked = %s WHERE username = %s',
                                       (num_locked, username,))
                        mysql.connection.commit()
                        # LOG FOR ACCOUNT LOCK AND EXCEEDED ATTEMPTS
                        useragent = request.user_agent.string
                        cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
                        account = cursor.fetchone()
                        userid = account['userid']
                        log_datetime = datetime.now()
                        log_category = "Login"
                        log_activity = "Exceeded Attempts and Account Lockout"
                        log_status = "Unsuccessful"
                        cursor.execute(
                            'INSERT INTO userlog (log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                            (log_datetime, log_category, log_activity, ip_address, log_status, useragent, userid)
                        )
                        mysql.connection.commit()
                        flash('Exceeded maximum login attempts. Account is locked')
                        return render_template('login.html', form=form)
                    # Account doesn’t exist or username/password incorrect
                    flash('Incorrect username and password!')
            elif not (SINGAPORE_LAT_MIN <= latitude <= SINGAPORE_LAT_MAX) and not (
                    SINGAPORE_LON_MIN <= longitude <= SINGAPORE_LON_MAX):
                flash("Login rejected: Invalid Location")
            else:
                flash('Incorrect username and password!')

    # Show the login form with message (if any)
    return render_template('login.html', form=form)


@app.route('/cfmEmail', methods=['GET', 'POST'])
def cfmEmail():
    form = cfmEmailForm(request.form)
    form2 = verifyForm2(request.form)
    if form2.validate_on_submit():
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        email = session['email']
        otpinput = form2.otpinput.data
        cursor.execute('SELECT otp FROM otplogin WHERE email = %s', (email,))
        otpcode = cursor.fetchone()['otp']
        if otpinput == str(otpcode):
            return redirect(url_for('resetpw'))
        else:
            return render_template('verify.html', form=form2, email=email, error=True)
    if form.validate_on_submit():
        email = form.cfmEmail.data
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE email = %s', (email,))
        account = cursor.fetchone()
        num_locked = account['num_locked']
        if account and num_locked <= 2:
            session['email'] = email
            key = pyotp.random_base32()
            otp = pyotp.TOTP(key, interval=300)
            otpcode = str(otp.now())
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            otp_expire = datetime.now() + timedelta(minutes=1)
            otp_expire_time = otp_expire.strftime('%H:%M:%S')
            cursor.execute('INSERT INTO otplogin (email, otp, otp_expire) VALUES (%s, %s, %s)',
                           (email, otpcode, otp_expire,))
            mysql.connection.commit()
            cursor.close()
            # OTP Email
            msg = EmailMessage()
            msg['From'] = email_sender
            msg['To'] = email
            msg['Subject'] = email_subject
            msg.set_content(
                'This OTP is valid for 1 minute It will expire at {}\nYour OTP is: {}'.format(otp_expire_time, otpcode))
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(email_sender, email_sender_pw)
                smtp.sendmail(email_sender, email, msg.as_string())
            return render_template('verify.html', form=form2, email=email)
        elif num_locked == 3:
            flash('Exceeded maximun unlock attempts. Please contact admin to unlock account')
            return redirect(url_for('login'))
        else:
            flash('Email does not exist')
            return render_template('cfmEmail.html', form=form)
    return render_template('cfmEmail.html', form=form)


@app.route('/resetpw', methods=['GET', 'POST'])
def resetpw():
    form = resetpwForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            password = form.newpw.data
            hashed_password = Bcrypt().generate_password_hash(password)
            email = session['email']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM user WHERE email = %s', (email,))
            account = cursor.fetchone()
            pw1 = account.get('password1')
            pw2 = account.get('password2')
            pw3 = account.get('password3')
            pw_expiry = datetime.now() + timedelta(days=30)
            bcrypt = Bcrypt()
            if pw1 and bcrypt.check_password_hash(pw1, password):
                flash('Cannot reuse previous password!')
                return render_template('resetpw.html', form=form, error=True)
            elif pw2 and bcrypt.check_password_hash(pw2, password):
                flash('Cannot reuse previous password!')
                return render_template('resetpw.html', form=form, error=True)
            elif pw3 and bcrypt.check_password_hash(pw3, password):
                flash('Cannot reuse previous password!')
                return render_template('resetpw.html', form=form, error=True)
            else:
                if pw2 is None:
                    cursor.execute(
                        'UPDATE user SET password = %s, is_locked = FALSE, pw_expiry = %s, password2 = %s WHERE email = %s',
                        (hashed_password, pw_expiry, hashed_password, email,))
                    mysql.connection.commit()
                elif pw3 is None:
                    cursor.execute(
                        'UPDATE user SET password = %s, is_locked = FALSE, pw_expiry = %s, password3 = %s WHERE email = %s',
                        (hashed_password, pw_expiry, hashed_password, email,))
                    mysql.connection.commit()
                else:
                    cursor.execute(
                        'UPDATE user SET password = %s, is_locked = FALSE, pw_expiry = %s, password1 = %s WHERE email = %s',
                        (hashed_password, pw_expiry, hashed_password, email,))
                    mysql.connection.commit()

                useragent = request.user_agent.string
                ip_address = request.remote_addr
                cursor.execute('SELECT * FROM user WHERE email = %s', (email,))
                account = cursor.fetchone()
                userid = account['userid']
                log_datetime = datetime.now()
                log_category = "Forgot Password"
                log_activity = "Reset Password"
                log_status = "Successful"
                cursor.execute(
                    'INSERT INTO userlog (log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                    (log_datetime, log_category, log_activity, ip_address, log_status, useragent, userid)
                )
                mysql.connection.commit()

                flash('Password has been reset')
                return redirect(url_for('login'))

        return render_template('resetpw.html', form=form)
    return render_template('resetpw.html', form=form)


@app.route('/logout')
def logout():
    if 'loggedin' in session:
        username = session['username']
        session.pop("username", None)
        session.pop("loggedin", None)

        # LOG USER LOGOUT
        # Retrieve the IP address of the user
        ip_address = request.remote_addr
        useragent = request.user_agent.string
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
        account = cursor.fetchone()
        userid = account['userid']
        log_datetime = datetime.now()
        log_category = "Logout"
        log_activity = "User has Logout"
        log_status = "Successful"

        cursor.execute(
            'INSERT INTO userlog (log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid) VALUES (%s, %s, %s, %s, %s, %s, %s)',
            (log_datetime, log_category, log_activity, ip_address, log_status, useragent, userid)
        )
        mysql.connection.commit()
        flash('You have successfully logged out!')
    return redirect(url_for("home"))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = registerForm(request.form)
    form2 = verifyForm(request.form)
    # To add a send again function, and SMS option
    if form2.validate_on_submit():
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        username = session['username']
        firstname = session['firstname']
        lastname = session['lastname']
        hashpw = session['password']
        email = session['email']
        phoneno = session['phoneno']
        admin = session['admin']
        num_locked = session['num_locked']
        pw_expiry = session['pw_expiry']
        is_locked = session['is_locked']
        otpinput = form2.otpinput.data
        smsotpinput = form2.smsotpinput.data
        cursor.execute('SELECT * FROM otp WHERE email = %s', (email,))
        otprow = cursor.fetchone()
        otpcode = otprow['otp']
        smsotpcode = otprow['otp2']
        if otpinput == str(otpcode) and smsotpinput == str(smsotpcode):
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute(
                'INSERT INTO user (username, first_name, last_name, password, password1, email, phone_no, pw_expiry, admin, num_locked, is_locked) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                (username, firstname, lastname, hashpw, hashpw, email, phoneno, pw_expiry, admin, num_locked, is_locked,))
            mysql.connection.commit()
            session.clear()
            # Insert log into the database
            cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
            account = cursor.fetchone()
            userid = account['userid']
            # LOG USER CREATED
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Registration"
            log_activity = "Created"
            log_status = "Successful"

            cursor.execute(
                'INSERT INTO userlog (log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, ip_address, log_status, useragent, userid)
            )
            mysql.connection.commit()
            cursor.close()
            flash('Account created successfully!')
            return redirect(url_for("home"))
        else:
            cursor.execute('SELECT * FROM systemlog WHERE log_email = %s', (email,))
            account = cursor.fetchone()
            log_email = account['log_email']
            # LOG USER CREATED
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Registration"
            log_activity = "Failed OTP"
            log_status = "Unsuccessful"

            cursor.execute(
                'INSERT INTO systemlog (log_datetime, log_category, log_activity, log_status, log_email, log_ip, log_useragent) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, log_status, log_email, ip_address, useragent)
            )
            mysql.connection.commit()
            cursor.close()
            return render_template('verify.html', form=form2, email=email, error=True)
    if form.validate_on_submit():
        username = form.username.data
        firstname = form.firstname.data
        lastname = form.lastname.data
        password = form.password.data
        hashpw = Bcrypt().generate_password_hash(password)
        email = form.email.data
        phoneno = form.phoneno.data
        pw_expiry = datetime.now() + timedelta(days=30)

        # So i can transfer data across forms
        session['username'] = username
        session['firstname'] = firstname
        session['lastname'] = lastname
        session['password'] = hashpw
        session['email'] = email
        session['phoneno'] = phoneno
        session['admin'] = "no"
        session['num_locked'] = 0
        session['is_locked'] = False
        session['pw_expiry'] = pw_expiry

        # OTP
        key = pyotp.random_base32()
        otp = pyotp.TOTP(key, interval=60)
        otpcode = str(otp.now())
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        otp_expire = datetime.now() + timedelta(minutes=1)
        otp_expireformat = otp_expire.strftime('%H:%M:%S')
        # OTP Email
        msg = EmailMessage()
        msg['From'] = email_sender
        msg['To'] = email
        msg['Subject'] = email_subject
        msg.set_content(
            'This OTP is valid for 1 minute It will expire at {}\nYour OTP is: {}'.format(otp_expireformat, otpcode))
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(email_sender, email_sender_pw)
            smtp.sendmail(email_sender, email, msg.as_string())
        # OTP SMS
        key = pyotp.random_base32()
        smsotp = pyotp.TOTP(key, interval=60)
        smsotpcode = str(smsotp.now())

        client = Client(account_sid, auth_token)
        message = client.messages.create(
            body='This OTP is valid for 1 minute It will expire at {}\nYour OTP is: {}'.format(otp_expireformat,
                                                                                               smsotpcode),
            messaging_service_sid='MG01306ae938ccfe22158ce7a420e6eccf',
            from_=twilio_number,
            to=('+65{}').format(phoneno)
        )
        cursor.execute('INSERT INTO otp (email,otp,otp2, otp_expire) VALUES (%s,%s,%s,%s)',
                       (email, otpcode, smsotpcode, otp_expire))
        mysql.connection.commit()
        cursor.close()
        return render_template('verifyregister.html', form=form2, email=email, phoneno=phoneno)
    return render_template('register.html', form=form)


@app.route('/registerface', methods=['GET', 'POST'])
def register_face():
    form = faceForm(request.form)

    if form.validate_on_submit():
        def extract_faces(img):
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            face_detector = cv2.CascadeClassifier(
                'static/Rayden/FaceRecog/haarcascade_frontalface_default.xml')  # haarcascade for face detection
            face_points = face_detector.detectMultiScale(gray, 1.3, 5)
            return face_points

        camera = cv2.VideoCapture(0)
        username = session['username']  # Temp var to change to session username
        userimagefolder = 'static/Rayden/FaceRecog/faces/{}'.format(username)
        # Makes directory for user(May Change to SQL Ltr but SQL will likely be file path)
        if not os.path.isdir(userimagefolder):
            os.makedirs(userimagefolder)
        counter = 0
        delaycounter = 0
        while True:
            ret, frame = camera.read()  # ret is a boolean, frame is the image
            faces = extract_faces(frame)  # Extracts the face from the return frame of the camera
            if ret:
                for (x, y, w, h) in faces:
                    cv2.rectangle(frame, (x, y), (x + w, y + h), (255, 0, 0), 2)  # Draws a rectangle around the face
                    cv2.putText(frame, 'Face captured {}/10'.format(counter), (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX,
                                0.9,
                                (255, 0, 0), 2)
                    cv2.imshow('Register Face', frame)
                    if cv2.waitKey(1) == ord('q'):  # Press q to quit
                        break
                    if delaycounter % 10 == 0:  # So that it only captures 1 frame every 10 frames
                        cv2.imwrite('static/Rayden/FaceRecog/faces/{}/{}.jpg'.format(username, counter),
                                    frame[y:y + h, x:x + w])  # Saves the face in the folder
                        counter += 1
                    delaycounter += 1
                    # time.sleep(3) #Increase time for more face variations but only renders 1 frame every 3 seconds so it's not ideal
                    if counter == 10:
                        camera.release()
                        cv2.destroyAllWindows()
                        flash('Face registered successfully!')
                        return redirect(url_for("home"))
    return render_template('registerface.html', form=form)


@app.route('/verifyface', methods=['GET', 'POST'])
def verify_face():
    form = faceForm2(request.form)
    if form.validate_on_submit():
        def extract_faces(img):
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            face_detector = cv2.CascadeClassifier(
                'static/Rayden/FaceRecog/haarcascade_frontalface_default.xml')  # haarcascade for face detection
            face_points = face_detector.detectMultiScale(gray, 1.3, 5)
            return face_points

        camera = cv2.VideoCapture(0)
        username = form.username.data  # Temp var to change to session username
        counter = 0
        while True:
            ret, frame = camera.read()  # ret is a boolean, frame is the image
            faces = extract_faces(frame)  # Extracts the face from the return frame of the camera
            if ret:
                for (x, y, w, h) in faces:
                    compareface = frame[y:y + h, x:x + w]

                    counter2 = 0
                    while counter2 != 10:  # Tries 10 times before moving to the next image
                        try:

                            if DeepFace.verify(compareface,
                                               'static/Rayden/FaceRecog/faces/{}/{}.jpg'.format(username, counter)):
                                print('Face found')
                                camera.release()
                                cv2.destroyAllWindows()
                                session['faceverify'] = 'true'
                                session['username'] = username
                                return redirect(url_for("verifyspoof"))
                        except:
                            print('Face not found')
                            counter2 += 1
                            if counter2 == 10:
                                print("Moving to next img")
                    counter += 1
                    if counter == 10:
                        camera.release()
                        cv2.destroyAllWindows()
                        print("Face not found")
                        flash('Face login failed, please try again or another method')
                        return redirect(url_for("login"))
    return render_template('verifyface.html', form=form)


@app.route('/verifyspoof', methods=['GET', 'POST'])
def verifyspoof():
    try:
        if session['faceverify'] == 'true':
            def extract_faces(img):
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                face_detector = cv2.CascadeClassifier(
                    'static/Rayden/FaceRecog/haarcascade_frontalface_default.xml')  # haarcascade for face detection
                face_points = face_detector.detectMultiScale(gray, 1.3, 5)
                return face_points

            camera = cv2.VideoCapture(0)
            count = 0
            while True:
                ret, frame = camera.read()  # ret is a boolean, frame is the image
                faces = extract_faces(frame)  # Extracts the face from the return frame of the camera
                if count == 20:
                    flash(
                        'Face login failed, please try again or another method')  # Message color need change to red, need to add logs
                    session['faceverify'] = 'false'
                    return redirect(url_for("login"))  # May redirect to login page instead of home
                if ret:
                    for (x, y, w, h) in faces:
                        compareface = frame[y:y + h, x:x + w]
                        try:
                            emotion_list = DeepFace.analyze(compareface, actions=['emotion'])
                            dominant_emotion = emotion_list[0]['dominant_emotion']
                            print(dominant_emotion)
                            count += 1
                            if dominant_emotion == 'surprise':
                                camera.release()
                                cv2.destroyAllWindows()
                                flash('Face login successful!')
                                session['faceverify'] = 'false'
                                # Put all the login stuff and session stuff here, logs also need to be added here
                                session['loggedin'] = True
                                # Insert log into the database
                                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                                cursor.execute('SELECT * FROM user WHERE username = %s', (session['username'],))
                                account = cursor.fetchone()
                                userid = account['userid']
                                session['userid'] = userid
                                # LOG USER CREATED
                                ip_address = request.remote_addr
                                useragent = request.user_agent.string
                                log_datetime = datetime.now()
                                log_category = "Login"
                                log_activity = "User has Login"
                                log_status = "Successful"

                                cursor.execute(
                                    'INSERT INTO userlog (log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                                    (
                                        log_datetime, log_category, log_activity, ip_address, log_status, useragent,
                                        userid)
                                )
                                mysql.connection.commit()
                                cursor.close()
                                return redirect(url_for("home"))
                        except:
                            print("Error")
    except:
        return (render_template('error.html'))
    else:
        return (render_template('error.html'))


@app.route('/about')
def about_us():
    return render_template('about.html')


@app.route('/shop')
def collection():
    return render_template('shop.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/product')
def product():
    return render_template('single.html')


@app.route('/admin')
def admin():

    if 'loggedin' in session and session['admin'] == "yes":
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # Calculate the start time for the last 24 hours
        start_time = datetime.now() - timedelta(hours=24)
        # Query failed login activities
        cursor.execute(
            "SELECT * FROM userlog WHERE log_activity = 'Failed Login' AND log_datetime >= %s ORDER BY log_datetime ASC",
            (start_time,))
        log_entries = cursor.fetchall()

        # Query successful login activities
        cursor.execute(
            "SELECT * FROM userlog WHERE log_activity = 'User has Login' AND log_datetime >= %s ORDER BY log_datetime ASC",
            (start_time,))
        successful_log_entries = cursor.fetchall()

        cursor.close()

        # Prepare data for failed login chart
        chart_data = defaultdict(int)
        for entry in log_entries:
            log_date_str = entry['log_datetime']
            log_date = datetime.strptime(log_date_str, '%Y-%m-%d %H:%M:%S.%f')
            month_year = log_date.strftime('%b %Y')
            chart_data[month_year] += 1

        chart_labels = list(chart_data.keys())
        chart_values = list(chart_data.values())

        # Prepare data for successful login chart
        successful_chart_data = defaultdict(int)
        for entry in successful_log_entries:
            log_date_str = entry['log_datetime']
            log_date = datetime.strptime(log_date_str, '%Y-%m-%d %H:%M:%S.%f')
            month_year = log_date.strftime('%b %Y')
            successful_chart_data[month_year] += 1

        successful_chart_labels = list(successful_chart_data.keys())
        successful_chart_values = list(successful_chart_data.values())

    return render_template('admin.html', username=session['username'], chart_labels=chart_labels,
                           chart_values=chart_values, successful_chart_labels=successful_chart_labels,
                           successful_chart_values=successful_chart_values)


@app.route('/retrieveLogs')
def retrieveLogs():
    if 'loggedin' in session and session['admin'] == "yes":
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM userlog ORDER BY log_datetime DESC")
        log_entries = cursor.fetchall()
        cursor.execute("SELECT COUNT(*) as log_count FROM userlog")
        log_count = cursor.fetchone()["log_count"]
        cursor.close()
        return render_template('retrieveLogs.html', log_entries=log_entries, log_count=log_count)


@app.route('/retrieveSystemLogs')
def retrieveSystemLogs():
    if 'loggedin' in session and session['admin'] == "yes":
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM systemlog ORDER BY log_datetime DESC")
        log_entries = cursor.fetchall()
        cursor.execute("SELECT COUNT(*) as log_count FROM systemlog")
        log_count = cursor.fetchone()["log_count"]
        cursor.close()
        return render_template('retrieveSystemLogs.html', log_entries=log_entries, log_count=log_count)


@app.route('/downloadLogsCSV')
def downloadLogsCSV():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        "SELECT logid, log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid FROM userlog ORDER BY log_datetime DESC")
    log_entries = cursor.fetchall()
    cursor.close()

    csv_data = "logid,log_datetime,log_category,log_activity,log_userip,log_status,log_useragent,userid\n"
    for row in log_entries:
        csv_data += f"{row['logid']},{row['log_datetime']},{row['log_category']},{row['log_activity']},{row['log_userip']},{row['log_status']},{row['log_useragent']},{row['userid']}\n"

    response = Response(csv_data, content_type='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=userlogs.csv'
    return response


@app.route('/downloadSystemLogsCSV')
def downloadSystemLogsCSV():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        "SELECT systemlogid, log_datetime, log_category, log_activity, log_status, log_email, log_passwd, log_cfmpasswd, log_ip, log_useragent FROM systemlog ORDER BY log_datetime DESC")
    log_entries = cursor.fetchall()
    cursor.close()

    csv_data = "systemlogid, log_datetime, log_category, log_activity, log_status, log_ip, log_useragent\n"
    for row in log_entries:
        csv_data += f"{row['systemlogid']},{row['log_datetime']},{row['log_category']},{row['log_activity']},{row['log_status']},{row['log_ip']},{row['log_useragent']},\n"

    response = Response(csv_data, content_type='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=systemlogs.csv'
    return response


@app.route('/retrieveUserAccount', methods=['GET', 'POST'])
def retrieveUserAccount():
    form = unlockForm()
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM user")
    accounts = cursor.fetchall()
    cursor.close()
    return render_template('retrieveUserAccount.html', accounts=accounts, form=form)


@app.route('/UnlockAccount/<userid>', methods=['POST'])
def UnlockAccount(userid):
    form = unlockForm()
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM user WHERE userid = %s", (userid,))
    account = cursor.fetchone()
    if request.method == 'POST':
        if form.validate_on_submit():
            userid = account.get('userid')
            print(userid)
            cursor.execute("UPDATE user SET num_locked = 0, is_locked = FALSE WHERE userid = %s", (userid,))
            mysql.connection.commit()
            cursor.close()
            return redirect(url_for('retrieveUserAccount'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    profile_picture_form = ProfilePictureForm(CombinedMultiDict((request.files, request.form)))
    if 'loggedin' in session:
        username = session['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
        account = cursor.fetchone()
        
        if request.method == "GET":
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM user WHERE userid = %s', (session['userid'],))
            account = cursor.fetchone()
        # Create an instance of the profile picture form
        # Handle profile picture upload
        if profile_picture_form.validate_on_submit():
            profile_picture = profile_picture_form.profile_picture.data
            profile_picture.save(app.config['UPLOAD_FOLDER'] + profile_picture.filename)
            if profile_picture:
                userid = session.get('userid')  # Get the user's ID from the session
                cursor.execute('UPDATE user SET profile_picture = %s WHERE userid = %s', (profile_picture.filename, userid))
                mysql.connection.commit()

                flash('Profile picture uploaded successfully', 'success')
                return redirect(url_for('profile'))
        else:
            print("Form validation failed", profile_picture_form.errors)  # Print validation errors
 
        try: 
            if session['tempcredit']:
                tempcredit = session['tempcredit']
        except:
            session['tempcredit'] = '--'

        try:
            if account['profile_picture']:
                picstatus = True
            else:
                picstatus = False
        except:
            picstatus = False
        
        return render_template('profile.html', username=session['username'], account=account, tempcredit=session['tempcredit'], form=profile_picture_form,picstatus=picstatus)
 
    return redirect(url_for("login"))


@app.route('/editprofile', methods=['GET', 'POST'])
def editprofile():
    form = editform(request.form)

    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE userid = %s', (session['userid'],))
        account = cursor.fetchone()
        if request.method == 'GET':
            # User is logged in; show them the edit profile page
            userid = account['userid']
            form.first_name.data = account['first_name']
            form.last_name.data = account['last_name']
            form.phoneno.data = account['phone_no']
            form.credit_card.data = session['tempcredit']
            form.address.data = account['address']
            form.gender.data = account['gender']

        if request.method == 'POST':
            if form.validate_on_submit():
                first_name = form.first_name.data
                last_name = form.last_name.data
                phoneno = form.phoneno.data
                credit_card = form.credit_card.data
                address = form.address.data
                gender = form.gender.data
                temp_credit = '**** **** **** {}'.format(credit_card[-4:])
                session['tempcredit'] = temp_credit

                # Generate a new symmetric key
                symmetric_key = Fernet.generate_key()

                # Encrypt the credit card using the symmetric key
                f = Fernet(symmetric_key)
                encrypted_credit_card = f.encrypt(credit_card.encode())

                # Store the encrypted credit card and symmetric key in the user table
                cursor.execute(
                    'UPDATE user SET first_name = %s, last_name = %s, phone_no = %s, credit_card = %s, gender = %s, address = %s, symmetric_key = %s WHERE userid = %s',
                    (first_name, last_name, phoneno, encrypted_credit_card, gender, address, symmetric_key, session['userid']))
                mysql.connection.commit()

                flash('Profile has been successfully edited')
                return redirect(url_for('profile'))
    return render_template('editprofile.html', userid=session['userid'], account=account, form=form, error=True)

@app.route("/oauth-login")
def oauthlogin():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


def get_user_by_email(email):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    query = "SELECT * FROM user WHERE email = %s"
    cursor.execute(query, (email,))

    user = cursor.fetchone()

    cursor.close()
    return user


def generate_username(first_name, last_name):
    username = f"{first_name.lower()}.{last_name.lower()}"
    return username


def create_new_user(user_data):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    username = generate_username(user_data["first_name"], user_data["last_name"])

    query = "INSERT INTO user (email, first_name, last_name, username) VALUES (%s, %s, %s, %s)"
    values = (
        user_data["email"],
        user_data["first_name"],
        user_data["last_name"],
        username,
    )
    cursor.execute(query, values)
    mysql.connection.commit()
    new_user_id = cursor.lastrowid

    cursor.close()
    return new_user_id


@app.route('/callback')
def callback():
    if "error" in request.args:
        return "Authorization failed: " + request.args["error"]

    flow.fetch_token(authorization_response=request.url)

    if session.get("state") != request.args.get("state"):
        return "Authorization failed: State mismatch."

    credentials = flow.credentials
    certs_url = "https://www.googleapis.com/oauth2/v3/certs"

    google_auth_request = GoogleAuthRequest()

    response = requests.get(certs_url)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials.id_token,
        request=google_auth_request,
        audience=GOOGLE_CLIENT_ID
    )

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM user WHERE email = %s', (id_info.get("email"),))
    account = cursor.fetchone()

    if account is not None:
        session['loggedin'] = True
        session['userid'] = account['userid']
        session['username'] = account['username']
        session['email'] = account['email']
        flash('Welcome %s' % session['username'])
        # LOG ACCOUNT LOGIN
        # Retrieve the IP address of the user
        ip_address = request.remote_addr
        useragent = request.user_agent.string
        cursor.execute('SELECT * FROM user WHERE username = %s', (session['username'],))
        account = cursor.fetchone()
        userid = account['userid']
        log_datetime = datetime.now()
        log_category = "Login"
        log_activity = "User has Login"
        log_status = "Successful"
        cursor.execute(
            'INSERT INTO userlog (log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid) VALUES (%s, %s, %s, %s, %s, %s, %s)',
            (log_datetime, log_category, log_activity, ip_address, log_status, useragent, userid)
        )
        mysql.connection.commit()
        cursor.close()
    else:
        cursor.execute('SELECT * FROM user WHERE username = %s',
                       (generate_username(id_info.get("given_name"), id_info.get("family_name")),))
        existing_user = cursor.fetchone()

        if existing_user is not None:
            # Get the userid of the existing user
            userid = existing_user['userid']
            # LOG FAILED LOGIN
            useragent = request.user_agent.string
            ip_address = request.remote_addr
            log_datetime = datetime.now()
            log_category = "Login"
            log_activity = "Failed Login"
            log_status = "Unsuccessful"
            cursor.execute(
                'INSERT INTO userlog (log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, ip_address, log_status, useragent, userid)
            )
            mysql.connection.commit()
            flash('An account with this username already exists.')
        else:
            new_user_data = {
                "email": id_info.get("email"),
                "first_name": id_info.get("given_name"),
                "last_name": id_info.get("family_name")
            }
            new_user_id = create_new_user(new_user_data)
            session['loggedin'] = True
            session['userid'] = new_user_id
            session['username'] = generate_username(id_info.get("given_name"), id_info.get("family_name"))
            session['email'] = id_info.get("email")
            flash('Welcome %s' % session['username'])
    return redirect(url_for("home"))

#Remove comment and debug mode during deployment
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error404.html')

@app.errorhandler(Exception)
def page_not_found(e):  
    return render_template('error.html')

@app.route('/display/<filename>')
def display_image(filename):
    return redirect(url_for('static', filename='/' + filename), code=301)

if __name__ == '__main__':
    app.run()
