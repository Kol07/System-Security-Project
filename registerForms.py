#Rayden
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import EmailField,StringField,PasswordField,TelField, ValidationError #Import types of form data
from wtforms import EmailField,StringField,PasswordField,TelField #Import types of form data
from wtforms.validators import DataRequired #Import validators
from flask_wtf.file import FileField,FileAllowed
import re
from flask import request
from flask_mysqldb import MySQL
import MySQLdb.cursors
import pyotp
import smtplib
import ssl
from datetime import datetime
mysql = MySQL()
class registerForm(FlaskForm):
    email = EmailField(validators=[(DataRequired())])
    def validate_email(FlaskForm,field):
        regex = (r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
        if not re.fullmatch(regex,field.data) or '+' in field.data:
            email = field.data
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Registration"
            log_activity = "Invalid Email"
            log_status = "Unsuccessful"

            cursor.execute(
                'INSERT INTO systemlog (log_datetime, log_category, log_activity, log_status, log_email, log_ip, log_useragent) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, log_status, email, ip_address, useragent)
            )
            mysql.connection.commit()
            cursor.close()
            raise ValidationError("Invalid email address")
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE email = %s', (field.data,))
        account = cursor.fetchone()
        if account:
            userid = account['userid']
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Registration"
            log_activity = "Duplicate Email"
            log_status = "Unsuccessful"

            cursor.execute(
                'INSERT INTO userlog (log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, ip_address, log_status, useragent, userid)
            )
            mysql.connection.commit()
            raise ValidationError("Email already exists")
        cursor.execute('SELECT * FROM otp WHERE email = %s', (field.data,))
        account = cursor.fetchone()
        if account:
            raise ValidationError("Email is currently in verification, please wait 5 minutes.")
            
        
    username = StringField('Username',validators=[(DataRequired())])
    def validate_username(FlaskForm,field):
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE username = %s', (field.data,))
        account = cursor.fetchone()
        if account:
            cursor.execute('SELECT * FROM user WHERE username = %s', (field.data,))
            account = cursor.fetchone()
            userid = account['userid']
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Registration"
            log_activity = "Duplicate Username"
            log_status = "Unsuccessful"

            cursor.execute(
                'INSERT INTO userlog (log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, ip_address, log_status, useragent, userid)
            )
            mysql.connection.commit()
            cursor.close()
            raise ValidationError("Username already exists")
        
    firstname = StringField('First Name',validators=[(DataRequired())])
    lastname = StringField('Last Name',validators=[(DataRequired())])
    password = PasswordField('Password',validators=[(DataRequired())])
    def validate_password(FlaskForm,field):
        regex = (r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$")
        if not re.fullmatch(regex,field.data):
            passwd = field.data
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Registration"
            log_activity = "Password Requirement Not Met"
            log_status = "Unsuccessful"

            cursor.execute(
                'INSERT INTO systemlog (log_datetime, log_category, log_activity, log_status, log_passwd, log_ip, log_useragent) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, log_status, passwd, ip_address, useragent)
            )
            mysql.connection.commit()
            cursor.close()
            raise ValidationError("Password must contain at least 8 characters, 1 uppercase letter, 1 number and 1 special character")
    
    cfmpassword = PasswordField('Confirm password',validators=[(DataRequired())])
    def validate_cfmpassword(FlaskForm,field):
        if field.data != FlaskForm.password.data:
            passwd = FlaskForm.password.data
            cfmpasswd = field.data
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Registration"
            log_activity = "Password do not match"
            log_status = "Unsuccessful"

            cursor.execute(
                'INSERT INTO systemlog (log_datetime, log_category, log_activity, log_status, log_passwd, log_cfmpasswd, log_ip, log_useragent) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, log_status, passwd, cfmpasswd, ip_address, useragent)
            )
            mysql.connection.commit()
            cursor.close()
            raise ValidationError("Passwords do not match")
    
    phoneno = TelField("Phone number",validators=[(DataRequired())])
    def validate_phoneno(FlaskForm,field):
        regex = (r"^[8|9]\d{7}$")
        if not re.fullmatch(regex,field.data):
            raise ValidationError("Invalid phone number")
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE phone_no = %s', (field.data,))
        account = cursor.fetchone()
        if account:
            userid = account['userid']
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Registration"
            log_activity = "Duplicate PhoneNo"
            log_status = "Unsuccessful"

            cursor.execute(
                'INSERT INTO userlog (log_datetime, log_category, log_activity, log_userip, log_status, log_useragent, userid) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, ip_address, log_status, useragent, userid)
            )
            mysql.connection.commit()
            raise ValidationError("Phone number already exists")
        cursor.close()
    
    pfp = FileField('Profile picture',validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    recaptcha = RecaptchaField()

class verifyForm(FlaskForm):
    otpinput = StringField('OTP',validators=[(DataRequired())])
    smsotpinput = StringField('SMS OTP',validators=[(DataRequired())])
    
class faceForm(FlaskForm):
    recaptcha = RecaptchaField()

class faceForm2(FlaskForm):
    username = StringField('Username',validators=[(DataRequired())])
    recaptcha = RecaptchaField()

