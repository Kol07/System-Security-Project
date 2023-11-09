# Tesmond
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, ValidationError
from wtforms.validators import DataRequired
import re
from flask_mysqldb import MySQL
from datetime import datetime
from flask import request
import MySQLdb.cursors

mysql = MySQL()

class resetpwForm(FlaskForm):
    newpw = PasswordField('New Password', validators=[(DataRequired())])
    def validate_newpw(FlaskForm,field):
        regex = (r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$")
        if not re.fullmatch(regex,field.data):
            passwd = field.data
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Forgot Password"
            log_activity = "Password Requirement Not Met"
            log_status = "Unsuccessful"

            cursor.execute(
                'INSERT INTO systemlog (log_datetime, log_category, log_activity, log_status, log_passwd, log_ip, log_useragent) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, log_status, passwd, ip_address, useragent)
            )
            mysql.connection.commit()
            cursor.close()
            raise ValidationError("Password must contain at least 8 characters, 1 uppercase letter, 1 number and 1 special character")
        
    cfmpw = PasswordField('Confirmation Password', validators=[(DataRequired())])

    def validate_cfmpw(FlaskForm,field):
        if field.data != FlaskForm.newpw.data:
            passwd = FlaskForm.newpw.data
            cfmpasswd = field.data
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Forgot Password"
            log_activity = "Password do not match"
            log_status = "Unsuccessful"

            cursor.execute(
                'INSERT INTO systemlog (log_datetime, log_category, log_activity, log_status, log_passwd, log_cfmpasswd, log_ip, log_useragent) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, log_status, passwd, cfmpasswd, ip_address, useragent)
            )
            mysql.connection.commit()
            cursor.close()
            raise ValidationError("Passwords do not match")

    recaptcha = RecaptchaField()

class verifyForm(FlaskForm):
    otpinput = StringField('OTP',validators=[(DataRequired())])
