# Tesmond
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, EmailField
from wtforms.validators import DataRequired, ValidationError
import re
from flask import request
from flask_mysqldb import MySQL
import MySQLdb.cursors
from datetime import datetime

mysql = MySQL()

class cfmEmailForm(FlaskForm):
    cfmEmail = EmailField(validators=[(DataRequired())])

    def validate_cfmEmail(FlaskForm,field):
        regex = (r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
        if not re.fullmatch(regex,field.data) or '+ ' in field.data:
            email = field.data
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Login"
            log_activity = "Invalid Confirmation Email"
            log_status = "Unsuccessful"

            cursor.execute(
                'INSERT INTO systemlog (log_datetime, log_category, log_activity, log_status, log_email, log_ip, log_useragent) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, log_status, email, ip_address, useragent)
            )
            mysql.connection.commit()
            cursor.close()
            raise ValidationError("Invalid email address")
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM otp WHERE email = %s', (field.data,))
        account = cursor.fetchone()
        if account:
            raise ValidationError("Email is currently in verification, please wait 5 minutes.")


    recaptcha = RecaptchaField()

class verifyForm(FlaskForm):
    otpinput = StringField('OTP',validators=[(DataRequired())])
