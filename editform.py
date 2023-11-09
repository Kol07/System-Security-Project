#Alston
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
import cryptography
from cryptography.fernet import Fernet
mysql = MySQL()
class editform(FlaskForm):        
    first_name = StringField('First Name',validators=[(DataRequired())])
    last_name = StringField('Last Name',validators=[(DataRequired())])
    address = StringField('Address')
    gender = StringField('Gender')
    phoneno = TelField("Phone number",validators=[(DataRequired())])
    def validate_phoneno(FlaskForm,field):
        regex = (r"^[8|9]\d{7}$")
        if not re.fullmatch(regex,field.data):
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Edit Profile"
            log_activity = "Invalid Phone Number"
            log_status = "Unsuccessful"

            cursor.execute(
                'INSERT INTO systemlog (log_datetime, log_category, log_activity, log_status,  log_ip, log_useragent) VALUES (%s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, log_status,  ip_address, useragent)
            )
            mysql.connection.commit()
            cursor.close()
            raise ValidationError("Invalid phone number")
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE phone_no = %s', (field.data,))
        account = cursor.fetchone()
    credit_card = StringField('Credit Card')
    def validate_credit_card(FlaskForm,field):
        regex = (r"^[456]\d{3}-?\d{4}-?\d{4}-?\d{4}$")
        if not re.fullmatch(regex,field.data):
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Edit Profile"
            log_activity = "Invalid Credit Card Detail"
            log_status = "Unsuccessful"

            cursor.execute(
                'INSERT INTO systemlog (log_datetime, log_category, log_activity, log_status,  log_ip, log_useragent) VALUES (%s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, log_status,  ip_address, useragent)
            )
            mysql.connection.commit()
            cursor.close()
            raise ValidationError("Invalid credit card number")
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE credit_card = %s', (field.data,))
        account = cursor.fetchone()