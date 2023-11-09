# Tesmond
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, ValidationError
from wtforms.validators import DataRequired
from flask_mysqldb import MySQL
import MySQLdb.cursors

mysql = MySQL()

class loginForm(FlaskForm):
    username = StringField('Username', validators=[(DataRequired())])    
    password = PasswordField('Password', validators=[(DataRequired())])
    recaptcha = RecaptchaField()

class verifyForm2(FlaskForm):
    otpinput = StringField('OTP',validators=[(DataRequired())])
