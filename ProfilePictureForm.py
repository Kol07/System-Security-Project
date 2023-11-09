from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired, DataRequired
from wtforms import SubmitField, validators, ValidationError

import os
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask import request
from datetime import datetime
mysql = MySQL()
class ProfilePictureForm(FlaskForm):
    profile_picture = FileField("Profile Picture", validators=[DataRequired(),FileAllowed(['jpg', 'png', 'jpeg'])])
    def validate_profile_picture(FlaskForm,field):
        # if file siz more than 1MB
        if len(field.data.read()) >  1024 * 1024:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            ip_address = request.remote_addr
            useragent = request.user_agent.string
            log_datetime = datetime.now()
            log_category = "Edit Profile"
            log_activity = "Invalid File Type / File too large"
            log_status = "Unsuccessful"

            cursor.execute(
                'INSERT INTO systemlog (log_datetime, log_category, log_activity, log_status,  log_ip, log_useragent) VALUES (%s, %s, %s, %s, %s, %s)',
                (log_datetime, log_category, log_activity, log_status,  ip_address, useragent)
            )
            mysql.connection.commit()
            cursor.close()
            raise ValidationError("File size too large")
        field.data.seek(0)
            