from flask_wtf import FlaskForm
from wtforms import SubmitField

class unlockForm(FlaskForm):
    unlock = SubmitField('Unlock Account')