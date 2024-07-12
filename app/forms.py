from flask_wtf import FlaskForm
from wtforms import DateField, DecimalField, FileField, StringField, PasswordField, SubmitField , IntegerField, RadioField, SelectField
from wtforms.validators import DataRequired, Optional, Email, EqualTo, Length  

class Profile(FlaskForm):
    username = StringField('Full Name' , validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    number = IntegerField('Phone Number', validators=[DataRequired()])
    gender = RadioField('Gender', choices=[('male', 'Male'), ('female', 'Female'), ('prefer_not_to_say', 'Prefer not to say')], validators=[DataRequired()])
    dateofbirth = DateField('Date of Birth', validators=[DataRequired()])
    father = StringField('Father Name', validators=[DataRequired()] )
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    college = StringField('College Name', validators=[DataRequired()])
    
    qualification = SelectField('Last highest qualifiction', choices=[
        ('', 'Select Last Highest Qualifiction'), 
        ('BA', 'Bachelor of Arts'), 
        ('BSc', 'Bachelor of Science'), 
        ('BCom', 'Bachelor of Commerce'),
        ('BE', 'Bachelor of Engineering'),
        ('BTech', 'Bachelor of Technology'),
        ('BBA', 'Bachelor of Business Administration'),
        ('BCA', 'Bachelor of Computer Applications'),
        ('MBBS', 'Bachelor of Medicine, Bachelor of Surgery'),
        ('MA', 'Master of Arts'), 
        ('MSc', 'Master of Science'), 
        ('MCom', 'Master of Commerce'),
        ('ME', 'Master of Engineering'),
        ('MTech', 'Master of Technology'),
        ('MBA', 'Master of Business Administration'),
        ('MCA', 'Master of Computer Applications'),
        ('PhD', 'Doctor of Philosophy')
    ], validators=[DataRequired()])
 
    submit = SubmitField('submit')
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')