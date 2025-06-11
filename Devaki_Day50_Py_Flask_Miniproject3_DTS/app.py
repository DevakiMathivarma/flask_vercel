from flask import Flask, render_template, flash, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms_components import DateTimeLocalField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, InputRequired, Length
from flask_mail import Mail, Message
from datetime import datetime
import os

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key')
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{os.getenv('DB_USER', 'root')}:{os.getenv('DB_PASS', '2798')}@"
    f"{os.getenv('DB_HOST', 'localhost')}/{os.getenv('DB_NAME', 'booking_db')}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASS')

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login = LoginManager(app)
login.login_view = 'login'
mail = Mail(app)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    provider = db.Column(db.String(100), nullable=False)
    appointments = db.relationship('Appointment', backref='service', cascade='all,delete')

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    datetime = db.Column(db.DateTime, nullable=False)
    user = db.relationship('User', backref='appointments')

# Forms
class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Confirm', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already exists!')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ServiceForm(FlaskForm):
    name = StringField('Service Name', validators=[DataRequired()])
    provider = StringField('Provider', validators=[DataRequired()])
    submit = SubmitField('Add Service')

class AppointmentForm(FlaskForm):
    service = SelectField('Service', coerce=int, validators=[DataRequired()])
    datetime = DateTimeLocalField('Date and Time', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    submit = SubmitField('Book')

# User loader
@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Init DB and Seed Data
with app.app_context():
    db.create_all()
    if Service.query.count() == 0:
        s1 = Service(name="Dental Cleaning", provider="Dr. Smith")
        s2 = Service(name="Eye Checkup", provider="Dr. Patel")
        db.session.add_all([s1, s2])
        db.session.commit()

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode()
        user = User(email=form.email.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in!', 'success')
            return redirect(url_for('home'))
        flash('Login failed', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/services', methods=['GET', 'POST'])
@login_required
def services():
    form = ServiceForm()
    if current_user.is_admin and form.validate_on_submit():
        service = Service(name=form.name.data, provider=form.provider.data)
        db.session.add(service)
        db.session.commit()
        flash('Service added!', 'success')
    services = Service.query.all()
    return render_template('services.html', services=services, form=form)

@app.route('/book', methods=['GET', 'POST'])
@login_required
def book():
    form = AppointmentForm()
    form.service.choices = [(s.id, f"{s.name} with {s.provider}") for s in Service.query.all()]

    if not form.service.choices:
        flash("No services available. Please contact admin.", "warning")
        return redirect(url_for('home'))

    if form.validate_on_submit():
        appt = Appointment(user_id=current_user.id, service_id=form.service.data, datetime=form.datetime.data)
        db.session.add(appt)
        db.session.commit()
        flash('Appointment booked!', 'success')

        try:
            msg = Message(
                'Appointment Confirmation',
                sender=app.config['MAIL_USERNAME'],
                recipients=[current_user.email]
            )
            msg.body = f"Your appointment is confirmed for {appt.datetime}."
            mail.send(msg)
        except Exception as e:
            print("Mail send error:", e)

        return redirect(url_for('my_appointments'))

    return render_template('book.html', form=form)

@app.route('/my_appointments')
@login_required
def my_appointments():
    appts = Appointment.query.filter_by(user_id=current_user.id).all()
    return render_template('my_appointments.html', appts=appts)

@app.route('/cancel/<int:id>')
@login_required
def cancel(id):
    appt = Appointment.query.get_or_404(id)
    if appt.user_id != current_user.id:
        flash('Not allowed', 'danger')
        return redirect(url_for('home'))
    
    db.session.delete(appt)
    db.session.commit()
    flash('Appointment canceled.', 'info')
    return redirect(url_for('my_appointments'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
