from flask import Flask, render_template, redirect, request, url_for, flash
import random
import string
import hashlib
import os
import zxcvbn
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:jacob@localhost:3306/database'
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['ENCRYPTION_KEY'] = 'ikfkZzSKk0qh3ypyF2ByhEd8RvZa6oDRynkAuCZuelQ='

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def encrypt_text(plain_text, encryption_key):
    cipher_suite = Fernet(encryption_key)
    cipher_text = cipher_suite.encrypt(plain_text.encode())
    return cipher_text


def decrypt_text(cipher_text, key):
    cipher_text = bytes(cipher_text, 'utf-8')  # Add this line to convert cipher_text to bytes
    cipher_suite = Fernet(key) #Fernet is a symmetric encryption method
    plain_text = cipher_suite.decrypt(cipher_text).decode()
    return plain_text


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/generate_password', methods=['GET', 'POST'])
def generate_password():
    if request.method == 'POST':
        password_length = int(request.form['password_length'])
        include_numbers = 'numbers' in request.form
        include_symbols = 'symbols' in request.form
        characters = string.ascii_letters
        if include_numbers:
            characters += string.digits
        if include_symbols:
            characters += string.punctuation
        password = ''.join(random.choice(characters) for i in range(password_length))
        return render_template('generate_password.html', password=password)
    return render_template('generate_password.html')

@app.route('/test_password', methods=['GET', 'POST'])
def test_password():
    if request.method == 'POST':
        password = request.form['password']
        password_strength = zxcvbn.zxcvbn(password)
        #Estimated time to crack a password using an offline attack with a slow hashing algorithm 
        #Specifically, a hash function that can perform 1e4 iterations per second, or 10,000 iterations per second
        time_to_crack = password_strength['crack_times_display']['offline_slow_hashing_1e4_per_second'] 
        suggestions = password_strength['feedback']['suggestions']
        return render_template('test_password.html', time_to_crack=time_to_crack, password_strength=password_strength, suggestions=suggestions)
    return render_template('test_password.html')

########################## LOG-IN AND REGISTER FOR PASSWORD MANAGER ##########################

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Add autoincrement=True
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class StrongPassword:
    def __init__(self, message=None):
        if not message:
            message = "Password must be strong: min. 8 characters, include uppercase, lowercase, digits, and symbols."
        self.message = message

    def __call__(self, form, field):
        password = field.data
        password_strength = zxcvbn.zxcvbn(password)
        score = password_strength["score"]

        if score < 3:
            raise ValidationError(self.message)

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20), StrongPassword()], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[
                             InputRequired(), EqualTo('password', message='Passwords must match.')], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
        # Display error message if username or password is incorrect
        flash('Wrong username/password', 'error')
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    stored_passwords = StoredPassword.query.filter_by(user_id=current_user.id).all()
    decrypted_passwords = []
    for sp in stored_passwords:
        decrypted_passwords.append({
            'id': sp.id,
            'website': sp.get_website(),
            'username': sp.get_username(),
            'password': sp.get_password(),
        })
    return render_template('dashboard.html', stored_passwords=decrypted_passwords)




@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

########################## LOG-IN AND REGISTER FOR PASSWORD MANAGER ##########################

########################## PASSWORD MANAGER ##########################
def create_stored_passwords_db():
    with app.app_context():
        db.create_all()

class StoredPassword(db.Model):
    __tablename__ = 'stored_password'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website = db.Column(db.String(100))
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))

    def __init__(self, user_id, website, username, password):
        self.user_id = user_id
        self.website = encrypt_text(website, app.config['ENCRYPTION_KEY'])
        self.username = encrypt_text(username, app.config['ENCRYPTION_KEY'])
        self.password = encrypt_text(password, app.config['ENCRYPTION_KEY'])

    def get_website(self):
        return decrypt_text(self.website, app.config['ENCRYPTION_KEY'])

    def get_username(self):
        return decrypt_text(self.username, app.config['ENCRYPTION_KEY'])

    def get_password(self):
        return decrypt_text(self.password, app.config['ENCRYPTION_KEY'])



class AddPasswordForm(FlaskForm):
    website = StringField('Website', validators=[InputRequired(), Length(max=100)])
    username = StringField('Username', validators=[InputRequired(), Length(max=100)])
    password = StringField('Password', validators=[InputRequired(), Length(max=200)])
    submit = SubmitField('Add Password')


class EditPasswordForm(FlaskForm):
    website = StringField('Website', validators=[InputRequired(), Length(max=100)])
    username = StringField('Username', validators=[InputRequired(), Length(max=100)])
    password = StringField('Password', validators=[InputRequired(), Length(max=200)])
    submit = SubmitField('Save Changes')


@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    form = AddPasswordForm()
    if form.validate_on_submit():
        new_password = StoredPassword(user_id=current_user.id,
                                      website=form.website.data,
                                      username=form.username.data,
                                      password=form.password.data)
        db.session.add(new_password)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('add_password.html', form=form)


@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
@login_required
def edit_password(password_id):
    stored_password = StoredPassword.query.get_or_404(password_id)
    form = EditPasswordForm()
    if form.validate_on_submit():
        stored_password.website = form.website.data
        stored_password.username = form.username.data
        stored_password.password = form.password.data
        db.session.commit()
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.website.data = stored_password.website
        form.username.data = stored_password.username
        form.password.data = stored_password.password
    return render_template('edit_password.html', form=form)


@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    stored_password = StoredPassword.query.get_or_404(password_id)
    db.session.delete(stored_password)
    db.session.commit()
    return redirect(url_for('dashboard'))
########################## PASSWORD MANAGER ##########################





if __name__ == '__main__':
    app.run(debug=True)





