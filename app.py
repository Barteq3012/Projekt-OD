from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from argon2 import PasswordHasher
from email.message import EmailMessage
from email_validator import validate_email, EmailNotValidError
import flask
import re
import math
import datetime
import smtplib
import random
import string
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import Padding

min_password_length = 12
max_password_length = 80
min_username_length = 6
max_username_length = 20
min_email_length = 3
max_email_length = 320
min_description_length = 3
max_description_length = 100
enthropy_threshold = 3.5
failed_login_seconds = 1800
login_delay = 1

initialization_vector = b'\xfc\\\x7f\xa3\xc9`\x05\x87\x898zlK\x06\xc8\x92'
aes_password = "thisissupersecretpassword"
aes_key = PBKDF2(aes_password.encode(), b"salt", dkLen=32)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\barte\\Documents\\Projekt_Ochrona_Danych\\Projekt-OD\\database.db'

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
                    hash_len=32, salt_len=16, encoding="utf-8")  # argon2id


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(max_username_length),
                         unique=True, nullable=False)
    email = db.Column(db.String(max_email_length), unique=True, nullable=False)
    password = db.Column(db.String(max_password_length), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)
    login_errors = db.Column(db.Integer, default=0, nullable=False)
    failed_login_date = db.Column(db.DateTime, nullable=True)


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(max_description_length), nullable=False)
    password = db.Column(db.String(max_password_length), nullable=False)
    public = db.Column(db.Boolean, default=False, nullable=False)
    userid = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[
                           InputRequired(), Length(min=min_username_length, max=max_username_length)])
    password = PasswordField('password', validators=[Length(
        min=min_password_length, max=max_password_length)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(
        message='Invalid email'), Length(min=min_email_length, max=max_email_length)])
    username = StringField('username', validators=[
                           InputRequired(), Length(min=min_username_length, max=max_username_length)])
    password = PasswordField('password', validators=[
                             InputRequired(), Length(min=min_password_length, max=max_password_length)])


class PasswordForm(FlaskForm):
    description = StringField('description', validators=[
        InputRequired(), Length(min=3, max=100)])
    password = PasswordField('password', validators=[
                             InputRequired(), Length(min=min_password_length, max=max_password_length)])
    public = BooleanField('public')


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('current password', validators=[
                                     InputRequired(), Length(min=min_password_length, max=max_password_length)])
    new_password = PasswordField('new password', validators=[
                                 InputRequired(), Length(min=min_password_length, max=max_password_length)])
    confirm_password = PasswordField('confirm password', validators=[
                                     InputRequired(), Length(min=min_password_length, max=max_password_length)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if flask.request.method == "GET":
        return render_template('login.html', form=form)

    user = User.query.filter_by(username=form.username.data).first()

    if (flask.request.form.get('email') == "email") and user:
        email = user.email
        username = user.username
        password = random_password(16)
        user.password = ph.hash(password)
        db.session.commit()
        s = smtplib.SMTP(host='smtp.gmail.com', port=587)
        s.starttls()
        s.login('przypomnienie.hasla2@gmail.com',
                'OchronaDanych1234!')  # haslo do env
        msg = EmailMessage()
        msg.set_content('Witaj ' + username +
                        ' twoje nowe hasło to: ' + password)
        msg['Subject'] = 'Przypomnienie hasła'
        msg['From'] = 'Ochrona Danych'
        msg['To'] = f'{email}'
        s.send_message(msg)
        s.quit()
        flash("Message has been sended!")
        return redirect(url_for('login'))

    if form.validate_on_submit() and user:
        time.sleep(login_delay)
        # wstępna walidacja danych
        if verify_username(form.username.data) == 1:
            flash("Wrong username or password!")
            return redirect(url_for('login'))

        if verify_password(form.password.data, False) == 1:
            flash("Wrong username or password!")
            return redirect(url_for('login'))

        waiting_time = verify_date(user.failed_login_date)
        if waiting_time > 0:
            min = int(waiting_time / 60)
            sec = waiting_time % 60
            flash("You have exceeded the maximum number of tries(3)!")
            flash("You have to wait: " + str(min) + " min " + str(sec) + " s")
            return redirect(url_for('login'))
        try:
            if ph.verify(user.password, form.password.data):
                login_user(user, remember=form.remember.data)  # create cookie
                return redirect(url_for('dashboard'))
        except:
            flash("Wrong username or password!")
            user.login_errors += 1
            if user.login_errors >= 3:
                user.failed_login_date = datetime.datetime.now()
                user.login_errors = 0
            db.session.commit()
            return redirect(url_for('login'))

    flash("Wrong username or password!")
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if flask.request.method == "GET":
        return render_template('signup.html', form=form)
    username = form.username.data
    email = form.email.data
    password = form.password.data
    verify_ue = verify_username_and_email(username, email)
    verify_p = verify_password(password, True)
    if form.validate_on_submit() and (verify_ue == 0) and (verify_p == 0):
        hashed_password = ph.hash(password)
        new_user = User(username=username,
                        email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("New user has been created!", "info")
        return redirect(url_for('signup'))
    if verify_ue == 1:
        flash("User with this username already exists!", "error")
    if verify_ue == 2:
        flash("There is an account assigned to this email!", "error")
    if verify_ue == 3:
        flash("Invalid username! It can contain only letters and numbers.", "error")
    if verify_ue == 4:
        flash("Invalid email!", "error")

    if verify_p != 0:
        flash("Your password is too weak!", "error")
    if verify_p == 1:
        flash("Use at least one: uppercase and lowercase letter, digit and special sign from: @$!%*#?&", "error")
    if verify_p == 2:
        flash("Try to use more diffrent signs to increase entrophy.", "error")

    flash("Account creation failed!", "error")
    return redirect(url_for('signup'))


def verify_username_and_email(username, email):
    user_un = User.query.filter_by(username=username).first()
    user_e = User.query.filter_by(email=email).first()
    if user_un:
        return 1
    if user_e:
        return 2
    if verify_username(username) == 1:
        return 3
    if verify_email(email) == 1:
        return 4
    return 0


def verify_password(password, check_entropy):
    regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{12,80}$"
    match = re.compile(regex)
    res = re.search(match, password)
    if not res:
        return 1
    if check_entropy == True:
        if entropy(password) < enthropy_threshold:
            return 2
    return 0


def verify_description(description):
    regex = "^((?=.*[a-z])|(?=.*[A-Z]))[A-Za-z\d\s]{3,100}$"
    match = re.compile(regex)
    res = re.search(match, description)
    if not res:
        return 1
    return 0


def verify_username(username):
    regex = "^((?=.*[a-z])|(?=.*[A-Z]))[A-Za-z\d]{6,20}$"
    match = re.compile(regex)
    res = re.search(match, username)
    if not res:
        return 1
    return 0

# to przepuszcza znaki typu "*", do gmail są dozwolone tylko: [a-z][0-9]\.{6,}


def verify_email(email):
    try:
        validate_email(email)
    except EmailNotValidError:
        return 1
    return 0


def verify_date(date):
    if(date is None):
        return -1
    seconds = (datetime.datetime.now() - date).seconds
    if seconds > failed_login_seconds:
        return -1
    return failed_login_seconds - seconds


def entropy(password):
    stat = {}
    ent = 0
    for znak in password:
        if znak in stat:
            stat[znak] += 1
        else:
            stat[znak] = 1

    n = 0  # liczba znaków

    for znak in stat:
        n = n + stat[znak]

    for znak in stat:
        p = stat[znak] / n
        ent += -(p * math.log2(p))

    return ent


def random_password(length):
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    num = string.digits
    symbols = '@$!%*#?&'
    all = lower + upper + num + symbols
    tmp = random.sample(all, length)
    password = "".join(tmp)
    entropy(password)
    return(password)



@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = PasswordForm()

    if form.validate_on_submit():
        if verify_description(form.description.data) == 1:
            flash("Invalid description!", "error")
            return redirect(url_for('dashboard'))

        # tu już bez sprawdzania entropii
        if verify_password(form.password.data, False) == 1:
            flash("Invalid password! Use at least one: uppercase and lowercase letter, digit and special sign from: @$!%*#?&", "error")
            return redirect(url_for('dashboard'))

        password = form.password.data
        password = Padding.appendPadding(password, blocksize=Padding.AES_blocksize, mode='CMS')  # Cryptographic Message Syntax
        encrypted_password = encrypt(password.encode())  # szyfrownie symetryczne
        new_passwd = Password(description=form.description.data,
                              password=encrypted_password, public=form.public.data, userid=current_user.id)
        db.session.add(new_passwd)
        db.session.commit()
        flash("Password has been added!", "info")
        return redirect(url_for('dashboard'))

    password_obj_array = db.session.query(Password).all()
    password_array = []
    for item in password_obj_array:
        #item2 = Padding.appendPadding(item.password, blocksize=Padding.AES_blocksize, mode='CMS')
        decrypted = decrypt(item.password)
        passwd = Padding.removePadding(decrypted.decode(), mode='CMS')
        print(passwd)
        password_array.append(passwd)

    #password_array = list(map(decrypt, password_array))
    return render_template('dashboard.html', form=form, name=current_user.username, password_array=password_array, password_obj_array=password_obj_array, zip=zip)


def encrypt(plaintext):
    aes = AES.new(aes_key, AES.MODE_CBC, initialization_vector)
    return(aes.encrypt(plaintext))


def decrypt(ciphertext):
    aes = AES.new(aes_key, AES.MODE_CBC, initialization_vector)
    return(aes.decrypt(ciphertext))


@app.route('/passwd_change', methods=['GET', 'POST'])
@login_required
def passwd_change():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        current = form.current_password.data
        new = form.new_password.data
        confirm = form.confirm_password.data
        try:
            if ph.verify(current_user.password, current):
                if new != confirm:
                    flash("Passwords are not the same!", "error")
                    return redirect(url_for('passwd_change'))
                verify_p = verify_password(new, True)
                if verify_p != 0:
                    flash("Your new password is too weak!", "error")
                if verify_p == 1:
                    flash(
                        "Use at least one: uppercase and lowercase letter, digit and special sign from: @$!%*#?&", "error")
                    return redirect(url_for('passwd_change'))
                if verify_p == 2:
                    flash(
                        "Try to use more diffrent signs to increase entrophy.", "error")
                    return redirect(url_for('passwd_change'))
                user = User.query.filter_by(
                    username=current_user.username).first()
                user.password = ph.hash(new)
                db.session.commit()
                flash("Password has been changed!", "info")
                return redirect(url_for('passwd_change'))
        except:
            flash("Invalid current password!", "error")
            return redirect(url_for('passwd_change'))

    return render_template('passwd_change.html', form=form, name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
