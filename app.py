from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
#from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from argon2 import PasswordHasher
import flask

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
warning = None


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    public = db.Column(db.Boolean, default=False, nullable=False)
    userid = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[
                           InputRequired(), Length(min=6, max=20)])
    password = PasswordField('password', validators=[
                             InputRequired(), Length(min=12, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(
        message='Invalid email'), Length(min=3, max=50)])
    username = StringField('username', validators=[
                           InputRequired(), Length(min=6, max=20)])
    password = PasswordField('password', validators=[
                             InputRequired(), Length(min=12, max=80)])


class PasswordForm(FlaskForm):
    description = StringField('description', validators=[
        InputRequired(), Length(min=3, max=100)])
    password = PasswordField('password', validators=[
                             InputRequired(), Length(min=12, max=80)])
    public = BooleanField('public')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if flask.request.method == "GET":
        return render_template('login.html', form=form)

    user = User.query.filter_by(username=form.username.data).first()
    if form.validate_on_submit() and user:
        try:
            if ph.verify(user.password, form.password.data):
                login_user(user, remember=form.remember.data)  # create cookie
                return redirect(url_for('dashboard'))
        except:
            flash("Wrong username or password!")
            return redirect(url_for('login'))

    flash("Wrong username or password!")
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if flask.request.method == "GET":
        return render_template('signup.html', form=form)
    if form.validate_on_submit():
        hashed_password = ph.hash(form.password.data)
        new_user = User(username=form.username.data,
                        email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("New user has been created!", "info")
        return redirect(url_for('signup'))

    flash("Account creation failed!", "error")
    return redirect(url_for('signup'))



@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = PasswordForm()
    info = ""
    if form.validate_on_submit():

        encrypted_password = form.password.data  # szyfrownie symetryczne
        new_passwd = Password(description=form.description.data,
                              password=encrypted_password, public=form.public.data, userid=current_user.id)
        db.session.add(new_passwd)
        db.session.commit()
        info = "Success"
        return redirect(url_for('dashboard'))

    password_array = db.session.query(Password).all()

    return render_template('dashboard.html', form=form, name=current_user.username, info=info, password_array=password_array)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
