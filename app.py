#/usr/bin/python3
""" app module """
from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, validators
from wtforms.validators import InputRequired, Email, Length, ValidationError, EqualTo, Regexp
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from os import getenv


app = Flask(__name__)
#app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql:///mysql+mysqldb://mahlet:mypass@localhost/gebeyahub_db'
#app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///database.db'
app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql+mysqldb://{}:{}@{}/{}'.format(
        getenv('ONLINE_STORE_MYSQL_USER'),
        getenv('ONLINE_STORE_MYSQL_PWD'),
        getenv('ONLINE_STORE_MYSQL_HOST'),
        getenv('ONLINE_STORE_MYSQL_DB')
        )

app.config["SECRET_KEY"] = "thisidsupposedtobeasecretkey"
app.config['JWT_SECRET_KEY'] = 'thisissupposedtobeajwtsecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(80), nullable=True)
    lastname = db.Column(db.String(80), nullable=True)
    email =  db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    email = StringField("email", validators=[InputRequired(), Email()], render_kw={"placeholder": "Email"})
    password = PasswordField("password", validators=[InputRequired(), Length(min=8)], render_kw={"placeholder": "Password"})
    remember = BooleanField("Remember me")
    submit = SubmitField("Login")

    def validate_email(self, email):
        user_email = User.query.filter_by(
                email=email.data).first()
        if not user_email:
            raise ValidationError(
                    "Don't have an account; Register instead")

    def validate_password(self, password, email):
        user_email = User.query.filter_by(
                email=email.data).first()
        if user_email:
            #if not bcrypt.check_password_hash(password = user_email.password, password.data):
            hashed_entered_password = bcrypt.hashpw(password.data.encode('utf-8'), user_email.password)
            #if not bcrypt.check_password_hash(user_email.password, password):
            if not hashed_entered_password == user_email.password:
                raise ValidationError(
                        "Unauthorized access")


class RegisterForm(FlaskForm):
    firstname = StringField("firstname", validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "First Name"})
    lastname = StringField("lastname", validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Last Name"})
    email = StringField("email", validators=[InputRequired(), Email()], render_kw={"placeholder": "Email"})
    username = StringField("username", validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField(
            "password",
            validators=[
                InputRequired(),
                Length(min=8, max=12),
                Regexp(
                    regex="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$",
                    message="Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character."
                    )
                ],
            render_kw={"placeholder": "Password"})
    confirm_password = PasswordField("confirm_password", validators=[InputRequired(), Length(min=8, max=12), EqualTo('password')], render_kw={"placeholder": "Confirm Password"})
    remember = BooleanField("Remember me")
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_username = User.query.filter_by(
                username=username.data).first()
        if existing_username:
            raise ValidationError(
                    "Username already Exists")

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("dashboard", form=form))
    return render_template("login.html", form=form)

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(
                firstname=form.firstname.data,
                lastname=form.lastname.data,
                email=form.email.data,
                username=form.username.data,
                password=hashed_password
            )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("register.html", form=form)

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    form = LoginForm()

    return render_template("dashboard.html", form=form)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port='5001', debug=True)
