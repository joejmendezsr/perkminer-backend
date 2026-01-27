from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, request, redirect, url_for, render_template_string, flash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace-this-with-a-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    referral_code = db.Column(db.String(20), unique=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
@app.route("/")
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet"
         href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
        <title>PerkMiner Homepage</title>
    </head>
    <body class="container py-5">
        <nav class="navbar navbar-expand navbar-light bg-light mb-4">
            <a class="navbar-brand" href="/">PerkMiner</a>
            <div class="navbar-nav">
                <a class="nav-link" href="{{ url_for('login') }}">Login</a>
                <a class="nav-link" href="{{ url_for('register') }}">Register</a>
            </div>
        </nav>
        <div class="jumbotron">
            <h1 class="display-4">Welcome to PerkMiner!</h1>
            <p class="lead">Your secure, custom site is now live.</p>
            <hr class="my-4">
            <p>Build more features, connect your domain, and make it yours.</p>
        </div>
    </body>
    </html>
    """)
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        referral_code = request.form.get("referral_code")
        if not username or not password:
            flash("Username and password cannot be empty.")
            return redirect(url_for("register"))
        
        # Generate a code for the new user (simple: "REF" + username)
        new_user_code = f"REF{username}"
        sponsor_id = None

        # If user enters a referral code, find a sponsor
        if referral_code:
            sponsor = User.query.filter_by(referral_code=referral_code).first()
            if sponsor:
                sponsor_id = sponsor.id
            else:
                flash("Invalid referral code.")
                return redirect(url_for("register"))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            username=username,
            password=hashed_pw,
            referral_code=new_user_code,
            sponsor_id=sponsor_id
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Account created! You can now log in.")
        return redirect(url_for("login"))
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
        <title>Register</title>
    </head>
    <body class="container py-5">
        <h2 class="mb-4">Register</h2>
        <form method="post" class="mb-3">
            <div class="mb-3">
                <input name="username" class="form-control" placeholder="Username">
            </div>
            <div class="mb-3">
                <input name="password" type="password" class="form-control" placeholder="Password">
            </div>
            <div class="mb-3">
                <input name="referral_code" class="form-control" placeholder="Referral Code (optional)">
            </div>
            <button type="submit" class="btn btn-success">Register</button>
        </form>
        <a href="{{ url_for('login') }}">Already have an account? Login</a>
    </body>
    </html>
    """)

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            message = "Login failed. Check username and password."
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet"
         href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
        <title>Login</title>
    </head>
    <body class="container py-5">
        <h2 class="mb-4">Login</h2>
        <form method="post" class="mb-3">
            <div class="mb-3">
                <input name="username" class="form-control" placeholder="Username">
            </div>
            <div class="mb-3">
                <input name="password" type="password" class="form-control" placeholder="Password">
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
        <div style='color:red;'>{{message}}</div>
        <a href="{{ url_for('register') }}">Register here</a>
    </body>
    </html>
    """, message=message)

@app.route("/dashboard")
@login_required
def dashboard():
    sponsor = User.query.get(current_user.sponsor_id) if current_user.sponsor_id else None
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet"
         href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
        <title>Dashboard</title>
    </head>
    <body class="container py-5">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>Welcome, {{ username }}!</h2>
            <a href="{{ url_for('logout') }}" class="btn btn-outline-danger">Logout</a>
        </div>
        <div class="card p-4 mb-4">
            <h4>Your Referral Code:</h4>
            <code>{{ referral_code }}</code>
        </div>
        {% if sponsor %}
        <div class="card p-4 mb-4">
            <h4>Your Sponsor:</h4>
            <p class="mb-0">{{ sponsor }}</p>
        </div>
        {% endif %}
        <div class="card p-4">
            <h4>This is your dashboard. 🎉</h4>
            <p class="mb-0">Congrats on building a secure, styled Python web app!</p>
        </div>
    </body>
    </html>
    """, username=current_user.username, referral_code=current_user.referral_code, sponsor=sponsor.username if sponsor else None)
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
