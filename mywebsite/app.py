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

@app.route("/")
def hello():
    return "Hello, Joe!"

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("Username and password cannot be empty.")
            return redirect(url_for("register"))
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_pw)
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
        <div class="card p-4">
            <h4>This is your dashboard. 🎉</h4>
            <p class="mb-0">Congrats on building a secure, styled Python web app!</p>
        </div>
    </body>
    </html>
    """, username=current_user.username)
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
