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

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already taken. Choose another.")
            return redirect(url_for("register"))

        # Generate a unique referral code for each user
        base_code = f"REF{username}"
        code = base_code
        counter = 1
        while User.query.filter_by(referral_code=code).first():
            code = f"{base_code}{counter}"
            counter += 1
        new_user_code = code

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

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    sponsor = User.query.get(current_user.sponsor_id) if current_user.sponsor_id else None
    rewards_table = ""
    invoice_amount = None

    # Reward calculation for downline purchases
    if request.method == "POST":
        try:
            invoice_amount = float(request.form.get("invoice_amount", 0))
            downline_level = int(request.form.get("downline_level", 2))
            if not (0 < invoice_amount <= 2500):
                flash("Amount must be between 0 and 2500.")
            elif downline_level not in [2, 3, 4, 5]:
                flash("Invalid downline level.")
            else:
                if downline_level in [2, 3, 4]:
                    rate = 0.0025
                    cap = 6.25
                elif downline_level == 5:
                    rate = 0.02
                    cap = 50
                reward = min(invoice_amount * rate, cap)
                rewards_table += f"<h5 class='mt-4 mb-2'>If your level {downline_level} downline makes a purchase of ${invoice_amount:,.2f}:</h5>"
                rewards_table += f"<div class='alert alert-success'>You earn <strong>${reward:.2f}</strong> as cashback.</div>"
        except Exception:
            flash("Please enter a valid number for the invoice amount.")

    # Downline lookup for Levels 2-5
    level2 = User.query.filter_by(sponsor_id=current_user.id).all()
    level3 = []
    level4 = []
    level5 = []
    for u2 in level2:
        l3s = User.query.filter_by(sponsor_id=u2.id).all()
        level3.extend(l3s)
        for u3 in l3s:
            l4s = User.query.filter_by(sponsor_id=u3.id).all()
            level4.extend(l4s)
            for u4 in l4s:
                l5s = User.query.filter_by(sponsor_id=u4.id).all()
                level5.extend(l5s)

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
        <div class="card p-4 mb-4">
            <h4>Estimate Your Reward From Downline Purchases</h4>
            <form method="post" class="row g-3 mb-3">
                <div class="col-auto">
                    <input name="invoice_amount" class="form-control" type="number" step="0.01" min="0" max="2500"
                        placeholder="Purchase Amount (e.g. 500)" required>
                </div>
                <div class="col-auto">
                    <select name="downline_level" class="form-select" required>
                        <option value="2">Level 2 (your direct referral)</option>
                        <option value="3">Level 3 (your referral's referral)</option>
                        <option value="4">Level 4 (third downline)</option>
                        <option value="5">Level 5 (fourth downline)</option>
                    </select>
                </div>
                <div class="col-auto">
                    <button class="btn btn-primary" type="submit">Calculate My Reward</button>
                </div>
            </form>
            {{ rewards_table | safe }}
        </div>
        <div class="card p-4 mb-4">
            <h4>My Downline</h4>
            <div>
                <strong>Level 2 (direct referrals):</strong>
                {% if level2 %}
                    <ul class="mb-2">{% for user in level2 %}<li>{{ user.username }} ({{ user.referral_code }})</li>{% endfor %}</ul>
                {% else %}
                    <span>None</span>
                {% endif %}
            </div>
            <div>
                <strong>Level 3:</strong>
                {% if level3 %}
                    <ul class="mb-2">{% for user in level3 %}<li>{{ user.username }} ({{ user.referral_code }})</li>{% endfor %}</ul>
                {% else %}
                    <span>None</span>
                {% endif %}
            </div>
            <div>
                <strong>Level 4:</strong>
                {% if level4 %}
                    <ul class="mb-2">{% for user in level4 %}<li>{{ user.username }} ({{ user.referral_code }})</li>{% endfor %}</ul>
                {% else %}
                    <span>None</span>
                {% endif %}
            </div>
            <div>
                <strong>Level 5:</strong>
                {% if level5 %}
                    <ul class="mb-2">{% for user in level5 %}<li>{{ user.username }} ({{ user.referral_code }})</li>{% endfor %}</ul>
                {% else %}
                    <span>None</span>
                {% endif %}
            </div>
        </div>
        <div class="card p-4">
            <h4>This is your dashboard. 🎉</h4>
            <p class="mb-0">Congrats on building a secure, styled Python web app!</p>
        </div>
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <div class="alert alert-warning mt-3">
              {% for message in messages %}
                {{ message }}<br>
              {% endfor %}
            </div>
          {% endif %}
        {% endwith %}
    </body>
    </html>
    """, username=current_user.username,
         referral_code=current_user.referral_code,
         sponsor=sponsor.username if sponsor else None,
         rewards_table=rewards_table,
         level2=level2, level3=level3, level4=level4, level5=level5)
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
