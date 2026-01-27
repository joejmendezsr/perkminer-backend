from flask import Flask, request, redirect, url_for, render_template_string, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from twilio.rest import Client
import os, re, random, string

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', "sqlite:///site.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email config for Flask-Mail (Gmail example, works on Render)
app.config['MAIL_SERVER']   = os.environ.get('MAIL_SERVER',   'smtp.gmail.com')
app.config['MAIL_PORT']     = int(os.environ.get('MAIL_PORT', 465))
app.config['MAIL_USE_SSL']  = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)

# Twilio config (from Render env vars)
twilio_sid   = os.environ.get('TWILIO_SID')
twilio_token = os.environ.get('TWILIO_TOKEN')
twilio_from  = os.environ.get('TWILIO_FROM')
twilio_client = Client(twilio_sid, twilio_token) if twilio_sid and twilio_token else None

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    referral_code = db.Column(db.String(32), unique=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    email_confirmed = db.Column(db.Boolean, default=False)
    phone_confirmed = db.Column(db.Boolean, default=False)
    phone_code = db.Column(db.String(8))

EMAIL_REGEX = r'^[\w\.-]+@[\w\.-]+\.\w{2,}$'
PHONE_REGEX = r'^\+?\d{10,15}$'

def valid_email(email):
    return re.match(EMAIL_REGEX, email or "")

def valid_phone(phone):
    return re.match(PHONE_REGEX, phone or "")

def random_phone_code():
    return ''.join(random.choices(string.digits, k=6))

def random_referral_code(email):
    base_code = "REF" + (email.split("@")[0].replace(".", "")[:12])
    code = base_code
    counter = 1
    while User.query.filter_by(referral_code=code).first():
        code = f"{base_code}{counter}"
        counter += 1
    return code

def send_email(to, subject, html_body):
    msg = Message(subject, recipients=[to], html=html_body, sender=app.config['MAIL_USERNAME'])
    try:
        mail.send(msg)
    except Exception as e:
        print("EMAIL SEND ERROR:", e)

def send_sms(to, body):
    try:
        if twilio_client and twilio_from:
            twilio_client.messages.create(
                body=body,
                from_=twilio_from,
                to=to
            )
        else:
            print("[TWILIO WARNING] Twilio not configured. Skipping SMS send.")
    except Exception as e:
        print("SMS SEND ERROR:", e)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password")
        referral_code = request.form.get("referral_code")
        if not (email and password and phone):
            flash("All fields are required.")
            return redirect(url_for("register"))
        if not valid_email(email):
            flash("Invalid email format.")
            return redirect(url_for("register"))
        if not valid_phone(phone):
            flash("Invalid phone number. Use +1234567890 or 10-15 digits.")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Email already registered.")
            return redirect(url_for("register"))
        if User.query.filter_by(phone=phone).first():
            flash("Phone number already registered.")
            return redirect(url_for("register"))
        sponsor_id = None
        if referral_code:
            sponsor = User.query.filter_by(referral_code=referral_code).first()
            if sponsor:
                sponsor_id = sponsor.id
            else:
                flash("Invalid referral code.")
                return redirect(url_for("register"))
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user_ref_code = random_referral_code(email)
        phone_code = random_phone_code()
        new_user = User(
            email=email,
            password=hashed_pw,
            phone=phone,
            referral_code=user_ref_code,
            sponsor_id=sponsor_id,
            email_confirmed=False,
            phone_confirmed=False,
            phone_code=phone_code,
        )
        db.session.add(new_user)
        db.session.commit()
        # Send confirmation email with link
        activate_url = url_for("activate", user_id=new_user.id, _external=True)
        html_body = f"""<p>Welcome to PerkMiner!</p>
            <p>Click <a href="{activate_url}">here</a> to confirm your email.</p>"""
        send_email(new_user.email, "Activate your PerkMiner account", html_body)
        # Send phone code SMS
        send_sms(new_user.phone, f"Your PerkMiner phone confirmation code is: {phone_code}")
        flash("Check your email and SMS for confirmation instructions.")
        return redirect(url_for("login"))
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
        <title>Register</title>
    </head>
    <body class="container py-5">
        <h2 class="mb-4">Register</h2>
        <form method="post" class="mb-3">
            <div class="mb-3">
                <input name="email" required class="form-control" placeholder="Email (this is your username)">
            </div>
            <div class="mb-3">
                <input name="phone" required class="form-control" placeholder="Phone (with country code)">
            </div>
            <div class="mb-3">
                <input name="password" required type="password" class="form-control" placeholder="Password">
            </div>
            <div class="mb-3">
                <input name="referral_code" class="form-control" placeholder="Referral Code (optional)">
            </div>
            <button type="submit" class="btn btn-success">Register</button>
        </form>
        <a href="{{ url_for('login') }}">Already have an account? Login</a>
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
    """)

@app.route("/activate/<int:user_id>")
def activate(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("Unknown account.")
        return redirect(url_for("login"))
    user.email_confirmed = True
    db.session.commit()
    flash("Email confirmed. Please confirm your phone.")
    session["user_for_phone"] = user.id
    return redirect(url_for("confirm_phone"))

@app.route("/confirm_phone", methods=["GET", "POST"])
def confirm_phone():
    user_id = session.get("user_for_phone")
    user = User.query.get(user_id) if user_id else None
    if not user:
        flash("Session expired or unknown account.")
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form.get("code", "")
        if code == user.phone_code:
            user.phone_confirmed = True
            user.phone_code = None
            db.session.commit()
            flash("Phone confirmed. You can now log in.")
            session.pop("user_for_phone", None)
            return redirect(url_for("login"))
        else:
            flash("Invalid code. Please try again.")
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
        <title>Confirm Phone</title>
    </head>
    <body class="container py-5">
        <h2>Confirm Your Phone</h2>
        <form method="post" class="mb-3">
            <div class="mb-3">
                <input name="code" class="form-control" placeholder="Enter the code sent to your phone" required>
            </div>
            <button type="submit" class="btn btn-primary">Confirm</button>
        </form>
        <div class="alert alert-info mt-2">
            You'll receive the code via SMS.
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
    """)

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if not user.email_confirmed:
                message = "Please confirm your email first (check your inbox)."
            elif not user.phone_confirmed:
                message = "Please confirm your phone."
            else:
                login_user(user)
                return redirect(url_for("dashboard"))
        else:
            message = "Login failed. Check email and password."
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
    <title>Login</title>
    </head>
    <body class="container py-5">
        <h2 class="mb-4">Login</h2>
        <form method="post" class="mb-3">
            <div class="mb-3">
                <input name="email" class="form-control" placeholder="Email (username)" required>
            </div>
            <div class="mb-3">
                <input name="password" type="password" class="form-control" placeholder="Password" required>
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
        <div style='color:red;'>{{message}}</div>
        <a href="{{ url_for('register') }}">Register here</a>
    </body>
    </html>
    """, message=message)

@app.route("/")
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
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

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    if not (current_user.email_confirmed and current_user.phone_confirmed):
        flash("You must confirm your email and phone to access the dashboard.")
        return redirect(url_for("login"))
    sponsor = User.query.get(current_user.sponsor_id) if current_user.sponsor_id else None
    rewards_table = ""
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
    level2 = User.query.filter_by(sponsor_id=current_user.id).all()
    level3, level4, level5 = [], [], []
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
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
        <title>Dashboard</title>
    </head>
    <body class="container py-5">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>Welcome, {{ email }}!</h2>
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
                    <ul class="mb-2">{% for user in level2 %}<li>{{ user.email }} ({{ user.referral_code }})</li>{% endfor %}</ul>
                {% else %}
                    <span>None</span>
                {% endif %}
            </div>
            <div>
                <strong>Level 3:</strong>
                {% if level3 %}
                    <ul class="mb-2">{% for user in level3 %}<li>{{ user.email }} ({{ user.referral_code }})</li>{% endfor %}</ul>
                {% else %}
                    <span>None</span>
                {% endif %}
            </div>
            <div>
                <strong>Level 4:</strong>
                {% if level4 %}
                    <ul class="mb-2">{% for user in level4 %}<li>{{ user.email }} ({{ user.referral_code }})</li>{% endfor %}</ul>
                {% else %}
                    <span>None</span>
                {% endif %}
            </div>
            <div>
                <strong>Level 5:</strong>
                {% if level5 %}
                    <ul class="mb-2">{% for user in level5 %}<li>{{ user.email }} ({{ user.referral_code }})</li>{% endfor %}</ul>
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
    """, email=current_user.email,
         referral_code=current_user.referral_code,
         sponsor=sponsor.email if sponsor else None,
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
