from flask import Flask, request, redirect, url_for, render_template, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, DecimalField, SelectField
from wtforms.validators import DataRequired, Email, Length, Optional, NumberRange
import os, re, random, string, time, logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', "sqlite:///site.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER']   = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT']     = int(os.environ.get('MAIL_PORT', 465))
app.config['MAIL_USE_SSL']  = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')

db = SQLAlchemy(app)
with app.app_context():
    db.create_all()
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)
logging.basicConfig(level=logging.INFO)

SESSION_EMAIL_RESEND_KEY = "last_resend_email_time"
MIN_PASSWORD_LENGTH = 8

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    referral_code = db.Column(db.String(32), unique=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    email_confirmed = db.Column(db.Boolean, default=False)
    email_code = db.Column(db.String(16))

class Business(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    business_name = db.Column(db.String(100), unique=True, nullable=False)
    business_email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    referral_code = db.Column(db.String(32), unique=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('business.id'))
    email_confirmed = db.Column(db.Boolean, default=False)
    email_code = db.Column(db.String(16))

EMAIL_REGEX = r'^[\w\.-]+@[\w\.-]+\.\w{2,}$'

def valid_email(email):
    return re.match(EMAIL_REGEX, email or "")

def valid_password(pw):
    return pw and len(pw) >= MIN_PASSWORD_LENGTH

def random_email_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def random_referral_code(email):
    base_code = "REF" + (email.split("@")[0].replace(".", "")[:12])
    code = base_code
    counter = 1
    while User.query.filter_by(referral_code=code).first():
        code = f"{base_code}{counter}"
        counter += 1
    return code

def random_business_code(business_name):
    base_code = "BIZ" + (business_name.replace(" ", "")[:12])
    code = base_code
    counter = 1
    while Business.query.filter_by(referral_code=code).first():
        code = f"{base_code}{counter}"
        counter += 1
    return code

def send_email(to, subject, html_body):
    msg = Message(subject, recipients=[to], html=html_body, sender=app.config['MAIL_USERNAME'])
    try:
        mail.send(msg)
    except Exception as e:
        logging.error("EMAIL SEND ERROR: %s", e)

def send_verification_email(user):
    code = user.email_code
    verify_url = url_for("activate", code=code, _external=True)
    html_body = f"""<p>Click <a href="{verify_url}">here</a> to confirm your email, or use code: <b>{code}</b></p>"""
    send_email(
        user.email,
        "Confirm your PerkMiner email!",
        html_body
    )

def send_business_verification_email(biz):
    code = biz.email_code
    verify_url = url_for("business_activate", code=code, _external=True)
    html_body = f"""<p>Click <a href="{verify_url}">here</a> to verify your business email, or use code: <b>{code}</b></p>"""
    send_email(biz.business_email, "[PerkMiner] Verify your business email!", html_body)

# WTForms classes
class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=MIN_PASSWORD_LENGTH)])
    referral_code = StringField('Referral Code', validators=[Optional()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RewardForm(FlaskForm):
    invoice_amount = DecimalField('Purchase Amount', validators=[DataRequired(), NumberRange(min=0.01, max=2500)], places=2, default=0)
    downline_level = SelectField(
        'Downline Level',
        choices=[('1', 'Level 1 (your purchases)'), ('2', 'Level 2 (direct referral)'), ('3', "Level 3 (referral's referral)"),
                 ('4', "Level 4 (third downline)"), ('5', "Level 5 (fourth downline)")],
        validators=[DataRequired()],
        default='1'
    )
    submit = SubmitField('Calculate My Reward')

class BusinessRegisterForm(FlaskForm):
    business_name = StringField('Business Name', validators=[DataRequired()])
    business_email = StringField('Business Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=MIN_PASSWORD_LENGTH)])
    referral_code = StringField('Referral Code', validators=[Optional()])
    submit = SubmitField('Register')

class BusinessLoginForm(FlaskForm):
    business_email = StringField('Business Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class BusinessRewardForm(FlaskForm):
    invoice_amount = DecimalField('Purchase Amount', validators=[DataRequired(), NumberRange(min=0.01, max=2500)], places=2, default=0)
    downline_level = SelectField(
        'Downline Level',
        choices=[('1', 'Level 1 (your business invoices)'), ('2', 'Level 2 (your directly referred businesses)'),
                 ('3', "Level 3 (businesses referred by your direct referrals)"),
                 ('4', "Level 4 (third-level downline)"), ('5', "Level 5 (fourth-level downline)")],
        validators=[DataRequired()],
        default='1'
    )
    submit = SubmitField('Calculate My Reward')

# User dashboard route
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    # Default: show Level 1 reward
    form = RewardForm(request.form)
    if request.method == "GET":
        form.downline_level.data = '1'
        form.invoice_amount.data = 0

    rewards_table = ""
    reward = None
    invoice_amount = float(form.invoice_amount.data or 0)
    downline_level = int(form.downline_level.data or 1)
    desc = {
        1: "your own purchase",
        2: "your direct referral",
        3: "your referral's referral",
        4: "third downline",
        5: "fourth downline"
    }
    cap = None

    # Defaults
    if not request.method == "POST" or not form.validate_on_submit():
        downline_level = 1
        form.downline_level.data = '1'
        reward = invoice_amount * 0.02
        cap = None
        rewards_desc = "As the customer, you earn"
    else:
        invoice_amount = float(form.invoice_amount.data)
        downline_level = int(form.downline_level.data)
        if downline_level == 1:
            reward = invoice_amount * 0.02  # 2% for self
            rewards_desc = "As the customer, you earn"
            cap = None
        elif downline_level in [2, 3, 4]:
            rate = 0.0025
            cap = 6.25
            reward = min(invoice_amount * rate, cap)
            rewards_desc = f"If your level {downline_level} downline makes a purchase"
        elif downline_level == 5:
            rate = 0.02
            cap = 50
            reward = min(invoice_amount * rate, cap)
            rewards_desc = "If your level 5 downline makes a purchase"
        else:
            reward = 0
            rewards_desc = ""
    # Only show reward if invoice_amount > 0
    if invoice_amount > 0 and reward is not None:
        if cap:
            rewards_table += f"<h5 class='mt-4 mb-2'>{rewards_desc} of ${invoice_amount:,.2f}:</h5>"
            rewards_table += f"<div class='alert alert-success'>You earn <strong>${reward:.2f}</strong> as cashback (capped at ${cap:.2f}).</div>"
        else:
            rewards_table += f"<h5 class='mt-4 mb-2'>{rewards_desc} of ${invoice_amount:,.2f}:</h5>"
            rewards_table += f"<div class='alert alert-success'>You earn <strong>${reward:.2f}</strong> as cashback.</div>"

    sponsor = User.query.get(current_user.sponsor_id) if current_user.sponsor_id else None
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
    return render_template("dashboard.html", form=form, email=current_user.email,
         referral_code=current_user.referral_code, sponsor=sponsor.email if sponsor else None,
         rewards_table=rewards_table, level2=level2, level3=level3, level4=level4, level5=level5)

# Business dashboard route
@app.route("/business/dashboard", methods=["GET", "POST"])
def business_dashboard():
    form = BusinessRewardForm(request.form)
    biz_id = session.get('business_id')
    biz = Business.query.get(biz_id) if biz_id else None
    if not biz or not biz.email_confirmed:
        flash("Please log in and confirm your business email to access the dashboard.")
        return redirect(url_for("business_login"))

    # Default: show Level 1 reward (business invoice)
    if request.method == "GET":
        form.downline_level.data = '1'
        form.invoice_amount.data = 0
    rewards_table = ""
    reward = None
    invoice_amount = float(form.invoice_amount.data or 0)
    downline_level = int(form.downline_level.data or 1)
    desc = {
        1: "your own invoice",
        2: "your directly referred businesses",
        3: "businesses referred by your direct referrals",
        4: "third-level downline",
        5: "fourth-level downline"
    }
    cap = None
    if not request.method == "POST" or not form.validate_on_submit():
        downline_level = 1
        form.downline_level.data = '1'
        reward = invoice_amount * 0.01
        cap = None
        rewards_desc = "As the business, you earn"
    else:
        invoice_amount = float(form.invoice_amount.data)
        downline_level = int(form.downline_level.data)
        if downline_level == 1:
            reward = invoice_amount * 0.01  # 1% for business self
            rewards_desc = "As the business, you earn"
            cap = None
        elif downline_level in [2, 3, 4]:
            rate = 0.0025
            cap = 3.25
            reward = min(invoice_amount * rate, cap)
            rewards_desc = f"If your level {downline_level} downline business makes a purchase"
        elif downline_level == 5:
            rate = 0.02
            cap = 25
            reward = min(invoice_amount * rate, cap)
            rewards_desc = "If your level 5 downline business makes a purchase"
        else:
            reward = 0
            rewards_desc = ""
    # Only show reward if invoice_amount > 0
    if invoice_amount > 0 and reward is not None:
        if cap:
            rewards_table += f"<h5 class='mt-4 mb-2'>{rewards_desc} of ${invoice_amount:,.2f}:</h5>"
            rewards_table += f"<div class='alert alert-success'>You earn <strong>${reward:.2f}</strong> as cashback (capped at ${cap:.2f}).</div>"
        else:
            rewards_table += f"<h5 class='mt-4 mb-2'>{rewards_desc} of ${invoice_amount:,.2f}:</h5>"
            rewards_table += f"<div class='alert alert-success'>You earn <strong>${reward:.2f}</strong> as cashback.</div>"

    sponsor = Business.query.get(biz.sponsor_id) if biz.sponsor_id else None
    level2 = Business.query.filter_by(sponsor_id=biz.id).all()
    level3, level4, level5 = [], [], []
    for b2 in level2:
        b3s = Business.query.filter_by(sponsor_id=b2.id).all()
        level3.extend(b3s)
        for b3 in b3s:
            b4s = Business.query.filter_by(sponsor_id=b3.id).all()
            level4.extend(b4s)
            for b4 in b4s:
                b5s = Business.query.filter_by(sponsor_id=b4.id).all()
                level5.extend(b5s)
    return render_template("business_dashboard.html", form=form, biz=biz, sponsor=sponsor,
        rewards_table=rewards_table, level2=level2, level3=level3, level4=level4, level5=level5)

# ...all your other (unchanged) routes here...

if __name__ == "__main__":
    app.run(debug=True)