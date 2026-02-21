from flask import Flask, request, redirect, url_for, render_template, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, DecimalField, SelectField, FileField
from wtforms.validators import DataRequired, Email, Length, Optional, NumberRange
from werkzeug.utils import secure_filename
from functools import wraps
from flask import abort
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Email, Optional
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_wtf import RecaptchaField
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_wtf import FlaskForm
from wtforms import SelectField, TextAreaField, DecimalField, SubmitField
from wtforms.validators import DataRequired, NumberRange, Length
from flask_mail import Message as MailMessage
from datetime import datetime
from datetime import date, datetime
from datetime import datetime, date
from functools import wraps
from flask import session, flash, redirect, url_for, request
from sqlalchemy import or_, and_
from sqlalchemy import func, literal
from flask import render_template
from flask_login import current_user

class ServiceRequestForm(FlaskForm):
    service_type = SelectField(
        "Type of Service Requested",
        choices=[
            ("handyman", "Handyman Service"),
            ("contractor", "Contractor Services"),
            ("cleaning", "Cleaning Services"),
            ("lawn", "Lawn Care"),
            # Add more as needed here
        ],
        validators=[DataRequired()]
    )
    details = TextAreaField("Service Details", validators=[DataRequired(), Length(max=1000)])
    budget_low = DecimalField("Budget (Low End)", validators=[NumberRange(min=0)], default=0)
    budget_high = DecimalField("Budget (High End)", validators=[NumberRange(min=0)], default=0)
    submit = SubmitField("Submit Request")

class TwoFactorForm(FlaskForm):
    code = StringField('Enter the 6-digit code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')

class EditUserForm(FlaskForm):
    name = StringField('Name', validators=[Optional()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Save')
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not any(r.name == 'super_admin' for r in current_user.roles):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.has_role(role_name):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_interaction_for_business_and_user(business_id, user_id):
    return Interaction.query.filter_by(
        business_id=business_id,
        user_id=user_id,
        status="active"
    ).first()

def business_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('business_id'):
            flash('Please log in as a business to access this page.', 'warning')
            return redirect(url_for('business_login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function

import csv
from io import StringIO, BytesIO
from flask import Response, send_file, url_for
import hmac
import hashlib
from flask import request, jsonify
import os, re, random, string, time, logging
import cloudinary
import cloudinary.uploader
import random
import qrcode
import uuid  # <-- only needs to be here once! Put with other imports

cloudinary.config(
  cloud_name = 'dmrntlcfd',
  api_key = '786387955898581',
  api_secret = 'cLtDoC44BarYjVrr3dIgi_0XiKo'
)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'perkminer_hardcoded_secret_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', "sqlite:///site.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 465))
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdhAV8sAAAAABwITf0HytcbADISlcMd87NP-i2H'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdhAV8sAAAAAFi9YjxnZqFLUl3SlQjHc1g7IEOq'

UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

db = SQLAlchemy(app)
from flask_migrate import Migrate
migrate = Migrate(app, db)
with app.app_context():
    db.create_all()
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
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
    business_referral_id = db.Column(db.String(32))
    email_confirmed = db.Column(db.Boolean, default=False)
    email_code = db.Column(db.String(16))
    name = db.Column(db.String(100))
    profile_photo = db.Column(db.String(200))
    roles = db.relationship('Role', secondary='user_roles', backref='users')
    is_suspended = db.Column(db.Boolean, default=False)

    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)

class Business(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    business_name = db.Column(db.String(100), unique=True, nullable=False)
    listing_type = db.Column(db.String(50))
    category = db.Column(db.String(50), nullable=False, default="Other")
    business_email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    referral_code = db.Column(db.String(32), unique=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('business.id'))
    user_sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    email_confirmed = db.Column(db.Boolean, default=False)
    email_code = db.Column(db.String(16))
    profile_photo = db.Column(db.String(200))
    phone_number = db.Column(db.String(30))
    address = db.Column(db.String(255))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    hours_of_operation = db.Column(db.String(100))
    website_url = db.Column(db.String(255))
    about_us = db.Column(db.Text)
    service_1 = db.Column(db.String(100))
    service_2 = db.Column(db.String(100))
    service_3 = db.Column(db.String(100))
    service_4 = db.Column(db.String(100))
    service_5 = db.Column(db.String(100))
    service_6 = db.Column(db.String(100))
    service_7 = db.Column(db.String(100))
    service_8 = db.Column(db.String(100))
    service_9 = db.Column(db.String(100))
    service_10 = db.Column(db.String(100))
    search_keywords = db.Column(db.String(500))
    draft_business_name = db.Column(db.String(100))
    draft_listing_type = db.Column(db.String(50))
    draft_category = db.Column(db.String(50), default="Other")
    draft_profile_photo = db.Column(db.String(200))
    draft_phone_number = db.Column(db.String(30))
    draft_address = db.Column(db.String(255))
    draft_latitude = db.Column(db.Float)
    draft_longitude = db.Column(db.Float)
    draft_hours_of_operation = db.Column(db.String(100))
    draft_website_url = db.Column(db.String(255))
    draft_about_us = db.Column(db.Text)
    draft_service_1 = db.Column(db.String(100))
    draft_service_2 = db.Column(db.String(100))
    draft_service_3 = db.Column(db.String(100))
    draft_service_4 = db.Column(db.String(100))
    draft_service_5 = db.Column(db.String(100))
    draft_service_6 = db.Column(db.String(100))
    draft_service_7 = db.Column(db.String(100))
    draft_service_8 = db.Column(db.String(100))
    draft_service_9 = db.Column(db.String(100))
    draft_service_10 = db.Column(db.String(100))
    draft_search_keywords = db.Column(db.String(500))
    account_balance = db.Column(db.Float, nullable=False, default=0.0)
    ad_fee = db.Column(db.Float)
    business_registration_doc = db.Column(db.String(255))  # stores filename or URL (S3, cloud, or local)

    is_suspended = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), nullable=False, default='not_submitted')

class Invite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    inviter_id = db.Column(db.Integer, nullable=True)
    inviter_type = db.Column(db.String(16), nullable=False)      # 'user' or 'business'
    invitee_email = db.Column(db.String(200), nullable=False)
    invitee_type = db.Column(db.String(16), nullable=False)      # 'user' or 'business'
    referral_code = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(16), nullable=False, default='pending')
    accepted_id = db.Column(db.Integer, nullable=True)
    accepted_at = db.Column(db.DateTime)

class Quote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    interaction_id = db.Column(db.Integer, db.ForeignKey('interaction.id'), nullable=False, unique=True)
    amount = db.Column(db.Float, nullable=False)
    details = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    interaction = db.relationship('Interaction', backref=db.backref('quote', uselist=False))

class UserTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(48), nullable=False, index=True)
    interaction_id = db.Column(db.Integer, db.ForeignKey('interaction.id'), nullable=False)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)
    amount = db.Column(db.Float, nullable=False)
    user_referral_id = db.Column(db.String(32), nullable=False)
    cash_back = db.Column(db.Float, nullable=False)
    tier2_user_referral_id = db.Column(db.String(32), nullable=False)
    tier2_commission = db.Column(db.Float, nullable=False)
    tier3_user_referral_id = db.Column(db.String(32), nullable=False)
    tier3_commission = db.Column(db.Float, nullable=False)
    tier4_user_referral_id = db.Column(db.String(32), nullable=False)
    tier4_commission = db.Column(db.Float, nullable=False)
    tier5_user_referral_id = db.Column(db.String(32), nullable=False)
    tier5_commission = db.Column(db.Float, nullable=False)
    business_referral_id = db.Column(db.String(32))
    tier1_business_user_referral_id = db.Column(db.String(32))
    tier1_business_user_commission = db.Column(db.Float)
    tier2_business_user_referral_id = db.Column(db.String(32))
    tier2_business_user_commission = db.Column(db.Float)
    tier3_business_user_referral_id = db.Column(db.String(32))
    tier3_business_user_commission = db.Column(db.Float)
    tier4_business_user_referral_id = db.Column(db.String(32))
    tier4_business_user_commission = db.Column(db.Float)
    tier5_business_user_referral_id = db.Column(db.String(32))
    tier5_business_user_commission = db.Column(db.Float)

class BusinessTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(48), nullable=False, index=True)
    interaction_id = db.Column(db.Integer, db.ForeignKey('interaction.id'), nullable=False)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)
    amount = db.Column(db.Float, nullable=False)
    business_referral_id = db.Column(db.String(32), nullable=False)
    cash_back = db.Column(db.Float, nullable=False)
    tier2_business_referral_id = db.Column(db.String(32), nullable=False)
    tier2_commission = db.Column(db.Float, nullable=False)
    tier3_business_referral_id = db.Column(db.String(32), nullable=False)
    tier3_commission = db.Column(db.Float, nullable=False)
    tier4_business_referral_id = db.Column(db.String(32), nullable=False)
    tier4_commission = db.Column(db.Float, nullable=False)
    tier5_business_referral_id = db.Column(db.String(32), nullable=False)
    tier5_commission = db.Column(db.Float, nullable=False)
    ad_fee = db.Column(db.Float)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class UserRoles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))

    user = db.relationship('User', backref=db.backref('user_roles', cascade='all, delete-orphan'))
    role = db.relationship('Role', backref=db.backref('user_roles', cascade='all, delete-orphan'))

from datetime import datetime

class Interaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    business_id = db.Column(db.Integer, db.ForeignKey('business.id'), nullable=False)
    service_type = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=False)
    budget_low = db.Column(db.Float)
    budget_high = db.Column(db.Float)
    status = db.Column(db.String(32), default="active")  # active, closed, ended, etc.
    referral_code = db.Column(db.String(32))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    awaiting_finalization = db.Column(db.Boolean, default=False)
    awaiting_payment = db.Column(db.Boolean, default=False)
    # relationships for easier querying (optional)
    user = db.relationship('User', backref='interactions', lazy=True)
    business = db.relationship('Business', backref='interactions', lazy=True)

from datetime import datetime

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    interaction_id = db.Column(db.Integer, db.ForeignKey('interaction.id'), nullable=False)
    sender_type = db.Column(db.String(16), nullable=False)  # "user" or "business"
    sender_id = db.Column(db.Integer, nullable=False)        # User or business id, based on sender_type
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    file_url = db.Column(db.String(255))  # stores the filename or URL
    file_name = db.Column(db.String(120))  # original name for display
    interaction = db.relationship('Interaction', backref='messages', lazy=True)

class EditUserForm(FlaskForm):
    name = StringField('Name', validators=[Optional()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Save')

class BusinessEditForm(FlaskForm):
    business_name = StringField('Business Name', validators=[Optional()])
    business_email = StringField('Business Email', validators=[DataRequired(), Email()])
    category = StringField('Category', validators=[Optional()])
    phone_number = StringField('Phone Number', validators=[Optional()])
    address = StringField('Address', validators=[Optional()])
    submit = SubmitField('Save')

EMAIL_REGEX = r'^[\w.-]+@[\w.-]+.\w{2,}$'
def valid_email(email): return re.match(EMAIL_REGEX, email or "")
def valid_password(pw): return pw and len(pw) >= MIN_PASSWORD_LENGTH
def random_email_code(): return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
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
    msg = MailMessage(subject, recipients=[to], html=html_body, sender=app.config['MAIL_USERNAME'])
    try:
        mail.send(msg)
    except Exception as e:
        logging.error("EMAIL SEND ERROR: %s", e)

def build_invite_email(inviter_name, join_url, video_url):
    html_body = f"""

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Joe has invited you to join PerkMiner!</title>
        <style type="text/css">
            body {{ margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }}
            table, td {{ border-collapse: collapse; }}
            a {{ color: #0066cc; text-decoration: none; }}
            .button {{
            display: inline-block;
            padding: 16px 36px;
            background-color: #6366f1;
            color: white !important;
            font-family: Arial, Helvetica, sans-serif;
            font-size: 18px;
            font-weight: bold;
            text-decoration: none;
            border-radius: 8px;
            line-height: 1;
            }}
            .button:hover {{ background-color: #4f46e5 !important; }}
        </style>
    </head>
        <body style="margin:0; padding:0; background-color:#f3f4f6;">

        <!-- Main Wrapper -->
            <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color:#f3f4f6;">
                <tr>
                    <td align="center" style="padding: 20px 10px;">

        <!-- Container -->
            <table role="presentation" width="600" border="0" cellspacing="0" cellpadding="0" style="background-color:#ffffff; border-radius:12px; overflow:hidden; box-shadow:0 4px 12px rgba(0,0,0,0.1); max-width:600px;">

        <!-- Top Message -->
                <tr>
                    <td align="center" style="padding: 40px 30px 20px; font-family: Arial, Helvetica, sans-serif; font-size: 28px; font-weight: bold; color: #1f2937; line-height: 1.2;">
                        {inviter_name} has invited you to join PerkMiner!
                    </td>
                </tr>

        <!-- Join Button -->
    <tr>
        <td align="center" style="padding: 0 40px 50px;">
            <a href="{join_url}" class="button" target="_blank" style="font-size:20px; padding:18px 48px;">
            Join PerkMiner Now
            </a>
        </td>
    </tr>

        <!-- Hero Banner with Logo -->
                <tr>
                    <td style="position:relative;">
                        <img src="https://res.cloudinary.com/dmrntlcfd/image/upload/v1771635742/Email_Background_kgfx10.jpg" width="600"
                        alt="PerkMiner Hero Banner"
                        style="display:block; width:100%; height:auto; border:0;" border="0">
        </td>
    </tr>

        <!-- Intro Text + Watch Video Button -->
    <tr>
        <td style="padding: 40px 40px 20px; font-family: Arial, Helvetica, sans-serif; font-size: 16px; color: #374151; line-height: 1.6; text-align:center;">
            <p style="margin:0 0 24px;">Discover how you earn cashback with PerkMiner.  Don't just settle for pennies, CashBack like a pro on products and services you're looking for!</p>

                <a href="{video_url}" class="button" target="_blank" style="margin: 12px 0 32px;">
                Watch our intro video
                </a>

            <p style="margin:0 0 12px;">It only takes 60 seconds to see how thousands are already earning perks every day.</p>
        </td>
    </tr>

        <!-- Secondary Image -->
    <tr>
        <td style="padding: 0 40px 30px;">
            <img src="https://res.cloudinary.com/dmrntlcfd/image/upload/v1769978430/Cashback_Network_bkqmkd.jpg" width="520" alt="PerkMiner Features"
            style="display:block; width:100%; max-width:520px; height:auto; border-radius:10px; border:0;" border="0">
        </td>
    </tr>

        <!-- Join Button -->
    <tr>
        <td align="center" style="padding: 0 40px 50px;">
            <a href="{join_url}" class="button" target="_blank" style="font-size:20px; padding:18px 48px;">
            Join PerkMiner Now
            </a>
        </td>
    </tr>

        <!-- Footer -->
    <tr>
        <td align="center" style="padding: 30px 40px; background-color:#f8f9fa; font-family: Arial, Helvetica, sans-serif; font-size: 14px; color: #6b7280; line-height:1.5; border-top:1px solid #e5e7eb;">
            <p style="margin:0 0 8px;">
                For questions regarding this email, contact
                <a href="mailto:fromperkminer@gmail.com" style="color:#4f46e5;">support@perkminer.com</a>
            </p>
            <p style="margin:0;">
                Copyright © PerkMiner 2026. All rights reserved.
            </p>
            </td>
                </tr>

                    </table>

                </td>
            </tr>
        </table>

    </body>
</html>
    """
    return html_body
def send_verification_email(user):
    code = user.email_code
    verify_url = url_for("activate", code=code, _external=True)
    html_body = f"""<p>Click <a href="{verify_url}">here</a> to confirm your email, or use code: <b>{code}</b></p>"""
    send_email(user.email, "Confirm your PerkMiner email!", html_body)

def send_business_verification_email(biz):
    code = biz.email_code
    verify_url = url_for("business_activate", code=code, _external=True)
    html_body = f"""<p>Click <a href="{verify_url}">here</a> to confirm your business email, or use code: <b>{code}</b></p>"""
    send_email(biz.business_email, "Confirm your PerkMiner business email!", html_body)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_reset_token(email, user_type):
    return serializer.dumps({'email': email, 'type': user_type})

def verify_reset_token(token, user_type, max_age=3600):
    try:
        data = serializer.loads(token, max_age=max_age)
        if data.get('type') == user_type:
            return data.get('email')
    except (SignatureExpired, BadSignature):
        return None
    return None

def send_reset_email(recipient_email, reset_url):
    send_email(
        recipient_email,
        "PerkMiner password reset",
        f"<p>You requested a password reset. Click <a href='{reset_url}'>here</a> to reset your password.</p>"
        "<p>If you didn't request this, please ignore this email.</p>"
    )

class InviteForm(FlaskForm):
    invitee_email = StringField('Invitee Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Invitation')
class BusinessInviteForm(FlaskForm):
    invitee_email = StringField('Invitee Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Invitation')
class VerifyCodeForm(FlaskForm):
    code = StringField('Code', validators=[DataRequired()])
    submit = SubmitField('Verify')
class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=MIN_PASSWORD_LENGTH)])
    referral_code = StringField('Referral Code', validators=[Optional()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Register')
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')
class RewardForm(FlaskForm):
    invoice_amount = DecimalField('Purchase Amount', validators=[DataRequired(), NumberRange(min=0.01, max=2500)], places=2, default=0)
    downline_level = SelectField(
        'Downline Level',
        choices=[
            ('1', 'Tier 1: (your purchases)'), 
            ('2', 'Tier 2: (direct referral purchases)'),
            ('3', 'Tier 3: (Tier 2 referral purchases)'),
            ('4', 'Tier 4: (Tier 3 referral purchases)'),
            ('5', 'Tier 5: (Tier 4 referral purchases)')
        ],
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
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')
class BusinessRewardForm(FlaskForm):
    invoice_amount = DecimalField('Purchase Amount', validators=[DataRequired(), NumberRange(min=0.01, max=2500)], places=2, default=0)
    downline_level = SelectField(
        'Downline Level',
        choices=[
            ('1', 'Tier 1: (your invoices)'), 
            ('2', 'Tier 2: (direct referral invoices)'),
            ('3', 'Tier 3: (Tier 2 referral invoices)'),
            ('4', 'Tier 4: (Tier 3 referral invoices)'),
            ('5', 'Tier 5: (Tier 4 referral invoices)')
        ],
        validators=[DataRequired()],
        default='1'
    )
    submit = SubmitField('Calculate My Reward')
class UserProfileForm(FlaskForm):
    name = StringField('Name', validators=[Optional(), Length(max=100)])
    profile_photo = FileField('Upload Profile Photo')
    submit = SubmitField('Save Profile')
class UserProfileForm(FlaskForm):
    name = StringField('Name', validators=[Optional(), Length(max=100)])
    profile_photo = FileField('Upload Profile Photo')
    submit = SubmitField('Save Profile')
class BusinessProfileForm(FlaskForm):
    business_name = StringField('Business Name', validators=[Optional(), Length(max=100)])
    profile_photo = FileField('Upload Profile Photo')
    phone_number = StringField('Phone Number', validators=[Optional(), Length(max=30)])
    address = StringField('Address', validators=[Optional(), Length(max=255)])
    latitude = StringField('Latitude', validators=[Optional()])
    longitude = StringField('Longitude', validators=[Optional()])
    submit = SubmitField('Save Profile')

class EmptyForm(FlaskForm):
    submit = SubmitField('Submit')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send reset link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Reset Password')

@app.route("/admin-roles")
@login_required
def admin_roles_landing():
    return render_template("admin_roles_landing.html")

@app.template_filter('usd')
def usd(value):
    return "${:,.2f}".format(value or 0.0)

@app.route("/")
def home():
    approved_listings = Business.query.filter_by(status="approved").all()

    # User totals
    user_transactions = UserTransaction.query.all()
    total_user_tier1 = sum(t.cash_back or 0 for t in user_transactions)
    total_user_commission = sum(
        (t.tier2_commission or 0) + (t.tier3_commission or 0) + 
        (t.tier4_commission or 0) + (t.tier5_commission or 0)
        for t in user_transactions
    )
    total_user_biz_commission = sum(
        (t.tier1_business_user_commission or 0) +
        (t.tier2_business_user_commission or 0) +
        (t.tier3_business_user_commission or 0) +
        (t.tier4_business_user_commission or 0) +
        (t.tier5_business_user_commission or 0)
        for t in user_transactions
    )
    total_member_paid = total_user_tier1 + total_user_commission + total_user_biz_commission

    # Business totals
    business_transactions = BusinessTransaction.query.all()
    total_biz_paid = sum(
        (t.cash_back or 0) +
        (t.tier2_commission or 0) +
        (t.tier3_commission or 0) +
        (t.tier4_commission or 0) +
        (t.tier5_commission or 0)
        for t in business_transactions
    )
    total_gross_sales = sum(t.amount or 0 for t in business_transactions)

    # Advertising fees
    total_ad_fees = sum((t.ad_fee or 0) for t in business_transactions)

    # Percent of ad fees paid by PerkMiner
    total_paid_out = total_member_paid + total_biz_paid
    percent_fees_paid = ( (total_paid_out / total_ad_fees) * 100 ) if total_ad_fees > 0 else 0

    return render_template(
        "home.html",
        approved_listings=approved_listings,
        total_member_paid=total_member_paid,
        total_biz_paid=total_biz_paid,
        total_gross_sales=total_gross_sales,
        total_ad_fees=total_ad_fees,
        percent_fees_paid=percent_fees_paid
    )

@app.route("/business")
def business_home():
    return render_template("business_home.html")

@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    lat = request.args.get("lat", type=float)
    lng = request.args.get("lng", type=float)
    distance = request.args.get("distance", "").strip()  # “5”, “10”, “25”, or “all”

    query = Business.query.filter_by(status="approved")

    if category:
        query = query.filter(Business.category == category)
    if q:
        query = query.filter(Business.search_keywords.ilike(f"%{q}%"))

    use_location = lat is not None and lng is not None

    if use_location:
        haversine = (
            3959 * func.acos(
                func.least(
                    1.0,
                    func.cos(func.radians(lat)) *
                    func.cos(func.radians(Business.latitude)) *
                    func.cos(func.radians(Business.longitude) - func.radians(lng)) +
                    func.sin(func.radians(lat)) *
                    func.sin(func.radians(Business.latitude))
                )
            )
        ).label('distance_mi')

        query = query.add_columns(haversine)
        query = query.filter(Business.latitude.isnot(None), Business.longitude.isnot(None))

        # Filter by distance if set and not "all"
        if distance and distance != "all":
            try:
                dist_num = float(distance)
                query = query.filter(haversine <= dist_num)
            except ValueError:
                pass

        # Always order by distance if calculating
        query = query.order_by(haversine)
        results = query.all()
        # results = [(Business, distance), ...]
        listings = []
        for biz, d in results:
            biz.distance_mi = round(d, 2) if d is not None else None
            listings.append(biz)
    else:
        # No lat/lng: show normally (might show all, not filtered)
        listings = query.all()

    return render_template(
        "search_results.html",
        results=listings,
        q=q,
        category=category,
        lat=lat,
        lng=lng,
        selected_distance=distance
    )

@app.route("/category/<name>")
def category_browse(name):
    results = Business.query.filter_by(category=name, status="approved").all()  # filter by approved!
    return render_template("category_results.html", results=results, category=name)

@app.route("/intro")
def intro():
    return render_template("intro.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    # Populate referral_code field from ?ref= on GET (invite link)
    ref_code = request.args.get('ref')
    if request.method == "GET" and ref_code:
        form.referral_code.data = ref_code

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data
        referral_code = form.referral_code.data.strip()
        if not valid_password(password):
            flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
            return redirect(url_for("register"))
        if not valid_email(email):
            flash("Invalid email format.")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Email already registered.")
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
        email_code = random_email_code()
        new_user = User(
            email=email,
            password=hashed_pw,
            referral_code=user_ref_code,
            sponsor_id=sponsor_id,
            email_confirmed=False,
            email_code=email_code
        )
        db.session.add(new_user)
        db.session.commit()
        send_verification_email(new_user)
        session['pending_email'] = email
        session['last_verification_sent'] = time.time()
        return redirect(url_for("verify_email"))
    return render_template("register.html", form=form)

@app.route("/verify_email", methods=["GET", "POST"])
def verify_email():
    form = VerifyCodeForm()
    pending_email = session.get('pending_email')
    user = User.query.filter_by(email=pending_email).first() if pending_email else None
    can_resend = False
    wait_seconds = 0
    if not user:
        flash("No registration found to verify.")
        return redirect(url_for("register"))
    if user.email_confirmed:
        flash("Email is already confirmed, please log in.")
        return redirect(url_for("login"))
    now = time.time()
    last_sent = session.get('last_verification_sent', 0)
    if now - last_sent >= 30:
        can_resend = True
    else:
        wait_seconds = int(30 - (now - last_sent))
    if form.validate_on_submit():
        submitted_code = form.code.data.strip().upper()
        if submitted_code == user.email_code:
            user.email_confirmed = True
            db.session.commit()
            flash("Email confirmed! You can now log in.")
            session.pop("pending_email", None)
            return redirect(url_for("login"))
        else:
            flash("Incorrect code.")
    return render_template("verify_email.html", form=form, can_resend=can_resend, wait_seconds=wait_seconds)

@app.route("/resend_verification", methods=["POST"])
def resend_verification():
    pending_email = session.get('pending_email')
    user = User.query.filter_by(email=pending_email).first() if pending_email else None
    if user and not user.email_confirmed:
        user.email_code = random_email_code()
        db.session.commit()
        send_verification_email(user)
        session['last_verification_sent'] = time.time()
        flash("Verification email resent.")
    return redirect(url_for("verify_email"))

@app.route("/activate/<code>")
def activate(code):
    user = User.query.filter_by(email_code=code).first()
    if user:
        user.email_confirmed = True
        db.session.commit()
        flash("Email confirmed! You can now log in.")
        session.pop('pending_email', None)
        return redirect(url_for("login"))
    else:
        flash("Invalid or expired code.")
        return redirect(url_for("register"))

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    message = ""
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if user.is_suspended:
                flash('Account suspended, contact <a href="mailto:fromperkpay@gmail.com">support</a>.', 'danger')
                return redirect(url_for("login"))
            if not user.email_confirmed:
                message = "Please confirm your email first (check your inbox)."
                session['pending_email'] = email
                return redirect(url_for("verify_email"))
            else:
                # --- 2FA LOGIC ---
                import random  # make sure this is also at the top of your file
                code = str(random.randint(100000, 999999))
                session['pending_2fa_code'] = code
                session['pending_2fa_user_id'] = user.id
                send_email(
                    user.email,
                    "Your PerkMiner Login Code",
                    f"<p>Your PerkMiner login code is: <b>{code}</b></p>"
                )
                flash("A login code has been sent to your email.")
                return redirect(url_for("two_factor"))
        else:
            message = "Login failed. Check email and password."
    return render_template("login.html", message=message, form=form)

@app.route("/two_factor", methods=["GET", "POST"])
def two_factor():
    form = TwoFactorForm()
    if form.validate_on_submit():
        code_entered = form.code.data.strip()
        code_expected = session.get('pending_2fa_code')
        user_id = session.get('pending_2fa_user_id')
        if code_expected and code_entered == code_expected and user_id:
            user = User.query.get(user_id)
            if user:
                login_user(user)
                # Clean up session
                session.pop('pending_2fa_code', None)
                session.pop('pending_2fa_user_id', None)
                flash("Login successful!")
                return redirect(url_for("dashboard"))
        flash("Incorrect code. Please try again.")
    return render_template("two_factor.html", form=form)

@app.route("/resend_login_2fa", methods=["POST"])
def resend_login_2fa():
    user_id = session.get('pending_2fa_user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            code = str(random.randint(100000, 999999))
            session['pending_2fa_code'] = code
            send_email(
                user.email,
                "Your PerkMiner Login Code",
                f"<p>Your PerkMiner login code is: <b>{code}</b></p>"
            )
            flash("New code sent.")
    return redirect(url_for("two_factor"))

@app.route("/resend_biz_2fa", methods=["POST"])
def resend_biz_2fa():
    biz_id = session.get('pending_2fa_biz_id')
    if biz_id:
        biz = Business.query.get(biz_id)
        if biz:
            code = str(random.randint(100000, 999999))
            session['pending_2fa_code'] = code
            send_email(
                biz.business_email,
                "Your PerkMiner Business Login Code",
                f"<p>Your PerkMiner business login code is: <b>{code}</b></p>"
            )
            flash("New code sent.")
    return redirect(url_for("two_factor_biz"))

@app.route("/resend_admin_2fa", methods=["POST"])
def resend_admin_2fa():
    user_id = session.get('pending_2fa_user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            code = str(random.randint(100000, 999999))
            session['pending_2fa_code'] = code
            send_email(
                user.email,
                "Your PerkMiner Login Code",
                f"<p>Your PerkMiner login code is: <b>{code}</b></p>"
            )
            flash("New code sent.")
    return redirect(url_for("two_factor"))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(email, "user")
            reset_url = url_for('reset_password', token=token, _external=True)
            send_reset_email(email, reset_url)
        flash("If an account with that email exists, a link has been sent.")
        return redirect(url_for('login'))
    return render_template('forgot_password.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token, "user")
    if not email:
        flash("Reset link invalid or expired.")
        return redirect(url_for('login'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            db.session.commit()
            flash("Password reset, please log in.")
            return redirect(url_for('login'))
        flash("Account not found.")
    return render_template('reset_password.html', form=form)

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/invite', methods=['POST'])
@login_required
def invite():
    invite_form = InviteForm()
    if not invite_form.validate_on_submit():
        flash('Invalid form.')
        return redirect(url_for('dashboard'))

    invitee_email = invite_form.invitee_email.data.strip()
    inviter_name = current_user.name if current_user.name else current_user.email
    invitee_type = request.form.get('invitee_type', 'user')  # New: type coming from form

    # Store the invite in the database (optional: add invitee_type)
    new_invite = Invite(
        inviter_id=current_user.id,
        inviter_type='user',
        invitee_email=invitee_email,
        invitee_type=invitee_type,
        referral_code=current_user.referral_code,
        status='pending'
    )
    db.session.add(new_invite)
    db.session.commit()

    # Build the correct registration link
    if invitee_type == 'business':
        reg_url = url_for('business_register', ref=current_user.referral_code, _external=True)
    else:
        reg_url = url_for('register', ref=current_user.referral_code, _external=True)
    video_url = url_for('intro', ref=current_user.referral_code, _external=True)
    html_body = build_invite_email(inviter_name, reg_url, video_url)
    send_email(invitee_email, f"{inviter_name} has invited you to join PerkMiner.", html_body)

    flash(
        'Business invitation sent!' if invitee_type == "business"
        else 'User invitation sent!'
    )
    return redirect(url_for('dashboard'))

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    print("Current user roles:", [role.name for role in current_user.roles])
    form = RewardForm(request.form)
    profile_form = UserProfileForm()
    invite_form = InviteForm()
    if request.method == "POST" and profile_form.submit.data and profile_form.validate():
        user = current_user
        updated = False
        if profile_form.name.data and profile_form.name.data != user.name:
            user.name = profile_form.name.data
            updated = True
        file = request.files.get('profile_photo')
        if file and allowed_file(file.filename):
            upload_result = cloudinary.uploader.upload(file)
            user.profile_photo = upload_result.get('secure_url')
            updated = True
        if updated:
            db.session.commit()
            flash("Profile updated!")
        return redirect(url_for('dashboard'))

    if request.method == "GET":
        form.downline_level.data = '1'
        form.invoice_amount.data = 0
    rewards_table = ""; reward = None
    invoice_amount = float(form.invoice_amount.data or 0)
    downline_level = int(form.downline_level.data or 1)
    cap = None
    if not request.method == "POST" or not form.validate_on_submit():
        downline_level = 1
        form.downline_level.data = '1'
        reward = invoice_amount * 0.02
        cap = None
        rewards_desc = "As the customer, when you make a purchase in the amount of"
    else:
        invoice_amount = float(form.invoice_amount.data)
        downline_level = int(form.downline_level.data)
        if downline_level == 1:
            reward = invoice_amount * 0.02; rewards_desc = "When you make a purchase, you earn"; cap = None
        elif downline_level in [2, 3, 4]:
            rate = 0.0025; cap = 6.25; reward = min(invoice_amount * rate, cap)
            rewards_desc = f"If a person in your Tier {downline_level} level makes a purchase"
        elif downline_level == 5:
            rate = 0.02; cap = 50; reward = min(invoice_amount * rate, cap)
            rewards_desc = "If a person in your Tier 5 level makes a purchase"
        else: reward = 0; rewards_desc = ""
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

    # --- Business network tiers ---
    user_id = current_user.id
    biz_level1 = Business.query.filter_by(user_sponsor_id=user_id).all()

    def biz_ids(bizlist): return [b.id for b in bizlist]

    biz_level2 = Business.query.filter(Business.sponsor_id.in_(biz_ids(biz_level1))).all() if biz_level1 else []
    biz_level3 = Business.query.filter(Business.sponsor_id.in_(biz_ids(biz_level2))).all() if biz_level2 else []
    biz_level4 = Business.query.filter(Business.sponsor_id.in_(biz_ids(biz_level3))).all() if biz_level3 else []
    biz_level5 = Business.query.filter(Business.sponsor_id.in_(biz_ids(biz_level4))).all() if biz_level4 else []

    has_invited_business = len(biz_level1) > 0

    # Query for active sessions for this user
    active_sessions = Interaction.query.filter_by(user_id=current_user.id, status='active').all()
    has_active_sessions = len(active_sessions) > 0

    return render_template(
        "dashboard.html",
        form=form,
        profile_form=profile_form,
        invite_form=invite_form,
        email=current_user.email,
        referral_code=current_user.referral_code,
        sponsor=sponsor if sponsor else None,
        rewards_table=rewards_table,
        level2=level2, level3=level3, level4=level4, level5=level5,
        biz_level1=biz_level1, biz_level2=biz_level2, biz_level3=biz_level3, biz_level4=biz_level4, biz_level5=biz_level5,
        has_invited_business=has_invited_business,
        user_name=current_user.name,
        profile_img_url=current_user.profile_photo,
        has_active_sessions=has_active_sessions  # for template logic
    )

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route("/user/qr")
@login_required
def user_qr_code():
    # The QR code will encode this full payment URL
    code_url = url_for('payment_qr_redirect', ref=current_user.referral_code, _external=True)
    img = qrcode.make(code_url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

@app.route("/session/<int:interaction_id>/user-receipt-check")
@login_required
def check_user_receipt(interaction_id):
    interaction = Interaction.query.get_or_404(interaction_id)
    if interaction.user_id != current_user.id:
        return {"has_receipt": False}
    # Check for receipt with both correct user and interaction:
    user_txn = UserTransaction.query.filter_by(
        interaction_id=interaction.id,
        user_referral_id=current_user.referral_code
    ).order_by(UserTransaction.date_time.desc()).first()
    return {"has_receipt": user_txn is not None}

@app.route("/session/<int:interaction_id>/user-receipt")
@login_required
def show_user_receipt(interaction_id):
    interaction = Interaction.query.get_or_404(interaction_id)
    if interaction.user_id != current_user.id:
        abort(403)
    transaction = UserTransaction.query.filter_by(
        interaction_id=interaction.id,
        user_referral_id=current_user.referral_code
    ).order_by(UserTransaction.date_time.desc()).first()
    return render_template("user_transaction_receipt.html", transaction=transaction, interaction=interaction)

@app.route("/user/receipts")
@login_required
def user_receipts():
    transactions = UserTransaction.query.filter_by(user_referral_id=current_user.referral_code).order_by(UserTransaction.date_time.desc()).all()
    # Optionally join/query interaction/business for each transaction
    return render_template("user_receipts.html", transactions=transactions)

@app.route("/export_user_receipts_csv")
@login_required
def export_user_receipts_csv():
    user = current_user
    ref_code = user.referral_code

    transactions = UserTransaction.query.filter_by(user_referral_id=ref_code).order_by(UserTransaction.date_time.desc()).all()

    import csv
    from io import StringIO
    si = StringIO()
    writer = csv.writer(si)

    # Header
    writer.writerow([f"Receipts for '{user.name or user.email}' from Perk Miner"])
    writer.writerow([])

    # Table headers
    writer.writerow([
        "Date/Time",
        "Transaction ID",
        "Amount",
        "Tier 1 (2% Cash Back)",
        "Tier 2 (Commission)",
        "Tier 3 (Commission)",
        "Tier 4 (Commission)",
        "Tier 5 (Commission)"
    ])
    for t in transactions:
        writer.writerow([
            t.date_time.strftime('%Y-%m-%d %I:%M %p'),
            t.transaction_id,
            f"{t.amount:,.2f}",
            f"{t.cash_back:,.2f}" if t.user_referral_id == ref_code else "",
            f"{t.tier2_commission:,.2f}" if t.tier2_user_referral_id == ref_code else "",
            f"{t.tier3_commission:,.2f}" if t.tier3_user_referral_id == ref_code else "",
            f"{t.tier4_commission:,.2f}" if t.tier4_user_referral_id == ref_code else "",
            f"{t.tier5_commission:,.2f}" if t.tier5_user_referral_id == ref_code else "",
        ])

    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={
        "Content-Disposition": f"attachment;filename=user_receipts_{user.referral_code}.csv"
    })

@app.route("/user/earnings", methods=["GET"])
@login_required
def user_earnings():
    period = request.args.get("period", "all")
    year = int(request.args.get("year", 0)) if request.args.get("year") else 0
    month = int(request.args.get("month", 0)) if request.args.get("month") else 0

    ref_code = current_user.referral_code

    all_txns = UserTransaction.query

    # Date filter
    if period == "year" and year:
        all_txns = all_txns.filter(UserTransaction.date_time >= datetime(year, 1, 1), UserTransaction.date_time < datetime(year+1, 1, 1))
    elif period == "month" and year and month:
        start = datetime(year, month, 1)
        if month == 12:
            end = datetime(year+1, 1, 1)
        else:
            end = datetime(year, month+1, 1)
        all_txns = all_txns.filter(UserTransaction.date_time >= start, UserTransaction.date_time < end)

    transactions = all_txns.order_by(UserTransaction.date_time.desc()).all()

    filtered = []
    for t in transactions:
        earned = False
        # Standard user earnings (cash back and user-user commissions)
        if t.user_referral_id == ref_code and t.cash_back > 0:
            earned = True
        if t.tier2_user_referral_id == ref_code and t.tier2_commission > 0:
            earned = True
        if t.tier3_user_referral_id == ref_code and t.tier3_commission > 0:
            earned = True
        if t.tier4_user_referral_id == ref_code and t.tier4_commission > 0:
            earned = True
        if t.tier5_user_referral_id == ref_code and t.tier5_commission > 0:
            earned = True
        # User-business commissions
        if t.tier1_business_user_referral_id == ref_code and t.tier1_business_user_commission > 0:
            earned = True
        if t.tier2_business_user_referral_id == ref_code and t.tier2_business_user_commission > 0:
            earned = True
        if t.tier3_business_user_referral_id == ref_code and t.tier3_business_user_commission > 0:
            earned = True
        if t.tier4_business_user_referral_id == ref_code and t.tier4_business_user_commission > 0:
            earned = True
        if t.tier5_business_user_referral_id == ref_code and t.tier5_business_user_commission > 0:
            earned = True
        if earned:
            filtered.append(t)
    transactions = filtered

    tier1_earnings = sum(
        t.cash_back for t in transactions
        if t.user_referral_id == ref_code and t.cash_back > 0
    )
    tier2_earnings = sum(t.tier2_commission for t in transactions if t.tier2_user_referral_id == ref_code)
    tier3_earnings = sum(t.tier3_commission for t in transactions if t.tier3_user_referral_id == ref_code)
    tier4_earnings = sum(t.tier4_commission for t in transactions if t.tier4_user_referral_id == ref_code)
    tier5_earnings = sum(t.tier5_commission for t in transactions if t.tier5_user_referral_id == ref_code)
    commissions_total = tier2_earnings + tier3_earnings + tier4_earnings + tier5_earnings

    # User-Business Commissions: Tier 1-5
    tier1_user_business_earnings = sum(
        t.tier1_business_user_commission for t in transactions
        if t.tier1_business_user_referral_id == ref_code and t.tier1_business_user_commission > 0
    )
    tier2_user_business_earnings = sum(
        t.tier2_business_user_commission for t in transactions
        if t.tier2_business_user_referral_id == ref_code and t.tier2_business_user_commission > 0
    )
    tier3_user_business_earnings = sum(
        t.tier3_business_user_commission for t in transactions
        if t.tier3_business_user_referral_id == ref_code and t.tier3_business_user_commission > 0
    )
    tier4_user_business_earnings = sum(
        t.tier4_business_user_commission for t in transactions
        if t.tier4_business_user_referral_id == ref_code and t.tier4_business_user_commission > 0
    )
    tier5_user_business_earnings = sum(
        t.tier5_business_user_commission for t in transactions
        if t.tier5_business_user_referral_id == ref_code and t.tier5_business_user_commission > 0
    )
    total_user_business_commission = (
        tier1_user_business_earnings +
        tier2_user_business_earnings +
        tier3_user_business_earnings +
        tier4_user_business_earnings +
        tier5_user_business_earnings
    )

    # Check if user has ever referred a business
    has_invited_business = Business.query.filter_by(user_sponsor_id=current_user.id).first() is not None

    summary = dict(
        tier1_earnings=f"{tier1_earnings:,.2f}",
        tier2_earnings=f"{tier2_earnings:,.2f}",
        tier3_earnings=f"{tier3_earnings:,.2f}",
        tier4_earnings=f"{tier4_earnings:,.2f}",
        tier5_earnings=f"{tier5_earnings:,.2f}",
        commissions_total=f"{commissions_total:,.2f}",
        tier1_user_business_earnings=f"{tier1_user_business_earnings:,.2f}",
        tier2_user_business_earnings=f"{tier2_user_business_earnings:,.2f}",
        tier3_user_business_earnings=f"{tier3_user_business_earnings:,.2f}",
        tier4_user_business_earnings=f"{tier4_user_business_earnings:,.2f}",
        tier5_user_business_earnings=f"{tier5_user_business_earnings:,.2f}",
        total_user_business_commission=f"{total_user_business_commission:,.2f}",
        total=f"{tier1_earnings + commissions_total + total_user_business_commission:,.2f}",
        period=period,
        year=year,
        month=month
    )

    # Optionally: build a business lookup for displaying business info in the table
    business_lookup = {b.referral_code: b for b in Business.query.all()}

    return render_template(
        "user_earnings.html",
        transactions=transactions,
        summary=summary,
        business_lookup=business_lookup,
        has_invited_business=has_invited_business,
        today=date.today(),
        period=period,
        year=year,
        month=month
    )

@app.route("/export_user_earnings_csv")
@login_required
def export_user_earnings_csv():
    user = current_user
    ref_code = user.referral_code

    period = request.args.get("period", "all")
    year = int(request.args.get("year", 0)) if request.args.get("year") else 0
    month = int(request.args.get("month", 0)) if request.args.get("month") else 0

    all_txns = UserTransaction.query

    if period == "year" and year:
        all_txns = all_txns.filter(UserTransaction.date_time >= datetime(year, 1, 1), UserTransaction.date_time < datetime(year+1, 1, 1))
    elif period == "month" and year and month:
        start = datetime(year, month, 1)
        if month == 12:
            end = datetime(year+1, 1, 1)
        else:
            end = datetime(year, month+1, 1)
        all_txns = all_txns.filter(UserTransaction.date_time >= start, UserTransaction.date_time < end)
    transactions = all_txns.order_by(UserTransaction.date_time.desc()).all()

    # Only include transactions where this user earned something
    filtered = []
    for t in transactions:
        earned = False
        # Any tier
        if t.user_referral_id == ref_code and t.cash_back > 0:
            earned = True
        if t.tier2_user_referral_id == ref_code and t.tier2_commission > 0:
            earned = True
        if t.tier3_user_referral_id == ref_code and t.tier3_commission > 0:
            earned = True
        if t.tier4_user_referral_id == ref_code and t.tier4_commission > 0:
            earned = True
        if t.tier5_user_referral_id == ref_code and t.tier5_commission > 0:
            earned = True
        if t.tier1_business_user_referral_id == ref_code and t.tier1_business_user_commission > 0:
            earned = True
        if t.tier2_business_user_referral_id == ref_code and t.tier2_business_user_commission > 0:
            earned = True
        if t.tier3_business_user_referral_id == ref_code and t.tier3_business_user_commission > 0:
            earned = True
        if t.tier4_business_user_referral_id == ref_code and t.tier4_business_user_commission > 0:
            earned = True
        if t.tier5_business_user_referral_id == ref_code and t.tier5_business_user_commission > 0:
            earned = True
        if earned:
            filtered.append(t)
    transactions = filtered

    # Summary (like on page)
    tier1_earnings = sum(
        t.cash_back for t in transactions
        if t.user_referral_id == ref_code and t.cash_back > 0
    )
    tier2_earnings = sum(t.tier2_commission for t in transactions if t.tier2_user_referral_id == ref_code)
    tier3_earnings = sum(t.tier3_commission for t in transactions if t.tier3_user_referral_id == ref_code)
    tier4_earnings = sum(t.tier4_commission for t in transactions if t.tier4_user_referral_id == ref_code)
    tier5_earnings = sum(t.tier5_commission for t in transactions if t.tier5_user_referral_id == ref_code)
    commissions_total = tier2_earnings + tier3_earnings + tier4_earnings + tier5_earnings

    # User-Business commissions
    tier1_user_business_earnings = sum(
        t.tier1_business_user_commission for t in transactions
        if t.tier1_business_user_referral_id == ref_code and t.tier1_business_user_commission > 0
    )
    tier2_user_business_earnings = sum(
        t.tier2_business_user_commission for t in transactions
        if t.tier2_business_user_referral_id == ref_code and t.tier2_business_user_commission > 0
    )
    tier3_user_business_earnings = sum(
        t.tier3_business_user_commission for t in transactions
        if t.tier3_business_user_referral_id == ref_code and t.tier3_business_user_commission > 0
    )
    tier4_user_business_earnings = sum(
        t.tier4_business_user_commission for t in transactions
        if t.tier4_business_user_referral_id == ref_code and t.tier4_business_user_commission > 0
    )
    tier5_user_business_earnings = sum(
        t.tier5_business_user_commission for t in transactions
        if t.tier5_business_user_referral_id == ref_code and t.tier5_business_user_commission > 0
    )
    total_user_business_commission = (
        tier1_user_business_earnings +
        tier2_user_business_earnings +
        tier3_user_business_earnings +
        tier4_user_business_earnings +
        tier5_user_business_earnings
    )
    total_all = tier1_earnings + commissions_total + total_user_business_commission

    # Generate CSV
    import csv
    from io import StringIO
    si = StringIO()
    writer = csv.writer(si)

    # Header
    writer.writerow([f"Earnings for '{user.name or user.email}' from Perk Miner"])
    writer.writerow([])
    writer.writerow([f"Total Earned:", f"${total_all:,.2f}"])
    writer.writerow([f"2% Cash Back (Self/Tier 1):", f"${tier1_earnings:,.2f}"])
    writer.writerow([f"Total Commission (Tiers 2-5):", f"${commissions_total:,.2f}"])
    writer.writerow([f"Total User-Business Commission (Tiers 1-5):", f"${total_user_business_commission:,.2f}"])
    writer.writerow([])
    writer.writerow([f"Tier 2 (Commission):", f"${tier2_earnings:,.2f}"])
    writer.writerow([f"Tier 3 (Commission):", f"${tier3_earnings:,.2f}"])
    writer.writerow([f"Tier 4 (Commission):", f"${tier4_earnings:,.2f}"])
    writer.writerow([f"Tier 5 (Commission):", f"${tier5_earnings:,.2f}"])
    writer.writerow([])
    writer.writerow([f"Tier 1 User-Business Commission:", f"${tier1_user_business_earnings:,.2f}"])
    writer.writerow([f"Tier 2 User-Business Commission:", f"${tier2_user_business_earnings:,.2f}"])
    writer.writerow([f"Tier 3 User-Business Commission:", f"${tier3_user_business_earnings:,.2f}"])
    writer.writerow([f"Tier 4 User-Business Commission:", f"${tier4_user_business_earnings:,.2f}"])
    writer.writerow([f"Tier 5 User-Business Commission:", f"${tier5_user_business_earnings:,.2f}"])
    writer.writerow([])

    # Table headers (your details)
    writer.writerow([
        "Date/Time",
        "Transaction ID",
        "Tier 1 (2% Cash Back)",
        "Tier 2 (Commission)",
        "Tier 3 (Commission)",
        "Tier 4 (Commission)",
        "Tier 5 (Commission)",
        "Tier 1 User-Business",
        "Tier 2 User-Business",
        "Tier 3 User-Business",
        "Tier 4 User-Business",
        "Tier 5 User-Business"
    ])
    for t in transactions:
        writer.writerow([
            t.date_time.strftime('%Y-%m-%d %I:%M %p'),
            t.transaction_id,
            f"{t.cash_back:,.2f}" if t.user_referral_id == ref_code else "",
            f"{t.tier2_commission:,.2f}" if t.tier2_user_referral_id == ref_code else "",
            f"{t.tier3_commission:,.2f}" if t.tier3_user_referral_id == ref_code else "",
            f"{t.tier4_commission:,.2f}" if t.tier4_user_referral_id == ref_code else "",
            f"{t.tier5_commission:,.2f}" if t.tier5_user_referral_id == ref_code else "",
            f"{t.tier1_business_user_commission:,.2f}" if t.tier1_business_user_referral_id == ref_code else "",
            f"{t.tier2_business_user_commission:,.2f}" if t.tier2_business_user_referral_id == ref_code else "",
            f"{t.tier3_business_user_commission:,.2f}" if t.tier3_business_user_referral_id == ref_code else "",
            f"{t.tier4_business_user_commission:,.2f}" if t.tier4_business_user_referral_id == ref_code else "",
            f"{t.tier5_business_user_commission:,.2f}" if t.tier5_business_user_referral_id == ref_code else "",
        ])

    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={
        "Content-Disposition": f"attachment;filename=user_earnings_{user.referral_code}.csv"
    })

# USER — View Quote (read-only; user context)
@app.route("/session/<int:interaction_id>/user-quote")
@login_required
def user_quote_view(interaction_id):
    interaction = Interaction.query.get_or_404(interaction_id)
    is_user = interaction.user_id == current_user.id
    is_biz = False
    if not is_user:
        abort(403)
    quote = Quote.query.filter_by(interaction_id=interaction.id).first()
    return render_template(
        "quote.html",
        interaction=interaction,
        quote=quote,
        is_user=is_user,
        is_biz=is_biz
    )

@app.route("/user/start-purchase/<int:biz_id>")
@login_required
def start_purchase(biz_id):
    interaction = Interaction.query.filter_by(
        user_id=current_user.id,
        business_id=biz_id,
        status='active'
    ).first()
    if not interaction:
        interaction = Interaction(
            user_id=current_user.id,
            business_id=biz_id,
            status='active',
            awaiting_payment=True,
            service_type='Purchase',              # Non-null default
            details='Direct QR purchase',         # Non-null default
            budget_low=0,
            budget_high=0,
            referral_code=current_user.referral_code
        )
        db.session.add(interaction)
        db.session.commit()
    else:
        interaction.awaiting_payment = True
        db.session.commit()
    return redirect(url_for('show_purchase_qr', interaction_id=interaction.id))

@app.route("/user/show-qr/<int:interaction_id>")
@login_required
def show_purchase_qr(interaction_id):
    interaction = Interaction.query.get_or_404(interaction_id)
    if interaction.user_id != current_user.id:
        abort(403)
    is_finalize_payment = getattr(interaction, "awaiting_payment", False)
    is_request_for_service = (not is_finalize_payment and getattr(interaction, "service_type", None) == "Service Request")
    return render_template(
        "show_qr.html",
        interaction=interaction,
        is_finalize_payment=is_finalize_payment,
        is_request_for_service=is_request_for_service
    )

@app.route("/finalize-transaction/<int:interaction_id>", methods=["GET", "POST"])
@login_required
def finalize_transaction_user(interaction_id):
    interaction = Interaction.query.get_or_404(interaction_id)
    if interaction.user_id != current_user.id:
        abort(403)

    now = datetime.now()
    summary = None

    if request.method == "POST":
        transaction_id = str(uuid.uuid4())
        data = request.form
        amount = float(data.get("amount", 0))

        # USER-TO-USER COMMISSION LOGIC
        user_referral_id = current_user.referral_code
        user_cash_back_raw = amount * 0.02
        user_cash_back = round(min(user_cash_back_raw, 50), 2)  # Tier 1 cap $50

        u2 = User.query.filter_by(id=current_user.sponsor_id).first()
        tier2_user_referral_id = u2.referral_code if u2 else None
        tier2_commission = round(min(amount * 0.0025, 6.25), 2) if u2 else 0

        u3 = User.query.filter_by(id=u2.sponsor_id).first() if u2 and u2.sponsor_id else None
        tier3_user_referral_id = u3.referral_code if u3 else None
        tier3_commission = round(min(amount * 0.0025, 6.25), 2) if u3 else 0

        u4 = User.query.filter_by(id=u3.sponsor_id).first() if u3 and u3.sponsor_id else None
        tier4_user_referral_id = u4.referral_code if u4 else None
        tier4_commission = round(min(amount * 0.0025, 6.25), 2) if u4 else 0

        u5 = User.query.filter_by(id=u4.sponsor_id).first() if u4 and u4.sponsor_id else None
        tier5_user_referral_id = u5.referral_code if u5 else None
        tier5_commission = round(min(amount * 0.02, 50), 2) if u5 else 0

        # All business-downline user fields are left default/blank for pure user-purchases!
        user_trans = UserTransaction(
            transaction_id=transaction_id,
            interaction_id=interaction.id,
            amount=amount,
            business_referral_id=None,
            user_referral_id=user_referral_id,
            cash_back=user_cash_back,
            tier2_user_referral_id=tier2_user_referral_id,
            tier2_commission=tier2_commission,
            tier3_user_referral_id=tier3_user_referral_id,
            tier3_commission=tier3_commission,
            tier4_user_referral_id=tier4_user_referral_id,
            tier4_commission=tier4_commission,
            tier5_user_referral_id=tier5_user_referral_id,
            tier5_commission=tier5_commission,
            tier2_business_user_referral_id=None,
            tier2_business_user_commission=0,
            tier3_business_user_referral_id=None,
            tier3_business_user_commission=0,
            tier4_business_user_referral_id=None,
            tier4_business_user_commission=0,
            tier5_business_user_referral_id=None,
            tier5_business_user_commission=0
        )
        db.session.add(user_trans)
        db.session.commit()

        summary = {
            "amount": f"{amount:.2f}",
            "user_cash_back": f"{user_cash_back:.2f}",
            "tier2_user_commission": f"{tier2_commission:.2f}" if u2 else "0.00",
            "tier3_user_commission": f"{tier3_commission:.2f}" if u3 else "0.00",
            "tier4_user_commission": f"{tier4_commission:.2f}" if u4 else "0.00",
            "tier5_user_commission": f"{tier5_commission:.2f}" if u5 else "0.00",
        }
        flash("User transaction finalized and all rewards/commissions assigned!", "success")

    return render_template(
        "finalize_transaction_user.html",
        interaction=interaction,
        now=now,
        summary=summary
    )

# BUSINESS — View/Edit Quote (business context)
@app.route("/session/<int:interaction_id>/quote", methods=["GET", "POST"])
@business_login_required
def create_quote(interaction_id):
    interaction = Interaction.query.get_or_404(interaction_id)
    is_biz = session.get('business_id') == interaction.business_id
    is_user = False
    if not is_biz:
        flash("Only the business can send or edit a quote for this session.")
        return redirect(url_for('biz_active_session', interaction_id=interaction_id))

    quote = Quote.query.filter_by(interaction_id=interaction.id).first()
    if request.method == "POST":
        amount = request.form.get("amount")
        details = request.form.get("details")
        if not amount or not details:
            flash("Amount and quote details are required.", "danger")
        else:
            if quote:
                quote.amount = amount
                quote.details = details
            else:
                quote = Quote(
                    interaction_id=interaction.id,
                    amount=amount,
                    details=details
                )
                db.session.add(quote)
            db.session.commit()
            flash("Quote sent to user!" if not quote else "Quote was updated!", "success")
            return redirect(url_for('biz_active_session', interaction_id=interaction_id))

    return render_template(
        "quote.html",
        interaction=interaction,
        quote=quote,
        is_user=is_user,
        is_biz=is_biz
    )

@app.route("/session/<int:interaction_id>/end", methods=["POST"])
def end_session(interaction_id):
    interaction = Interaction.query.get_or_404(interaction_id)
    # Allow both business and user to end the session
    is_user = current_user.is_authenticated and getattr(current_user, 'id', None) == interaction.user_id
    is_biz = session.get('business_id') == interaction.business_id
    if not (is_user or is_biz):
        abort(403)
    # End the session and hide from both dashboards
    interaction.status = "ended"
    db.session.commit()
    flash("Session ended.", "success")
    # Redirect to their respective dashboard
    if is_biz:
        return redirect(url_for('biz_user_interactions'))
    else:
        return redirect(url_for('user_biz_interactions'))

@app.route("/payment/<ref>")
def payment_qr_redirect(ref):
    user = User.query.filter_by(referral_code=ref).first()
    if not user:
        return "Invalid QR code.", 404
    if 'business_id' in session:
        interaction = get_interaction_for_business_and_user(
            business_id=session['business_id'],
            user_id=user.id
        )
        if interaction:
            return redirect(url_for('finalize_transaction', interaction_id=interaction.id))
        else:
            return "No active session found for this customer.", 404
    # This part runs if the QR was scanned by anyone who is NOT a logged-in business.
    return render_template("qr_user_landing.html", user=user)

from datetime import datetime

@app.route("/business/fund-account", methods=["GET", "POST"])
@business_login_required
def fund_account():
    biz_id = session.get('business_id')
    if not biz_id:
        return redirect(url_for('business_login'))
    biz = Business.query.get_or_404(biz_id)
    account_balance = biz.account_balance or 0.0

    # Temporary demo funding logic
    if request.method == "POST":
        amount = float(request.form.get("amount", 0))
        if amount > 0:
            biz.account_balance += amount
            db.session.commit()
            flash(f"Account funded: ${amount:.2f} added.", "success")
            return redirect(url_for('business_dashboard'))

    return render_template("fund_account.html", account_balance=account_balance)

@app.route("/business/finalize-transaction/<int:interaction_id>", methods=["GET", "POST"])
@business_login_required
def finalize_transaction(interaction_id):
    interaction = Interaction.query.get_or_404(interaction_id)
    if session.get('business_id') != interaction.business_id:
        abort(403)

    business = interaction.business
    now = datetime.now()
    summary = None

    def find_top_business_with_user_sponsor(biz):
        while biz and biz.sponsor_id:
            parent = Business.query.get(biz.sponsor_id)
            if parent:
                biz = parent
            else:
                break
        return biz

    if request.method == "POST":
        transaction_id = str(uuid.uuid4())
        data = request.form
        amount = float(data.get("amount", 0))

        # Calculate/cap ad fee now and block if business has insufficient funds
        ad_fee = min(round(amount * 0.10, 2), 250.00)
        if business.account_balance is None or business.account_balance < ad_fee:
            flash("Insufficient funds to complete this transaction. Please fund your account.")
            return redirect(url_for("fund_account"))

        # --- All your regular (user commission, business commission, etc.) logic follows here...
        user_referral_id = interaction.user.referral_code or "REFjoejmendez"
        user_cash_back_raw = amount * 0.02
        user_cash_back = round(min(user_cash_back_raw, 50), 2)

        u2 = User.query.filter_by(id=interaction.user.sponsor_id).first()
        tier2_user_referral_id = u2.referral_code if u2 else "REFjoejmendez"
        u3 = User.query.filter_by(id=u2.sponsor_id).first() if u2 and u2.sponsor_id else None
        tier3_user_referral_id = u3.referral_code if u3 else "REFjoejmendez"
        u4 = User.query.filter_by(id=u3.sponsor_id).first() if u3 and u3.sponsor_id else None
        tier4_user_referral_id = u4.referral_code if u4 else "REFjoejmendez"
        u5 = User.query.filter_by(id=u4.sponsor_id).first() if u4 and u4.sponsor_id else None
        tier5_user_referral_id = u5.referral_code if u5 else "REFjoejmendez"

        tier2_commission_raw = amount * 0.0025
        tier2_commission = round(min(tier2_commission_raw, 6.25), 2)
        tier3_commission_raw = amount * 0.0025
        tier3_commission = round(min(tier3_commission_raw, 6.25), 2)
        tier4_commission_raw = amount * 0.0025
        tier4_commission = round(min(tier4_commission_raw, 6.25), 2)
        tier5_commission_raw = amount * 0.02
        tier5_commission = round(min(tier5_commission_raw, 50), 2)

        top_biz = find_top_business_with_user_sponsor(business)
        root_user = User.query.get(top_biz.user_sponsor_id) if top_biz and top_biz.user_sponsor_id else None

        business_chain = []
        b = business
        while b:
            business_chain.insert(0, b)
            b = Business.query.get(b.sponsor_id) if b.sponsor_id else None
        downline_tier = len(business_chain)

        tier1_business_user_referral_id = None; tier1_business_user_commission = 0
        tier2_business_user_referral_id = None; tier2_business_user_commission = 0
        tier3_business_user_referral_id = None; tier3_business_user_commission = 0
        tier4_business_user_referral_id = None; tier4_business_user_commission = 0
        tier5_business_user_referral_id = None; tier5_business_user_commission = 0

        if root_user:
            if downline_tier == 1:
                tier1_business_user_referral_id = root_user.referral_code
                tier1_business_user_commission = round(min(amount * 0.01, 25), 2)
            elif downline_tier == 2:
                tier2_business_user_referral_id = root_user.referral_code
                tier2_business_user_commission = round(min(amount * 0.0025, 6.25), 2)
            elif downline_tier == 3:
                tier3_business_user_referral_id = root_user.referral_code
                tier3_business_user_commission = round(min(amount * 0.0025, 6.25), 2)
            elif downline_tier == 4:
                tier4_business_user_referral_id = root_user.referral_code
                tier4_business_user_commission = round(min(amount * 0.0025, 6.25), 2)
            elif downline_tier == 5:
                tier5_business_user_referral_id = root_user.referral_code
                tier5_business_user_commission = round(min(amount * 0.01, 25), 2)

        user_trans = UserTransaction(
            transaction_id=transaction_id,
            interaction_id=interaction.id,
            amount=amount,
            business_referral_id=business.referral_code,
            user_referral_id=user_referral_id,
            cash_back=user_cash_back,
            tier2_user_referral_id=tier2_user_referral_id,
            tier2_commission=tier2_commission,
            tier3_user_referral_id=tier3_user_referral_id,
            tier3_commission=tier3_commission,
            tier4_user_referral_id=tier4_user_referral_id,
            tier4_commission=tier4_commission,
            tier5_user_referral_id=tier5_user_referral_id,
            tier5_commission=tier5_commission,
            tier1_business_user_referral_id=tier1_business_user_referral_id,
            tier1_business_user_commission=tier1_business_user_commission,
            tier2_business_user_referral_id=tier2_business_user_referral_id,
            tier2_business_user_commission=tier2_business_user_commission,
            tier3_business_user_referral_id=tier3_business_user_referral_id,
            tier3_business_user_commission=tier3_business_user_commission,
            tier4_business_user_referral_id=tier4_business_user_referral_id,
            tier4_business_user_commission=tier4_business_user_commission,
            tier5_business_user_referral_id=tier5_business_user_referral_id,
            tier5_business_user_commission=tier5_business_user_commission
        )
        db.session.add(user_trans)

        # --- BUSINESS CHAIN PAYOUTS ---
        business_referral_id = business.referral_code or "BIZPerkMiner"
        b2 = Business.query.filter_by(id=business.sponsor_id).first()
        tier2_business_referral_id = b2.referral_code if b2 else "BIZPerkMiner"
        tier2_commission_biz = round(min(amount * 0.0025, 6.25), 2)
        b3 = Business.query.filter_by(id=b2.sponsor_id).first() if b2 and b2.sponsor_id else None
        tier3_business_referral_id = b3.referral_code if b3 else "BIZPerkMiner"
        tier3_commission_biz = round(min(amount * 0.0025, 6.25), 2)
        b4 = Business.query.filter_by(id=b3.sponsor_id).first() if b3 and b3.sponsor_id else None
        tier4_business_referral_id = b4.referral_code if b4 else "BIZPerkMiner"
        tier4_commission_biz = round(min(amount * 0.0025, 6.25), 2)
        b5 = Business.query.filter_by(id=b4.sponsor_id).first() if b4 and b4.sponsor_id else None
        tier5_business_referral_id = b5.referral_code if b5 else "BIZPerkMiner"
        tier5_commission_biz = round(min(amount * 0.01, 25), 2)

        business_cash_back_raw = amount * 0.01
        business_cash_back = round(min(business_cash_back_raw, 25), 2)

        # Deduct using capped ad fee, only if sufficient funds
        business.account_balance = (business.account_balance or 0.0) - ad_fee
        db.session.commit()

        business_trans = BusinessTransaction(
            transaction_id=transaction_id,
            interaction_id=interaction.id,
            amount=amount,
            ad_fee=ad_fee,
            business_referral_id=business_referral_id,
            cash_back=business_cash_back,
            tier2_business_referral_id=tier2_business_referral_id,
            tier2_commission=tier2_commission_biz,
            tier3_business_referral_id=tier3_business_referral_id,
            tier3_commission=tier3_commission_biz,
            tier4_business_referral_id=tier4_business_referral_id,
            tier4_commission=tier4_commission_biz,
            tier5_business_referral_id=tier5_business_referral_id,
            tier5_commission=tier5_commission_biz
        )
        db.session.add(business_trans)
        db.session.commit()

        summary = {
            "amount": f"{amount:.2f}",
            "user_cash_back": f"{user_cash_back:.2f}",
            "business_cash_back": f"{business_cash_back:.2f}",
            "ad_fee": f"{ad_fee:.2f}",
            "net_gross": f"{amount - ad_fee:,.2f}",
            "marketing_roi": int(((amount - ad_fee) / ad_fee) * 100) if ad_fee else 0,
            "marketing_ratio": round(((amount - ad_fee) + ad_fee) / ad_fee, 2) if ad_fee else 0,
            "transaction_id": transaction_id,
        }
        flash("Transaction finalized and all rewards/commissions assigned!", "success")

    return render_template(
        "finalize_transaction.html",
        interaction=interaction,
        now=now,
        summary=summary
    )

@app.route("/service-request/<int:biz_id>", methods=["GET", "POST"])
@login_required
def service_request(biz_id):
    biz = Business.query.get_or_404(biz_id)
    form = ServiceRequestForm()

    if form.validate_on_submit():
        # 1. Create the Interaction record
        interaction = Interaction(
            user_id=current_user.id,
            business_id=biz.id,
            service_type=form.service_type.data,
            details=form.details.data,
            budget_low=form.budget_low.data,
            budget_high=form.budget_high.data,
            status="active",
            referral_code=getattr(current_user, "referral_code", None)
        )
        db.session.add(interaction)
        db.session.commit()

        # 2. Send email to business
        interaction_link = url_for('biz_user_interactions', _external=True)
        subject = "Your business has been selected"
        body = f"""
        <p>You have been selected for a service request.</p>
        <ul>
          <li><strong>Service Type:</strong> {form.service_type.data}</li>
          <li><strong>Details:</strong> {form.details.data}</li>
          <li><strong>Budget:</strong> ${form.budget_low.data} - ${form.budget_high.data}</li>
          <li><strong>User Referral Code:</strong> {getattr(current_user, 'referral_code', '')}</li>
        </ul>
        <p>
          To view and manage the request, please 
          <a href="{interaction_link}">visit your business interaction dashboard</a>.
        </p>
        """
        send_email(biz.business_email, subject, body)

        # 3. Redirect user to their dashboard of active sessions
        return redirect(url_for('user_biz_interactions'))

    return render_template("service_request.html", form=form, biz=biz)

@app.route("/user/interactions")
@login_required
def user_biz_interactions():
    # Query all active interactions for this user
    interactions = Interaction.query.filter_by(user_id=current_user.id, status='active').order_by(Interaction.created_at.desc()).all()
    return render_template("user_biz_interactions.html", interactions=interactions)

@app.route("/session/<int:interaction_id>", methods=["GET", "POST"])
@login_required
def active_session(interaction_id):
    interaction = Interaction.query.get_or_404(interaction_id)
    is_user = interaction.user_id == getattr(current_user, 'id', None)
    is_biz = session.get('business_id') == interaction.business_id
    if not (is_user or is_biz):
        flash("Access denied.")
        if session.get('business_id'):
            return redirect(url_for('biz_user_interactions'))
        else:
            return redirect(url_for('user_biz_interactions'))

    if request.method == "POST":
        if is_user and request.form.get("accept_and_pay") == "1":
            interaction.awaiting_finalization = True
            db.session.commit()
            flash("Please show your QR code to the business to complete the payment.", "success")
            return redirect(url_for('active_session', interaction_id=interaction.id))

        text = request.form.get("message_text", "").strip()
        uploaded_file = request.files.get("message_file")
        file_url = None
        file_name = None

        if uploaded_file and uploaded_file.filename:
            filename = secure_filename(uploaded_file.filename)
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(upload_path)
            file_url = url_for('uploaded_file', filename=filename)
            file_name = uploaded_file.filename

        if text or file_url:
            if is_user:
                sender_type = "user"
                sender_id = current_user.id
            elif is_biz:
                sender_type = "business"
                sender_id = session['business_id']
            else:
                flash("Invalid sender.")
                return redirect(url_for('active_session', interaction_id=interaction_id))
            msg = Message(
                interaction_id=interaction.id,
                sender_type=sender_type,
                sender_id=sender_id,
                text=text,
                file_url=file_url,
                file_name=file_name
            )
            db.session.add(msg)
            db.session.commit()
            return redirect(url_for('active_session', interaction_id=interaction_id))

    messages = Message.query.filter_by(interaction_id=interaction.id).order_by(Message.timestamp).all()
    return render_template("active_session.html", interaction=interaction, is_user=is_user, is_biz=is_biz, messages=messages)

@app.route("/session/<int:interaction_id>/messages")
def session_messages(interaction_id):
    # Check for EITHER user or business session
    interaction = Interaction.query.get_or_404(interaction_id)
    is_user = False
    is_biz = False
    if 'business_id' in session and session['business_id'] == interaction.business_id:
        is_biz = True
    elif current_user.is_authenticated and getattr(current_user, 'id', None) == interaction.user_id:
        is_user = True
    if not (is_user or is_biz):
        return ""
    messages = Message.query.filter_by(interaction_id=interaction.id).order_by(Message.timestamp).all()
    return render_template("partials/_messages.html", interaction=interaction, messages=messages, is_user=is_user, is_biz=is_biz)

@app.route("/session/<int:interaction_id>/quote/view")
@business_login_required
def view_quote(interaction_id):
    interaction = Interaction.query.get_or_404(interaction_id)
    is_user = interaction.user_id == getattr(current_user, 'id', None)
    if not is_user:
        flash("Only the user may view the quote.")
        return redirect(url_for('active_session', interaction_id=interaction_id))
    quote = Quote.query.filter_by(interaction_id=interaction.id).first()
    return render_template("quote.html", interaction=interaction, quote=quote)

@app.route("/business/receipts")
@business_login_required
def business_receipts():
    biz_id = session.get('business_id')
    business = Business.query.get_or_404(biz_id)
    transactions = BusinessTransaction.query.filter_by(
        business_referral_id=business.referral_code
    ).order_by(BusinessTransaction.date_time.desc()).all()
    return render_template("business_receipts.html", transactions=transactions, business=business)

@app.route("/export_business_receipts_csv")
@business_login_required
def export_business_receipts_csv():
    biz_id = session.get('business_id')
    business = Business.query.get_or_404(biz_id)

    # Get transactions for this business (without filtering for commission)
    transactions = BusinessTransaction.query.filter_by(business_referral_id=business.referral_code).order_by(BusinessTransaction.date_time.desc()).all()

    import csv
    from io import StringIO
    si = StringIO()
    writer = csv.writer(si)

    # Header for business and Perk Miner
    writer.writerow([f"Invoices for '{business.business_name}' from Perk Miner"])
    writer.writerow([])

    # Table headers (should match what you show in business_receipts.html)
    writer.writerow([
        "Date/Time",
        "Interaction ID",
        "Sale Amount",
        "Ad Fee (10%, capped $250)",
        "Net Gross",
        "Marketing ROI",
        "Marketing ROI Ratio",
        "Cash Back"
    ])

    # Write each transaction (match values as in your HTML)
    for txn in transactions:
        ad_fee = txn.ad_fee or 0
        net_gross = txn.amount - ad_fee
        roi = (net_gross / ad_fee) * 100 if ad_fee else 0
        ratio = (net_gross + ad_fee) / ad_fee if ad_fee else 0

        writer.writerow([
            txn.date_time.strftime('%Y-%m-%d %I:%M %p'),
            txn.interaction_id,
            f"{txn.amount:,.2f}",
            f"{ad_fee:,.2f}",
            f"{net_gross:,.2f}",
            f"{roi:.0f}%",
            f"{ratio:.1f}:1",
            f"{txn.cash_back:,.2f}"
        ])

    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=business_receipts_{business.referral_code}.csv"}
    )

@app.route("/business/earnings", methods=["GET"])
@business_login_required
def business_earnings():
    biz_id = session.get('business_id')
    business = Business.query.get_or_404(biz_id)
    ref_code = business.referral_code

    period = request.args.get("period", "all")
    year = int(request.args.get("year", 0)) if request.args.get("year") else 0
    month = int(request.args.get("month", 0)) if request.args.get("month") else 0

    all_txns = BusinessTransaction.query

    # Date/month/year filter logic
    if period == "year" and year:
        all_txns = all_txns.filter(BusinessTransaction.date_time >= datetime(year, 1, 1), BusinessTransaction.date_time < datetime(year+1, 1, 1))
    elif period == "month" and year and month:
        start = datetime(year, month, 1)
        if month == 12:
            end = datetime(year+1, 1, 1)
        else:
            end = datetime(year, month+1, 1)
        all_txns = all_txns.filter(BusinessTransaction.date_time >= start, BusinessTransaction.date_time < end)
    transactions = all_txns.order_by(BusinessTransaction.date_time.desc()).all()

    # Only show transactions where this business EARNED cashback/commission
    filtered = []
    for t in transactions:
        earned = False
        if t.business_referral_id == ref_code and t.cash_back > 0:
            earned = True
        if t.tier2_business_referral_id == ref_code and t.tier2_commission > 0:
            earned = True
        if t.tier3_business_referral_id == ref_code and t.tier3_commission > 0:
            earned = True
        if t.tier4_business_referral_id == ref_code and t.tier4_commission > 0:
            earned = True
        if t.tier5_business_referral_id == ref_code and t.tier5_commission > 0:
            earned = True
        if earned:
            filtered.append(t)
    transactions = filtered

    # Stats/summary using the stored, capped ad_fee for each transaction
    tier1_txns = [txn for txn in transactions if txn.business_referral_id == ref_code]
    gross_earnings = sum(txn.amount for txn in tier1_txns)
    ad_fee = sum(txn.ad_fee or 0 for txn in tier1_txns)
    net_gross = sum(txn.amount - (txn.ad_fee or 0) for txn in tier1_txns)
    marketing_roi = int((net_gross / ad_fee) * 100) if ad_fee else 0
    marketing_ratio = round((net_gross + ad_fee) / ad_fee, 2) if ad_fee else 0

    tier1_earnings = sum(t.cash_back for t in transactions if t.business_referral_id == ref_code)
    tier2_earnings = sum(t.tier2_commission for t in transactions if t.tier2_business_referral_id == ref_code)
    tier3_earnings = sum(t.tier3_commission for t in transactions if t.tier3_business_referral_id == ref_code)
    tier4_earnings = sum(t.tier4_commission for t in transactions if t.tier4_business_referral_id == ref_code)
    tier5_earnings = sum(t.tier5_commission for t in transactions if t.tier5_business_referral_id == ref_code)
    total_cash_back = tier1_earnings + tier2_earnings + tier3_earnings + tier4_earnings + tier5_earnings

    summary = dict(
        gross_earnings=f"{gross_earnings:,.2f}",
        ad_fee=f"{ad_fee:,.2f}",
        net_gross=f"{net_gross:,.2f}",
        marketing_roi=marketing_roi,
        marketing_ratio=marketing_ratio,
        tier1_earnings=f"{tier1_earnings:,.2f}",
        tier2_earnings=f"{tier2_earnings:,.2f}",
        tier3_earnings=f"{tier3_earnings:,.2f}",
        tier4_earnings=f"{tier4_earnings:,.2f}",
        tier5_earnings=f"{tier5_earnings:,.2f}",
        total_cash_back=f"{total_cash_back:,.2f}",
        period=period,
        year=year,
        month=month
    )

    return render_template(
        "business_earnings.html",
        transactions=transactions,
        summary=summary,
        business=business,
        today=date.today(),
        period=period,
        year=year,
        month=month
    )

@app.route("/finance/business-detailed-report/export/csv")
@role_required("finance")
def export_business_combined_detail_report_csv():
    period = request.args.get("period", "all")
    year = int(request.args.get("year", 0)) if request.args.get("year") else 0
    month = int(request.args.get("month", 0)) if request.args.get("month") else 0
    interaction_id = request.args.get("interaction_id", "").strip()
    business_referral_id = request.args.get("business_referral_id", "").strip()
    business_email = (request.args.get("business_email", "") or "").strip().lower()

    bq = BusinessTransaction.query
    if period == "year" and year:
        bq = bq.filter(BusinessTransaction.date_time >= datetime(int(year), 1, 1), BusinessTransaction.date_time < datetime(int(year)+1, 1, 1))
    elif period == "month" and year and month:
        start = datetime(int(year), int(month), 1)
        if int(month) == 12:
            end = datetime(int(year)+1, 1, 1)
        else:
            end = datetime(int(year), int(month)+1, 1)
        bq = bq.filter(BusinessTransaction.date_time >= start, BusinessTransaction.date_time < end)
    if interaction_id:
        bq = bq.filter(BusinessTransaction.interaction_id == interaction_id)
    if business_referral_id:
        bq = bq.filter(
            (BusinessTransaction.business_referral_id == business_referral_id) |
            (BusinessTransaction.tier2_business_referral_id == business_referral_id) |
            (BusinessTransaction.tier3_business_referral_id == business_referral_id) |
            (BusinessTransaction.tier4_business_referral_id == business_referral_id) |
            (BusinessTransaction.tier5_business_referral_id == business_referral_id)
        )

    transactions = bq.all()
    business_lookup = {b.referral_code: b for b in Business.query.all()}
    if business_email:
        transactions = [t for t in transactions if t.business_referral_id in business_lookup and business_lookup[t.business_referral_id].business_email.lower() == business_email]

    import csv
    from io import StringIO
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow([
        "Date/Time", "Interaction ID", "Business Referral ID", "Business Name", "Business Email",
        "Tier 1 Cashback", "Tier 2 Cashback", "Tier 3 Cashback", "Tier 4 Cashback", "Tier 5 Cashback", "Transaction ID"
    ])
    for t in transactions:
        writer.writerow([
            t.date_time.strftime('%Y-%m-%d %I:%M %p'),
            t.interaction_id,
            t.business_referral_id,
            business_lookup[t.business_referral_id].business_name if t.business_referral_id in business_lookup else "",
            business_lookup[t.business_referral_id].business_email if t.business_referral_id in business_lookup else "",
            f"{t.cash_back:.2f}",
            f"{t.tier2_commission:.2f}",
            f"{t.tier3_commission:.2f}",
            f"{t.tier4_commission:.2f}",
            f"{t.tier5_commission:.2f}",
            t.transaction_id
        ])
    output = si.getvalue()
    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=business_combined_detail_report.csv"})

@app.route("/export_business_earnings_csv")
@business_login_required
def export_business_earnings_csv():
    biz_id = session.get('business_id')
    business = Business.query.get_or_404(biz_id)
    ref_code = business.referral_code

    # Get/replicate filters from business_earnings
    period = request.args.get("period", "all")
    year = int(request.args.get("year", 0)) if request.args.get("year") else 0
    month = int(request.args.get("month", 0)) if request.args.get("month") else 0
    all_txns = BusinessTransaction.query

    if period == "year" and year:
        all_txns = all_txns.filter(BusinessTransaction.date_time >= datetime(year, 1, 1), BusinessTransaction.date_time < datetime(year+1, 1, 1))
    elif period == "month" and year and month:
        start = datetime(year, month, 1)
        if month == 12:
            end = datetime(year+1, 1, 1)
        else:
            end = datetime(year, month+1, 1)
        all_txns = all_txns.filter(BusinessTransaction.date_time >= start, BusinessTransaction.date_time < end)
    transactions = all_txns.order_by(BusinessTransaction.date_time.desc()).all()

    # Filter as in your page
    filtered = []
    for t in transactions:
        earned = False
        if t.business_referral_id == ref_code and t.cash_back > 0:
            earned = True
        if t.tier2_business_referral_id == ref_code and t.tier2_commission > 0:
            earned = True
        if t.tier3_business_referral_id == ref_code and t.tier3_commission > 0:
            earned = True
        if t.tier4_business_referral_id == ref_code and t.tier4_commission > 0:
            earned = True
        if t.tier5_business_referral_id == ref_code and t.tier5_commission > 0:
            earned = True
        if earned:
            filtered.append(t)
    transactions = filtered

    # Prepare summary just like in your page (using only the filtered txns)
    tier1_txns = [txn for txn in transactions if txn.business_referral_id == ref_code]
    gross_earnings = sum(txn.amount for txn in tier1_txns)
    ad_fee = sum(txn.ad_fee or 0 for txn in tier1_txns)
    net_gross = sum(txn.amount - (txn.ad_fee or 0) for txn in tier1_txns)
    marketing_roi = int((net_gross / ad_fee) * 100) if ad_fee else 0
    marketing_ratio = round((net_gross + ad_fee) / ad_fee, 2) if ad_fee else 0

    tier1_earnings = sum(t.cash_back for t in transactions if t.business_referral_id == ref_code)
    tier2_earnings = sum(t.tier2_commission for t in transactions if t.tier2_business_referral_id == ref_code)
    tier3_earnings = sum(t.tier3_commission for t in transactions if t.tier3_business_referral_id == ref_code)
    tier4_earnings = sum(t.tier4_commission for t in transactions if t.tier4_business_referral_id == ref_code)
    tier5_earnings = sum(t.tier5_commission for t in transactions if t.tier5_business_referral_id == ref_code)
    total_cash_back = tier1_earnings + tier2_earnings + tier3_earnings + tier4_earnings + tier5_earnings

    # --- Prepare CSV ---
    import csv
    from io import StringIO
    si = StringIO()
    writer = csv.writer(si)

    # Add header for business and Perk Miner
    writer.writerow([f"Business summary for '{business.business_name}' from Perk Miner"])
    writer.writerow([])
    writer.writerow([f"Gross Sales (Tier1/Self):", f"${gross_earnings:,.2f}"])
    writer.writerow([f"Advertising Fee (10%, cap $250):", f"${ad_fee:,.2f}"])
    writer.writerow([f"Net Gross Sales:", f"${net_gross:,.2f}"])
    writer.writerow([f"Marketing ROI:", f"{marketing_roi}%"])
    writer.writerow([f"Marketing ROI Ratio:", f"{marketing_ratio}:1"])
    writer.writerow([])
    writer.writerow([f"Tier 1 (Self, 1% Cash Back):", f"${tier1_earnings:,.2f}"])
    writer.writerow([f"Tier 2 (B2B Commission):", f"${tier2_earnings:,.2f}"])
    writer.writerow([f"Tier 3 (B2B Commission):", f"${tier3_earnings:,.2f}"])
    writer.writerow([f"Tier 4 (B2B Commission):", f"${tier4_earnings:,.2f}"])
    writer.writerow([f"Tier 5 (B2B Commission):", f"${tier5_earnings:,.2f}"])
    writer.writerow([])
    writer.writerow([f"Total Cash Back (All Tiers):", f"${total_cash_back:,.2f}"])
    writer.writerow([])

    # Add detail table headers
    writer.writerow([
        "Date/Time",
        "Interaction ID",
        "Sale Amount",
        "Ad Fee (capped)",
        "Net Gross",
        "Marketing ROI",
        "Marketing ROI Ratio",
        "Tier 1 (1% Cash Back)",
        "Tier 2 (B2B Commission)",
        "Tier 3 (B2B Commission)",
        "Tier 4 (B2B Commission)",
        "Tier 5 (B2B Commission)",
    ])

    # Add details as in the HTML
    for txn in transactions:
        net_gross_row = txn.amount - (txn.ad_fee or 0)
        roi_row = (net_gross_row / (txn.ad_fee or 1)) * 100 if txn.ad_fee else 0
        ratio_row = (net_gross_row + (txn.ad_fee or 0)) / (txn.ad_fee or 1) if txn.ad_fee else 0
        writer.writerow([
            txn.date_time.strftime('%Y-%m-%d %I:%M %p'),
            txn.interaction_id,
            f"{txn.amount:,.2f}",
            f"{txn.ad_fee or 0:,.2f}",
            f"{net_gross_row:,.2f}",
            f"{roi_row:.0f}%",
            f"{ratio_row:.1f}:1",
            f"{txn.cash_back:,.2f}" if txn.business_referral_id == business.referral_code else "",
            f"{txn.tier2_commission:,.2f}" if txn.tier2_business_referral_id == business.referral_code else "",
            f"{txn.tier3_commission:,.2f}" if txn.tier3_business_referral_id == business.referral_code else "",
            f"{txn.tier4_commission:,.2f}" if txn.tier4_business_referral_id == business.referral_code else "",
            f"{txn.tier5_commission:,.2f}" if txn.tier5_business_referral_id == business.referral_code else "",
        ])

    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=business_earnings.csv"})

@app.route("/business/scan-qr/<int:interaction_id>")
@business_login_required
def scan_qr(interaction_id):
    # business protection, etc
    return render_template("scan_qr.html", interaction_id=interaction_id)

@app.route("/business/register", methods=["GET", "POST"])
def business_register():
    form = BusinessRegisterForm()
    # Populate referral_code field from ?ref= on GET (invite link)
    ref_code = request.args.get('ref')
    if request.method == "GET" and ref_code:
        form.referral_code.data = ref_code

    if form.validate_on_submit():
        business_name = form.business_name.data.strip()
        business_email = form.business_email.data.strip().lower()
        password = form.password.data
        referral_code = form.referral_code.data.strip()
        if not valid_password(password):
            flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
            return redirect(url_for("business_register"))
        if not valid_email(business_email):
            flash("Invalid email format.")
            return redirect(url_for("business_register"))
        if Business.query.filter_by(business_email=business_email).first():
            flash("Email already registered.")
            return redirect(url_for("business_register"))
        if Business.query.filter_by(business_name=business_name).first():
            flash("Business name already registered.")
            return redirect(url_for("business_register"))
        sponsor_id = None
        user_sponsor_id = None
        if referral_code:
            sponsor = Business.query.filter_by(referral_code=referral_code).first()
            if sponsor:
                sponsor_id = sponsor.id
            else:
                user_sponsor = User.query.filter_by(referral_code=referral_code).first()
                if user_sponsor:
                    user_sponsor_id = user_sponsor.id
                else:
                    flash("Invalid referral code.")
                    return redirect(url_for("business_register"))
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        biz_ref_code = random_business_code(business_name)
        email_code = random_email_code()
        new_biz = Business(
            business_name=business_name,
            business_email=business_email,
            password=hashed_pw,
            referral_code=biz_ref_code,
            sponsor_id=sponsor_id,
            user_sponsor_id=user_sponsor_id,
            email_confirmed=False,
            email_code=email_code,
        )
        db.session.add(new_biz)
        db.session.commit()
        send_business_verification_email(new_biz)
        session['pending_business_email'] = business_email
        session['last_business_verification_sent'] = time.time()
        return redirect(url_for("business_verify_email"))
    return render_template("business_register.html", form=form)

@app.route("/business/verify_email", methods=["GET", "POST"])
def business_verify_email():
    form = VerifyCodeForm()
    pending_email = session.get('pending_business_email')
    biz = Business.query.filter_by(business_email=pending_email).first() if pending_email else None
    can_resend = False
    wait_seconds = 0
    if not biz:
        flash("No registration found to verify.")
        return redirect(url_for("business_register"))
    if biz.email_confirmed:
        flash("Email is already confirmed, please log in.")
        return redirect(url_for("business_login"))
    now = time.time()
    last_sent = session.get('last_business_verification_sent', 0)
    if now - last_sent >= 30:
        can_resend = True
    else:
        wait_seconds = int(30 - (now - last_sent))
    if form.validate_on_submit():
        submitted_code = form.code.data.strip().upper()
        if submitted_code == biz.email_code:
            biz.email_confirmed = True
            db.session.commit()
            flash("Business email confirmed! You can now log in.")
            session.pop("pending_business_email", None)
            return redirect(url_for("business_login"))
        else:
            flash("Incorrect code.")
    return render_template("business_verify_email.html", form=form, can_resend=can_resend, wait_seconds=wait_seconds)

@app.route("/business/resend_verification", methods=["POST"])
def business_resend_verification():
    pending_email = session.get('pending_business_email')
    biz = Business.query.filter_by(business_email=pending_email).first() if pending_email else None
    if biz and not biz.email_confirmed:
        biz.email_code = random_email_code()
        db.session.commit()
        send_business_verification_email(biz)
        session['last_business_verification_sent'] = time.time()
        flash("Verification email resent.")
    return redirect(url_for("business_verify_email"))

@app.route("/business/activate/<code>")
def business_activate(code):
    biz = Business.query.filter_by(email_code=code).first()
    if biz:
        biz.email_confirmed = True
        db.session.commit()
        flash("Email confirmed! You can now log in as a business.")
        session.pop('pending_business_email', None)
        return redirect(url_for("business_login"))
    else:
        flash("Invalid or expired code.")
        return redirect(url_for("business_register"))

@app.route("/business/login", methods=["GET", "POST"])
def business_login():
    form = BusinessLoginForm()
    message = ""
    if form.validate_on_submit():
        business_email = form.business_email.data.strip().lower()
        password = form.password.data
        biz = Business.query.filter_by(business_email=business_email).first()
        if biz and bcrypt.check_password_hash(biz.password, password):
            if biz.is_suspended:
                flash('Account suspended, contact <a href="mailto:fromperkpay@gmail.com">support</a>.', 'danger')
                return redirect(url_for("business_login"))
            if not biz.email_confirmed:
                message = "Please confirm your business email first (check your inbox)."
                session['pending_business_email'] = business_email
                return redirect(url_for("business_verify_email"))
            else:
                # --- 2FA CODE ---
                code = str(random.randint(100000, 999999))
                session['pending_2fa_code'] = code
                session['pending_2fa_biz_id'] = biz.id
                send_email(
                    biz.business_email,
                    "Your PerkMiner Business Login Code",
                    f"<p>Your PerkMiner business login code is: <b>{code}</b></p>"
                )
                flash("A login code has been sent to your email.")
                return redirect(url_for("two_factor_biz"))
        else:
            message = "Login failed. Check business email and password."
    return render_template("business_login.html", message=message, form=form)

@app.route("/two_factor_biz", methods=["GET", "POST"])
def two_factor_biz():
    form = TwoFactorForm()
    if form.validate_on_submit():
        code_entered = form.code.data.strip()
        code_expected = session.get('pending_2fa_code')
        biz_id = session.get('pending_2fa_biz_id')
        if code_expected and code_entered == code_expected and biz_id:
            session['business_id'] = biz_id
            # Clean up session
            session.pop('pending_2fa_code', None)
            session.pop('pending_2fa_biz_id', None)
            flash("Login successful!")
            return redirect(url_for("business_dashboard"))
        flash("Incorrect code. Please try again.")
    return render_template("two_factor_biz.html", form=form)

@app.route('/business/forgot_password', methods=['GET', 'POST'])
def business_forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        business_email = form.email.data.strip().lower()
        biz = Business.query.filter_by(business_email=business_email).first()
        if biz:
            token = generate_reset_token(business_email, "biz")
            reset_url = url_for('business_reset_password', token=token, _external=True)
            send_reset_email(business_email, reset_url)
        flash("If a business account with that email exists, a link has been sent.")
        return redirect(url_for('business_login'))
    return render_template('forgot_password.html', form=form)

@app.route('/business/reset_password/<token>', methods=['GET', 'POST'])
def business_reset_password(token):
    email = verify_reset_token(token, "biz")
    if not email:
        flash("Reset link invalid or expired.")
        return redirect(url_for('business_login'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        biz = Business.query.filter_by(business_email=email).first()
        if biz:
            biz.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            db.session.commit()
            flash("Password reset. Please log in.")
            return redirect(url_for('business_login'))
        flash("Account not found.")
    return render_template('reset_password.html', form=form)

@app.route('/business/invite', methods=['POST'])
def business_invite():
    invite_form = BusinessInviteForm()
    biz_id = session.get('business_id')
    biz = Business.query.get(biz_id) if biz_id else None
    if not biz or not invite_form.validate_on_submit():
        flash("Business invite failed. Please log in and use a valid email.")
        return redirect(url_for("business_login"))
    invitee_email = invite_form.invitee_email.data.strip()
    subject = f"{biz.business_name} has invited you to join PerkMiner."
    reg_url = url_for('business_register', ref=biz.referral_code, _external=True)
    video_url = url_for('intro', ref=biz.referral_code, _external=True)
    html_body = build_invite_email(biz.business_name, reg_url, video_url)
    send_email(invitee_email, subject, html_body)
    flash('Business invitation sent!')
    return redirect(url_for('business_dashboard'))
    send_email(invitee_email, subject, html_body)
    flash('Business invitation sent!')
    return redirect(url_for('business_dashboard'))

@app.route("/business/interactions")
@business_login_required
def biz_user_interactions():
    # Make sure only a logged-in business can view this
    biz_id = session.get('business_id')
    if not biz_id:
        flash("You must be logged in as a business.")
        return redirect(url_for('business_login'))
    interactions = Interaction.query.filter_by(business_id=biz_id, status='active').order_by(Interaction.created_at.desc()).all()
    return render_template("biz_user_interactions.html", interactions=interactions)

@app.route("/business/interactions/<int:interaction_id>/details")
@business_login_required
def biz_interaction_details(interaction_id):
    biz_id = session.get('business_id')
    if not biz_id:
        flash("You must be logged in as a business.")
        return redirect(url_for('business_login'))
    interaction = Interaction.query.get_or_404(interaction_id)
    # Security: make sure this belongs to the logged-in business!
    if interaction.business_id != biz_id:
        flash("Access denied.")
        return redirect(url_for('biz_user_interactions'))
    return render_template("biz_request_details.html", interaction=interaction)

@app.route("/business/session/<int:interaction_id>", methods=["GET", "POST"])
@business_login_required
def biz_active_session(interaction_id):
    biz_id = session.get('business_id')
    if not biz_id:
        flash("You must be logged in as a business.")
        return redirect(url_for('business_login'))
    interaction = Interaction.query.get_or_404(interaction_id)
    if interaction.business_id != biz_id:
        flash("Access denied.")
        return redirect(url_for('biz_user_interactions'))

    # Detect this as a business view
    is_user = False
    is_biz = True

    # Support POST (sending messages) if you want chat from business side too
    if request.method == "POST":
        text = request.form.get("message_text", "").strip()
        uploaded_file = request.files.get("message_file")
        file_url = None
        file_name = None
        if uploaded_file and uploaded_file.filename:
            filename = secure_filename(uploaded_file.filename)
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(upload_path)
            file_url = url_for('uploaded_file', filename=filename)
            file_name = uploaded_file.filename
        if text or file_url:
            msg = Message(
                interaction_id=interaction.id,
                sender_type="business",
                sender_id=biz_id,
                text=text,
                file_url=file_url,
                file_name=file_name
            )
            db.session.add(msg)
            db.session.commit()
            return redirect(url_for('biz_active_session', interaction_id=interaction.id))

    messages = Message.query.filter_by(interaction_id=interaction.id).order_by(Message.timestamp).all()
    # Render the same template you use for users
    return render_template(
        "active_session.html",
        interaction=interaction,
        is_user=is_user,
        is_biz=is_biz,
        messages=messages
    )

@app.route("/business/dashboard", methods=["GET", "POST"])
def business_dashboard():
    form = BusinessRewardForm(request.form)
    profile_form = BusinessProfileForm()
    invite_form = BusinessInviteForm()
    biz_id = session.get('business_id')
    biz = Business.query.get(biz_id) if biz_id else None

    if not biz or not biz.email_confirmed:
        flash("Please log in and confirm your business email to access the dashboard.")
        return redirect(url_for("business_login"))

    editable_fields = [
        "business_name", "listing_type", "category", "phone_number", "address", "latitude", "longitude",
        "website_url", "about_us", "hours_of_operation", "search_keywords",
        "service_1", "service_2", "service_3", "service_4", "service_5",
        "service_6", "service_7", "service_8", "service_9", "service_10"
    ]

    def get_service_field(n):
        return request.form.get(f"service_{n}", "")

    def safe_float(val):
        try:
            return float(val)
        except (TypeError, ValueError):
            return None

    # POST: Handle profile save
    if request.method == "POST":
        updated = False
        if not request.form.get("listing_type"):
            flash("Listing Type is required.")
            return redirect(url_for('business_dashboard'))

        if biz.status == "approved":
            for field in editable_fields:
                val = request.form.get(field)
                # Fix for latitude/longitude fields:
                if field in ["latitude", "longitude"]:
                    setattr(biz, f"draft_{field}", safe_float(val))
                    updated = True
                else:
                    if val is not None:
                        setattr(biz, f"draft_{field}", val)
                        updated = True
            file = request.files.get('profile_photo')
            if file and allowed_file(file.filename):
                upload_result = cloudinary.uploader.upload(file)
                biz.draft_profile_photo = upload_result.get('secure_url')
                updated = True
        else:
            for field in editable_fields:
                val = request.form.get(field)
                if field in ["latitude", "longitude"]:
                    setattr(biz, field, safe_float(val))
                    updated = True
                else:
                    if val is not None:
                        setattr(biz, field, val)
                        updated = True
            file = request.files.get('profile_photo')
            if file and allowed_file(file.filename):
                upload_result = cloudinary.uploader.upload(file)
                biz.profile_photo = upload_result.get('secure_url')
                updated = True

        if updated:
            db.session.commit()
            flash("Business profile updated!")
        return redirect(url_for('business_dashboard'))

    # GET: Load profile form data (prefer draft if status=approved and draft exists)
    form_data = {}
    for field in editable_fields:
        draft_field = f"draft_{field}"
        val = getattr(biz, draft_field, None) if biz.status == "approved" else None
        if val not in [None, ""]:
            form_data[field] = val
        else:
            form_data[field] = getattr(biz, field, "")

    # Profile photo logic (show draft if exists, otherwise live)
    if hasattr(biz, "draft_profile_photo") and biz.status == "approved" and biz.draft_profile_photo:
        profile_img_url = biz.draft_profile_photo
    else:
        profile_img_url = biz.profile_photo if biz.profile_photo else None

    latitude = form_data.get("latitude", "")
    longitude = form_data.get("longitude", "")

    # --- Rewards and referral tree logic (leave unchanged) ---
    if request.method == "GET":
        form.downline_level.data = '1'
        form.invoice_amount.data = 0
    rewards_table = ""; reward = None
    invoice_amount = float(form.invoice_amount.data or 0)
    downline_level = int(form.downline_level.data or 1)
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
            reward = invoice_amount * 0.01
            rewards_desc = "As the business, for an invoice you create and get paid for in the amount"
            cap = None
        elif downline_level in [2, 3, 4]:
            rate = 0.002
            cap = 3.75
            reward = min(invoice_amount * rate, cap)
            rewards_desc = f"If a Tier {downline_level} business creates and gets paid for an invoice in the amount"
        elif downline_level == 5:
            rate = 0.02
            cap = 25
            reward = min(invoice_amount * rate, cap)
            rewards_desc = "If a Tier 5 business creates and gets paid for an invoice in the amount"
        else:
            reward = 0
            rewards_desc = ""
    if invoice_amount > 0 and reward is not None:
        if cap:
            rewards_table += f"<h5 class='mt-4 mb-2'>{rewards_desc} of ${invoice_amount:,.2f}:</h5>"
            rewards_table += f"<div class='alert alert-success'>Your business earns <strong>${reward:.2f}</strong> as cashback (capped at ${cap:.2f}).</div>"
        else:
            rewards_table += f"<h5 class='mt-4 mb-2'>{rewards_desc} of ${invoice_amount:,.2f}:</h5>"
            rewards_table += f"<div class='alert alert-success'>Your business earns <strong>${reward:.2f}</strong> as cashback.</div>"

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

    # Add active session indicator for dashboard button
    active_biz_sessions = Interaction.query.filter_by(business_id=biz.id, status='active').all()
    has_active_biz_sessions = len(active_biz_sessions) > 0

    # Add this line to fetch payment alerts/awaiting payments
    payment_alerts = Interaction.query.filter_by(
        business_id=biz.id,
        awaiting_payment=True,
        status='active'
    ).all()

    return render_template(
        "business_dashboard.html",
        form=form,
        profile_form=profile_form,
        invite_form=invite_form,
        biz=biz,
        payment_alerts=payment_alerts,  # <-- This line passes to template
        form_data=form_data,
        sponsor=sponsor,
        referral_code=biz.referral_code,
        rewards_table=rewards_table,
        level2=level2, level3=level3, level4=level4, level5=level5,
        profile_img_url=profile_img_url,
        phone_number=form_data.get("phone_number",""),
        address=form_data.get("address",""),
        latitude=latitude,
        longitude=longitude,
        has_active_biz_sessions=has_active_biz_sessions  # pass to template
    )

@app.route("/business/logout")
def business_logout():
    session.pop('business_id', None)
    flash("Logged out as business.")
    return redirect(url_for("business_home"))

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    form = LoginForm()
    message = ""
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            # Require that this user has a super_admin role
            if user.roles and any(r.name == "super_admin" for r in user.roles):
                # 2FA logic starts here
                code = str(random.randint(100000, 999999))
                session['pending_2fa_code'] = code
                session['pending_2fa_admin_id'] = user.id
                send_email(
                    user.email,
                    "Your PerkMiner Admin Login Code",
                    f"<p>Your PerkMiner admin login code is: <b>{code}</b></p>"
                )
                flash("A login code has been sent to your admin email.")
                return redirect(url_for("two_factor_admin"))
            else:
                message = "You are not an admin."
        else:
            message = "Login failed. Check email and password."
    return render_template("admin_login.html", message=message, form=form)

@app.route("/two_factor_admin", methods=["GET", "POST"])
def two_factor_admin():
    form = TwoFactorForm()
    if form.validate_on_submit():
        code_entered = form.code.data.strip()
        code_expected = session.get('pending_2fa_code')
        admin_id = session.get('pending_2fa_admin_id')
        if code_expected and code_entered == code_expected and admin_id:
            user = User.query.get(admin_id)
            if user:
                login_user(user)
                # Clean up session
                session.pop('pending_2fa_code', None)
                session.pop('pending_2fa_admin_id', None)
                flash("Admin login successful!")
                return redirect(url_for("admin_dashboard"))
        flash("Incorrect code. Please try again.")
    return render_template("two_factor_admin.html", form=form)

@app.route('/admin/forgot_password', methods=['GET', 'POST'])
def admin_forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()
        # Only send if super_admin
        if user and user.roles and any(r.name == "super_admin" for r in user.roles):
            token = generate_reset_token(email, "admin")
            reset_url = url_for('admin_reset_password', token=token, _external=True)
            send_reset_email(email, reset_url)
        flash("If an admin account with that email exists, a link has been sent.")
        return redirect(url_for('admin_login'))
    return render_template('forgot_password.html', form=form)

@app.route('/admin/reset_password/<token>', methods=['GET', 'POST'])
def admin_reset_password(token):
    email = verify_reset_token(token, "admin")
    if not email:
        flash("Reset link invalid or expired.")
        return redirect(url_for('admin_login'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if user and user.roles and any(r.name == "super_admin" for r in user.roles):
            user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            db.session.commit()
            flash("Password reset. Please log in.")
            return redirect(url_for('admin_login'))
        flash("Admin account not found.")
    return render_template('reset_password.html', form=form)

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    users = User.query.all()
    businesses = Business.query.all()
    EmptyFormInstance = EmptyForm  # Alias if you prefer

    # Create a form instance for each business (by id)
    business_forms = {biz.id: EmptyFormInstance() for biz in businesses}
    return render_template(
        "admin_dashboard.html",
        users=users,
        businesses=businesses,
        business_forms=business_forms
    )

@app.route("/finance-dashboard", methods=["GET"])
@role_required("finance")  # or your finance admin decorator
def finance_dashboard():
    period = request.args.get("period", "all")
    year = int(request.args.get("year", 0)) if request.args.get("year") else 0
    month = int(request.args.get("month", 0)) if request.args.get("month") else 0

    bqry = BusinessTransaction.query
    uqry = UserTransaction.query
    if period == "year" and year:
        bqry = bqry.filter(BusinessTransaction.date_time >= datetime(year, 1, 1), BusinessTransaction.date_time < datetime(year+1, 1, 1))
        uqry = uqry.filter(UserTransaction.date_time >= datetime(year, 1, 1), UserTransaction.date_time < datetime(year+1, 1, 1))
    elif period == "month" and year and month:
        start = datetime(year, month, 1)
        if month == 12:
            end = datetime(year+1, 1, 1)
        else:
            end = datetime(year, month+1, 1)
        bqry = bqry.filter(BusinessTransaction.date_time >= start, BusinessTransaction.date_time < end)
        uqry = uqry.filter(UserTransaction.date_time >= start, UserTransaction.date_time < end)

    btxns = bqry.all()
    utxns = uqry.all()

    total_ad_revenue = sum(min(t.amount * 0.10, 250) for t in btxns)
    total_transactions = len(btxns)

    # Add in ALL user-business commissions in total_paid_members
    total_paid_members = sum(
        (t.cash_back or 0)
        + (t.tier2_commission or 0)
        + (t.tier3_commission or 0)
        + (t.tier4_commission or 0)
        + (t.tier5_commission or 0)
        + (t.tier1_business_user_commission or 0)
        + (t.tier2_business_user_commission or 0)
        + (t.tier3_business_user_commission or 0)
        + (t.tier4_business_user_commission or 0)
        + (t.tier5_business_user_commission or 0)
        for t in utxns
    )

    # Correct logic for business payouts and capital reserves
    total_paid_businesses = 0.0
    capital_reserves = 0.0
    for t in btxns:
        if t.business_referral_id != "BIZPerkMiner":
            total_paid_businesses += t.cash_back
        else:
            capital_reserves += t.cash_back
        if t.tier2_business_referral_id != "BIZPerkMiner":
            total_paid_businesses += t.tier2_commission
        else:
            capital_reserves += t.tier2_commission
        if t.tier3_business_referral_id != "BIZPerkMiner":
            total_paid_businesses += t.tier3_commission
        else:
            capital_reserves += t.tier3_commission
        if t.tier4_business_referral_id != "BIZPerkMiner":
            total_paid_businesses += t.tier4_commission
        else:
            capital_reserves += t.tier4_commission
        if t.tier5_business_referral_id != "BIZPerkMiner":
            total_paid_businesses += t.tier5_commission
        else:
            capital_reserves += t.tier5_commission

    # Charitable Contributions
    charitable_contribution = total_ad_revenue * 0.105

    # Net Gross
    net_gross = total_ad_revenue - (total_paid_members + total_paid_businesses + capital_reserves + charitable_contribution)

    # Allocations
    operating_capital = net_gross * 0.60 
    silent_partners = net_gross * 0.30
    legal_services = net_gross * 0.07
    miscellaneous = net_gross * 0.03

    # Operating Capital breakdown
    real_estate_utilities = operating_capital * 0.30
    employees = operating_capital * 0.40
    webapp_fees = operating_capital * 0.15
    misc_services = operating_capital * 0.15

    # Silent Partners breakdown (with per-partner cap)
    tito = min(silent_partners * 0.4525, 5000000)
    pedro = min(silent_partners * 0.1725, 1000000)
    paul_tara = min(silent_partners * 0.0875, 500000)
    james = min(silent_partners * 0.045, 250000)
    angel = min(silent_partners * 0.0275, 150000)
    josh = min(silent_partners * 0.0275, 150000)
    diego = min(silent_partners * 0.0175, 100000)
    esther = min(silent_partners * 0.0175, 100000)
    reyna = min(silent_partners * 0.0175, 100000)
    ramico = min(silent_partners * 0.0175, 100000)
    michael = min(silent_partners * 0.0175, 100000)
    manuela = min(silent_partners * 0.0175, 100000)
    alex = min(silent_partners * 0.0175, 100000)
    victor_r = min(silent_partners * 0.0175, 100000)
    john_paul = min(silent_partners * 0.0175, 100000)
    ana_pepe = min(silent_partners * 0.01, 50000)
    karen = min(silent_partners * 0.01, 50000)
    raul = min(silent_partners * 0.01, 50000)

    summary = dict(
        total_ad_revenue=f"{total_ad_revenue:,.2f}",
        total_transactions=total_transactions,
        total_paid_members=f"{total_paid_members:,.2f}",
        total_paid_businesses=f"{total_paid_businesses:,.2f}",
        net_gross=f"{net_gross:,.2f}",
        capital_reserves=f"{capital_reserves:,.2f}",
        operating_capital=f"{operating_capital:,.2f}",
        charitable_contribution=f"{charitable_contribution:,.2f}",
        silent_partners=f"{silent_partners:,.2f}",
        legal_services=f"{legal_services:,.2f}",
        miscellaneous=f"{miscellaneous:,.2f}",
        real_estate_utilities=f"{real_estate_utilities:,.2f}",
        employees=f"{employees:,.2f}",
        webapp_fees=f"{webapp_fees:,.2f}",
        misc_services=f"{misc_services:,.2f}",
        tito=f"{tito:,.2f}",
        pedro=f"{pedro:,.2f}",
        paul_tara=f"{paul_tara:,.2f}",
        james=f"{james:,.2f}",
        angel=f"{angel:,.2f}",
        josh=f"{josh:,.2f}",
        diego=f"{diego:,.2f}",
        esther=f"{esther:,.2f}",
        reyna=f"{reyna:,.2f}",
        ramico=f"{ramico:,.2f}",
        michael=f"{michael:,.2f}",
        manuela=f"{manuela:,.2f}",
        alex=f"{alex:,.2f}",
        victor_r=f"{victor_r:,.2f}",
        john_paul=f"{john_paul:,.2f}",
        ana_pepe=f"{ana_pepe:,.2f}",
        karen=f"{karen:,.2f}",
        raul=f"{raul:,.2f}",
        period=period,
        year=year,
        month=month
    )

    return render_template(
        "finance_dashboard.html",
        summary=summary,
        period=period,
        year=year,
        month=month
    )

@app.route("/approve-reject-dashboard")
@role_required("approve_reject_listings")
def approve_reject_dashboard():
    # Query all pending or in_review businesses
    pending_listings = Business.query.filter(Business.status.in_(["pending", "in_review"])).all()
    return render_template("approve_reject_dashboard.html", pending_listings=pending_listings)

@app.route("/feedback-dashboard")
@role_required("feedback_moderation")
def feedback_dashboard():
    return render_template("feedback_dashboard.html")

@app.route("/support-dashboard")
@role_required("customer_support")
def support_dashboard():
    return render_template("support_dashboard.html")

@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if any(r.name == 'super_admin' for r in user.roles):
        flash("Cannot delete a super_admin user.")
        return redirect(url_for("admin_dashboard"))
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.email} deleted.")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/user/<int:user_id>/suspend", methods=["POST"])
@admin_required
def admin_suspend_user(user_id):
    user = User.query.get_or_404(user_id)
    if any(r.name == 'super_admin' for r in user.roles):
        flash("Cannot suspend a super_admin user.")
        return redirect(url_for("admin_dashboard"))
    user.is_suspended = not user.is_suspended
    db.session.commit()
    action = "Suspended" if user.is_suspended else "Unsuspended"
    flash(f"User {user.email} {action.lower()}.")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/listing/<int:listing_id>/start_review", methods=["POST"])
@role_required("approve_reject_listings")
def start_review(listing_id):
    biz = Business.query.get_or_404(listing_id)
    if biz.status == "pending":
        biz.status = "in_review"
        db.session.commit()
        flash(f"Listing {biz.business_name} is now in review.")
    return redirect(url_for("approve_reject_dashboard"))

@app.route("/admin/listing/<int:listing_id>/approve", methods=["POST"])
@role_required("approve_reject_listings")
def approve_listing(listing_id):
    biz = Business.query.get_or_404(listing_id)
    if biz.status in ["pending", "in_review", "approved"]:
        # Promote all draft fields to live fields if they exist
        promote_fields = [
            "business_name", "listing_type", "category", "phone_number", "address", "latitude", "longitude",
            "website_url", "about_us", "hours_of_operation", "search_keywords",
            "service_1", "service_2", "service_3", "service_4", "service_5",
            "service_6", "service_7", "service_8", "service_9", "service_10",
            "profile_photo"
        ]
        changed = False
        # Print draft and live before promoting
        print("Before promotion:")
        print("DRAFT listing_type:", getattr(biz, "draft_listing_type", "MISSING"))
        print("LIVE listing_type:", getattr(biz, "listing_type", "MISSING"))

        for field in promote_fields:
            draft_attr = f"draft_{field}"
            draft_value = getattr(biz, draft_attr, None)
            print(f"Promoting field: {field}, draft value: {draft_value}")
            if draft_value not in [None, ""]:
                setattr(biz, field, draft_value)
                setattr(biz, draft_attr, None)
                print(f"--> Promoted {field} and cleared {draft_attr}")
                changed = True

        # Print draft and live after promoting
        print("After promotion:")
        print("DRAFT listing_type:", getattr(biz, "draft_listing_type", "MISSING"))
        print("LIVE listing_type:", getattr(biz, "listing_type", "MISSING"))

        biz.status = "approved"
        db.session.commit()
        flash(f"Listing {biz.business_name} approved!" + (" Draft changes promoted." if changed else ""))
    return redirect(url_for("approve_reject_dashboard"))

@app.route("/admin/listing/<int:listing_id>/reject", methods=["POST"])
@role_required("approve_reject_listings")
def reject_listing(listing_id):
    biz = Business.query.get_or_404(listing_id)
    if biz.status in ["pending", "in_review"]:
        biz.status = "rejected"
        db.session.commit()
        flash(f"Listing {biz.business_name} rejected.")
    return redirect(url_for("approve_reject_dashboard"))

@app.route("/admin/assign-roles", methods=["GET", "POST"])
@role_required("super_admin")
def assign_roles():
    users = User.query.all()
    roles = Role.query.all()

    if request.method == "POST":
        # Get the form data (user_id and roles to assign)
        user_id = int(request.form["user_id"])
        chosen_roles = request.form.getlist("roles")

        user = User.query.get(user_id)
        if user:
            # Remove all roles, then add selected ones
            user.roles = []
            for role_name in chosen_roles:
                role = Role.query.filter_by(name=role_name).first()
                if role:
                    user.roles.append(role)
            db.session.commit()
            flash("Roles updated!", "success")

@app.route("/listing-disclaimer", methods=["GET", "POST"])
@business_login_required
def listing_disclaimer():
    biz_id = session.get('business_id')
    biz = Business.query.get_or_404(biz_id)

    if request.method == 'POST':
        listing_id = request.form.get("listing_id")
        referral_code = request.form.get("referral_code")
        accept_terms = request.form.get("accept_terms")
        # (You may want to check accept_terms here if using POST to capture consent.)
        if not accept_terms:
            flash("You must accept the terms and conditions.")
            return render_template(
                "listing_disclaimer.html",
                listing_id=listing_id,
                referral_code=referral_code,
                biz=biz
            )
        return redirect(url_for('send_for_review'))

    # GET (or POST fallback): pull from form or args
    listing_id = request.args.get("listing_id") or request.form.get("listing_id")
    referral_code = request.args.get("referral_code") or request.form.get("referral_code")

    return render_template(
        "listing_disclaimer.html",
        listing_id=listing_id,
        referral_code=referral_code,
        biz=biz
    )

@app.route("/send-for-review", methods=["POST"])
@business_login_required
def send_for_review():
    biz_id = session.get('business_id')
    biz = Business.query.get_or_404(biz_id)

    # Always fetch these from the form FIRST
    listing_id = request.form.get("listing_id") or request.args.get("listing_id")
    referral_code = request.form.get("referral_code") or request.args.get("referral_code")

    # Check: redirect if account balance is less than $1
    if biz.account_balance is None or biz.account_balance < 1:
        flash("You must have an account balance of at least $1 to submit your listing. Please fund your account.")
        return redirect(url_for("fund_account"))

    accept_terms = request.form.get("accept_terms")
    if not accept_terms:
        flash("You must accept the terms and conditions.")
        return render_template(
            "listing_disclaimer.html",
            listing_id=listing_id,
            referral_code=referral_code,
            biz=biz
        )

    # Only require/upload a doc if it hasn't been uploaded yet (first submission)
    if not biz.business_registration_doc:
        file = request.files.get("business_registration_doc")
        if not file or file.filename == '':
            flash("Business registration document is required.")
            return render_template(
                "listing_disclaimer.html",
                listing_id=listing_id,
                referral_code=referral_code,
                biz=biz
            )
        # Save the file securely
        filename = secure_filename(file.filename)
        upload_folder = app.config.get("UPLOAD_FOLDER", "uploads")
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        filepath = os.path.join(upload_folder, filename)
        file.save(filepath)
        biz.business_registration_doc = filename

    # Mark as pending and commit
    listing = Business.query.get(listing_id)
    if listing:
        listing.status = "pending"
        db.session.commit()
        flash("Listing submitted for admin review. You will be notified after a decision.")
    else:
        flash("Listing not found.")

    return redirect(url_for("business_dashboard"))

@app.route("/admin/user/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = EditUserForm(obj=user)
    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data
        db.session.commit()
        flash("User updated.")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_edit_user.html", user=user, form=form)

@app.route("/admin/business/<int:business_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_business(business_id):
    biz = Business.query.get_or_404(business_id)
    form = BusinessEditForm(obj=biz)
    if form.validate_on_submit():
        biz.business_name = form.business_name.data
        biz.business_email = form.business_email.data
        biz.listing_type = form.listing_type.data
        biz.category = form.category.data
        biz.phone_number = form.phone_number.data
        biz.address = form.address.data
        db.session.commit()
        flash("Business updated.")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_edit_business.html", biz=biz, form=form)

@app.route("/admin/business/<int:business_id>/suspend", methods=["POST"])
@admin_required
def admin_suspend_business(business_id):
    biz = Business.query.get_or_404(business_id)
    biz.is_suspended = not biz.is_suspended
    db.session.commit()
    action = "Suspended" if biz.is_suspended else "Unsuspended"
    flash(f"Business {biz.business_name} {action.lower()}.")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/business/<int:business_id>/delete", methods=["POST"])
@admin_required
def admin_delete_business(business_id):
    biz = Business.query.get_or_404(business_id)
    db.session.delete(biz)
    db.session.commit()
    flash(f"Business {biz.business_name} deleted.")
    return redirect(url_for("admin_dashboard"))

from flask_login import login_required

@app.route("/listing/<int:biz_id>")
@login_required
def view_listing(biz_id):
    biz = Business.query.get_or_404(biz_id)
    return render_template("large_listing.html", biz=biz)

@app.route("/finance/combined-detailed-report", methods=["GET"])
@role_required("finance")
def combined_detailed_report():
    interaction_id = request.args.get("interaction_id", "").strip()
    user_email = (request.args.get("user_email", "") or "").strip().lower()
    business_email = (request.args.get("business_email", "") or "").strip().lower()
    period = request.args.get("period", "all")
    year = request.args.get("year", "")
    month = request.args.get("month", "")

    uq = UserTransaction.query
    bq = BusinessTransaction.query

    # Date/month/year filter logic
    if period == "year" and year:
        uq = uq.filter(UserTransaction.date_time >= datetime(int(year), 1, 1), UserTransaction.date_time < datetime(int(year)+1, 1, 1))
        bq = bq.filter(BusinessTransaction.date_time >= datetime(int(year), 1, 1), BusinessTransaction.date_time < datetime(int(year)+1, 1, 1))
    elif period == "month" and year and month:
        start = datetime(int(year), int(month), 1)
        if int(month) == 12:
            end = datetime(int(year)+1, 1, 1)
        else:
            end = datetime(int(year), int(month)+1, 1)
        uq = uq.filter(UserTransaction.date_time >= start, UserTransaction.date_time < end)
        bq = bq.filter(BusinessTransaction.date_time >= start, BusinessTransaction.date_time < end)

    # Interaction ID filtering
    if interaction_id:
        uq = uq.filter(UserTransaction.interaction_id == interaction_id)
        bq = bq.filter(BusinessTransaction.interaction_id == interaction_id)

    user_lookup = {u.referral_code: u for u in User.query.all()}
    business_lookup = {b.referral_code: b for b in Business.query.all()}

    # User email filter: only user transactions
    if user_email:
        utrans = [t for t in uq.all() if t.user_referral_id in user_lookup and user_lookup[t.user_referral_id].email.lower() == user_email]
        btrans = []
    # Business email filter: only business transactions
    elif business_email:
        btrans = [t for t in bq.all() if t.business_referral_id in business_lookup and business_lookup[t.business_referral_id].business_email.lower() == business_email]
        utrans = []
    else:
        utrans = uq.all()
        btrans = bq.all()

    # Grand/summaries (from business table only)
    grand_total = sum(t.amount for t in btrans)
    total_ad_fee = sum(min(t.amount * 0.10, 250) for t in btrans)
    total_user_cash_back = sum(t.cash_back for t in utrans)
    total_user_commission = sum(
        (t.tier2_commission or 0) + (t.tier3_commission or 0) + (t.tier4_commission or 0) + (t.tier5_commission or 0)
        for t in utrans
    )
    # User-Business commissions summary (new field!)
    total_user_business_commission = sum(
        (t.tier1_business_user_commission or 0) +
        (t.tier2_business_user_commission or 0) +
        (t.tier3_business_user_commission or 0) +
        (t.tier4_business_user_commission or 0) +
        (t.tier5_business_user_commission or 0)
        for t in utrans
    )
    total_biz_cash_back = sum(
        t.cash_back + (t.tier2_commission or 0) + (t.tier3_commission or 0) + (t.tier4_commission or 0) + (t.tier5_commission or 0)
        for t in btrans
    )
    total_paid_all = total_user_cash_back + total_user_commission + total_user_business_commission + total_biz_cash_back

    return render_template(
        "combined_detailed_report.html",
        utrans=utrans,
        btrans=btrans,
        user_lookup=user_lookup,
        business_lookup=business_lookup,
        grand_total=grand_total,
        total_ad_fee=total_ad_fee,
        total_user_cash_back=total_user_cash_back,
        total_user_commission=total_user_commission,
        total_user_business_commission=total_user_business_commission,
        total_biz_cash_back=total_biz_cash_back,
        total_paid_all=total_paid_all,
        period=period,
        year=year,
        month=month,
        interaction_id=interaction_id,
        user_email=user_email,
        business_email=business_email,
        months=[(f"{i}", datetime(2026, i, 1).strftime('%B')) for i in range(1, 13)],
        years=[str(y) for y in range(2026, 2051)]
    )

@app.route('/finance/combined-detailed-report/export/csv')
@role_required("finance")
def export_combined_detailed_report_csv():
    interaction_id = request.args.get("interaction_id", "").strip()
    user_email = (request.args.get("user_email", "") or "").strip().lower()
    business_email = (request.args.get("business_email", "") or "").strip().lower()
    period = request.args.get("period", "all")
    year = request.args.get("year", 0) or 0
    month = request.args.get("month", 0) or 0

    uq = UserTransaction.query
    bq = BusinessTransaction.query

    # Apply filters (same as your HTML page)
    # ...[date/month/interact/user_email/business_email filtering as in your page]...

    if period == "year" and year:
        uq = uq.filter(UserTransaction.date_time >= datetime(int(year), 1, 1), UserTransaction.date_time < datetime(int(year)+1, 1, 1))
        bq = bq.filter(BusinessTransaction.date_time >= datetime(int(year), 1, 1), BusinessTransaction.date_time < datetime(int(year)+1, 1, 1))
    elif period == "month" and year and month:
        start = datetime(int(year), int(month), 1)
        if int(month) == 12:
            end = datetime(int(year)+1, 1, 1)
        else:
            end = datetime(int(year), int(month)+1, 1)
        uq = uq.filter(UserTransaction.date_time >= start, UserTransaction.date_time < end)
        bq = bq.filter(BusinessTransaction.date_time >= start, BusinessTransaction.date_time < end)
    if interaction_id:
        uq = uq.filter(UserTransaction.interaction_id == interaction_id)
        bq = bq.filter(BusinessTransaction.interaction_id == interaction_id)

    user_lookup = {u.referral_code: u for u in User.query.all()}
    business_lookup = {b.referral_code: b for b in Business.query.all()}
    if user_email:
        utrans = [t for t in uq.all() if t.user_referral_id in user_lookup and user_lookup[t.user_referral_id].email.lower() == user_email]
        btrans = []
    elif business_email:
        btrans = [t for t in bq.all() if t.business_referral_id in business_lookup and business_lookup[t.business_referral_id].business_email.lower() == business_email]
        utrans = []
    else:
        utrans = uq.all()
        btrans = bq.all()

    import csv
    from io import StringIO
    si = StringIO()
    writer = csv.writer(si)

    # Add super header
    writer.writerow(["Perk Miner Detailed Report"])
    writer.writerow([])

    # User transactions header row
    writer.writerow([
        "Date/Time",
        "Interaction ID",
        "User Referral ID",
        "User Name",
        "User Email",
        "Tier 1 Cashback",
        "Tier 2 Commission",
        "Tier 3 Commission",
        "Tier 4 Commission",
        "Tier 5 Commission",
        "Tier 1 User-Biz",
        "Tier 2 User-Biz",
        "Tier 3 User-Biz",
        "Tier 4 User-Biz",
        "Tier 5 User-Biz",
        "Transaction ID",
    ])
    for t in utrans:
        writer.writerow([
            t.date_time.strftime('%Y-%m-%d %I:%M %p'),
            t.interaction_id,
            t.user_referral_id,
            user_lookup[t.user_referral_id].name if t.user_referral_id in user_lookup else "",
            user_lookup[t.user_referral_id].email if t.user_referral_id in user_lookup else "",
            f"{t.cash_back:,.2f}",
            f"{t.tier2_commission:,.2f}",
            f"{t.tier3_commission:,.2f}",
            f"{t.tier4_commission:,.2f}",
            f"{t.tier5_commission:,.2f}",
            f"{t.tier1_business_user_commission:,.2f}" if hasattr(t, "tier1_business_user_commission") else "",
            f"{t.tier2_business_user_commission:,.2f}" if hasattr(t, "tier2_business_user_commission") else "",
            f"{t.tier3_business_user_commission:,.2f}" if hasattr(t, "tier3_business_user_commission") else "",
            f"{t.tier4_business_user_commission:,.2f}" if hasattr(t, "tier4_business_user_commission") else "",
            f"{t.tier5_business_user_commission:,.2f}" if hasattr(t, "tier5_business_user_commission") else "",
            t.transaction_id
        ])

    writer.writerow([])
    writer.writerow(["Business Transactions"])
    writer.writerow([
        "Date/Time", "Interaction ID", "Business Referral ID", "Business Name", "Business Email",
        "Tier 1 Biz Cashback", "Tier 2 Biz Cashback", "Tier 3 Biz Cashback", "Tier 4 Biz Cashback", "Tier 5 Biz Cashback", "Transaction ID"
    ])
    for t in btrans:
        writer.writerow([
            t.date_time.strftime('%Y-%m-%d %I:%M %p'),
            t.interaction_id,
            t.business_referral_id,
            business_lookup[t.business_referral_id].business_name if t.business_referral_id in business_lookup else '',
            business_lookup[t.business_referral_id].business_email if t.business_referral_id in business_lookup else '',
            f"{t.cash_back:,.2f}",
            f"{t.tier2_commission:,.2f}",
            f"{t.tier3_commission:,.2f}",
            f"{t.tier4_commission:,.2f}",
            f"{t.tier5_commission:,.2f}",
            t.transaction_id
        ])

    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment;filename=perkminer_combined_detailed_report.csv"})

@app.route("/finance/business-detailed-report", methods=["GET"])
@role_required("finance")
def business_combined_detail_report():
    interaction_id = request.args.get("interaction_id", "").strip()
    business_referral_id = request.args.get("business_referral_id", "").strip()
    business_email = (request.args.get("business_email", "") or "").strip().lower()
    period = request.args.get("period", "all")
    year = request.args.get("year", "")
    month = request.args.get("month", "")

    bq = BusinessTransaction.query

    # Date/year/month filtering
    if period == "year" and year:
        bq = bq.filter(BusinessTransaction.date_time >= datetime(int(year), 1, 1), BusinessTransaction.date_time < datetime(int(year)+1, 1, 1))
    elif period == "month" and year and month:
        start = datetime(int(year), int(month), 1)
        if int(month) == 12:
            end = datetime(int(year)+1, 1, 1)
        else:
            end = datetime(int(year), int(month)+1, 1)
        bq = bq.filter(BusinessTransaction.date_time >= start, BusinessTransaction.date_time < end)
    if interaction_id:
        bq = bq.filter(BusinessTransaction.interaction_id == interaction_id)
    if business_referral_id:
        bq = bq.filter(
            (BusinessTransaction.business_referral_id == business_referral_id) |
            (BusinessTransaction.tier2_business_referral_id == business_referral_id) |
            (BusinessTransaction.tier3_business_referral_id == business_referral_id) |
            (BusinessTransaction.tier4_business_referral_id == business_referral_id) |
            (BusinessTransaction.tier5_business_referral_id == business_referral_id)
        )

    transactions = bq.all()
    business_lookup = {b.referral_code: b for b in Business.query.all()}
    if business_email:
        transactions = [t for t in transactions if t.business_referral_id in business_lookup and business_lookup[t.business_referral_id].business_email.lower() == business_email]
    return render_template(
        "business_combined_detail_report.html",
        transactions=transactions,
        business_lookup=business_lookup,
        period=period,
        year=year,
        month=month,
        interaction_id=interaction_id,
        business_referral_id=business_referral_id,
        business_email=business_email,
        months=[(f"{i}", datetime(2026, i, 1).strftime('%B')) for i in range(1, 13)],
        years=[str(y) for y in range(2026, 2051)]
    )

@app.route("/finance/combined-cashback-paid", methods=["GET"])
@role_required("finance")
def combined_cashback_paid():
    period = request.args.get("period", "all")
    year = int(request.args.get("year", 0)) if request.args.get("year") else 0
    month = int(request.args.get("month", 0)) if request.args.get("month") else 0

    uq = UserTransaction.query
    bq = BusinessTransaction.query
    if period == "year" and year:
        uq = uq.filter(UserTransaction.date_time >= datetime(year, 1, 1), UserTransaction.date_time < datetime(year + 1, 1, 1))
        bq = bq.filter(BusinessTransaction.date_time >= datetime(year, 1, 1), BusinessTransaction.date_time < datetime(year + 1, 1, 1))
    elif period == "month" and year and month:
        start = datetime(year, month, 1)
        if month == 12:
            end = datetime(year + 1, 1, 1)
        else:
            end = datetime(year, month + 1, 1)
        uq = uq.filter(UserTransaction.date_time >= start, UserTransaction.date_time < end)
        bq = bq.filter(BusinessTransaction.date_time >= start, BusinessTransaction.date_time < end)
    user_cbs = uq.all()
    bus_cbs = bq.all()

    # Only Tier 1 cashback for each (ignore commissions)
    tier1_user_cashback = sum(txn.cash_back for txn in user_cbs)
    tier1_biz_cashback = sum(txn.cash_back for txn in bus_cbs)
    grand_total = tier1_user_cashback + tier1_biz_cashback

    return render_template(
        "combined_cashback_paid.html",
        user_cbs=user_cbs,
        bus_cbs=bus_cbs,
        tier1_user_cashback=tier1_user_cashback,
        tier1_biz_cashback=tier1_biz_cashback,
        grand_total=grand_total,
        period=period,
        year=year,
        month=month,
    )

@app.route('/finance/combined-cashback-paid/export/csv')
@role_required("finance")
def export_finance_cashback_paid_csv():
    period = request.args.get("period", "all")
    year = int(request.args.get("year", 0)) if request.args.get("year") else 0
    month = int(request.args.get("month", 0)) if request.args.get("month") else 0

    uq = UserTransaction.query
    bq = BusinessTransaction.query
    if period == "year" and year:
        uq = uq.filter(UserTransaction.date_time >= datetime(year, 1, 1), UserTransaction.date_time < datetime(year + 1, 1, 1))
        bq = bq.filter(BusinessTransaction.date_time >= datetime(year, 1, 1), BusinessTransaction.date_time < datetime(year + 1, 1, 1))
    elif period == "month" and year and month:
        start = datetime(year, month, 1)
        if month == 12:
            end = datetime(year + 1, 1, 1)
        else:
            end = datetime(year, month + 1, 1)
        uq = uq.filter(UserTransaction.date_time >= start, UserTransaction.date_time < end)
        bq = bq.filter(BusinessTransaction.date_time >= start, BusinessTransaction.date_time < end)
    user_cbs = uq.all()
    bus_cbs = bq.all()

    import csv
    from io import StringIO
    si = StringIO()
    writer = csv.writer(si)

    writer.writerow(["Perk Miner Member Commissions and Business Cash Back To Be Paid"])
    writer.writerow([])
    writer.writerow([
        "Type",
        "Referral ID",
        "Email",
        "Date/Time",
        "Tier 1 Cashback"
    ])
    for t in user_cbs:
        user = User.query.filter_by(referral_code=t.user_referral_id).first()
        writer.writerow([
            "User",
            t.user_referral_id,
            user.email if user else "",
            t.date_time.strftime('%Y-%m-%d %I:%M %p'),
            f"{t.cash_back:,.2f}"
        ])
    for t in bus_cbs:
        business = Business.query.filter_by(referral_code=t.business_referral_id).first()
        writer.writerow([
            "Business",
            t.business_referral_id,
            business.business_email if business else "",
            t.date_time.strftime('%Y-%m-%d %I:%M %p'),
            f"{t.cash_back:,.2f}"
        ])

    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=perkminer_combined_cashback_paid.csv"}
    )

@app.route("/finance/commissions-paid", methods=["GET"])
@role_required("finance")
def commissions_paid():
    period = request.args.get("period", "all")
    year = int(request.args.get("year", 0)) if request.args.get("year") else 0
    month = int(request.args.get("month", 0)) if request.args.get("month") else 0

    qry = UserTransaction.query
    if period == "year" and year:
        qry = qry.filter(UserTransaction.date_time >= datetime(year, 1, 1), UserTransaction.date_time < datetime(year + 1, 1, 1))
    elif period == "month" and year and month:
        start = datetime(year, month, 1)
        if month == 12:
            end = datetime(year + 1, 1, 1)
        else:
            end = datetime(year, month+1, 1)
        qry = qry.filter(UserTransaction.date_time >= start, UserTransaction.date_time < end)

    transactions = qry.all()
    from collections import defaultdict

    users_data = defaultdict(lambda: {"referral_id": "", "name": "", "email": "",
                                      "tier2": 0.0, "tier3": 0.0, "tier4": 0.0, "tier5": 0.0, "grand_total": 0.0})
    all_users = {u.referral_code: u for u in User.query.all()}

    # Loop through every transaction and add to every user's total (per tier) if that user earned a commission in any tier
    for t in transactions:
        for tier, field, comm_field in [
            ("tier2", t.tier2_user_referral_id, t.tier2_commission),
            ("tier3", t.tier3_user_referral_id, t.tier3_commission),
            ("tier4", t.tier4_user_referral_id, t.tier4_commission),
            ("tier5", t.tier5_user_referral_id, t.tier5_commission),
        ]:
            if field and comm_field > 0 and field in all_users:
                u = all_users[field]
                udata = users_data[u.referral_code]
                udata["referral_id"] = u.referral_code
                udata["name"] = u.name or ""
                udata["email"] = u.email or ""
                udata[tier] += comm_field
                udata["grand_total"] += comm_field

    # Only display users with nonzero grand total:
    users = [u for u in users_data.values() if u["grand_total"] > 0]
    users.sort(key=lambda x: x["grand_total"], reverse=True)

    return render_template(
        "commissions_paid.html",
        users=users,
        period=period,
        year=year,
        month=month
    )

@app.route("/finance/commissions-paid/export/csv")
@role_required("finance")
def export_commissions_paid_csv():
    period = request.args.get("period", "all")
    year = int(request.args.get("year", 0)) if request.args.get("year") else 0
    month = int(request.args.get("month", 0)) if request.args.get("month") else 0

    qry = UserTransaction.query
    if period == "year" and year:
        qry = qry.filter(UserTransaction.date_time >= datetime(year, 1, 1), UserTransaction.date_time < datetime(year + 1, 1, 1))
    elif period == "month" and year and month:
        start = datetime(year, month, 1)
        if month == 12:
            end = datetime(year + 1, 1, 1)
        else:
            end = datetime(year, month + 1, 1)
        qry = qry.filter(UserTransaction.date_time >= start, UserTransaction.date_time < end)
    transactions = qry.all()

    from collections import defaultdict
    users_data = defaultdict(lambda: {
        "referral_id": "",
        "name": "",
        "email": "",
        "tier2": 0.0,
        "tier3": 0.0,
        "tier4": 0.0,
        "tier5": 0.0,
        "grand_total": 0.0
    })
    all_users = {u.referral_code: u for u in User.query.all()}

    for t in transactions:
        if t.tier2_user_referral_id and t.tier2_commission > 0:
            u = all_users.get(t.tier2_user_referral_id)
            if u:
                x = users_data[u.referral_code]
                x["referral_id"] = u.referral_code
                x["name"] = u.name or ""
                x["email"] = u.email or ""
                x["tier2"] += t.tier2_commission
                x["grand_total"] += t.tier2_commission
        if t.tier3_user_referral_id and t.tier3_commission > 0:
            u = all_users.get(t.tier3_user_referral_id)
            if u:
                x = users_data[u.referral_code]
                x["referral_id"] = u.referral_code
                x["name"] = u.name or ""
                x["email"] = u.email or ""
                x["tier3"] += t.tier3_commission
                x["grand_total"] += t.tier3_commission
        if t.tier4_user_referral_id and t.tier4_commission > 0:
            u = all_users.get(t.tier4_user_referral_id)
            if u:
                x = users_data[u.referral_code]
                x["referral_id"] = u.referral_code
                x["name"] = u.name or ""
                x["email"] = u.email or ""
                x["tier4"] += t.tier4_commission
                x["grand_total"] += t.tier4_commission
        if t.tier5_user_referral_id and t.tier5_commission > 0:
            u = all_users.get(t.tier5_user_referral_id)
            if u:
                x = users_data[u.referral_code]
                x["referral_id"] = u.referral_code
                x["name"] = u.name or ""
                x["email"] = u.email or ""
                x["tier5"] += t.tier5_commission
                x["grand_total"] += t.tier5_commission

    users = sorted(users_data.values(), key=lambda x: x["grand_total"], reverse=True)

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['User Referral ID', 'Name', 'Email', 'Tier 2 (0.25%)', 'Tier 3 (0.25%)', 'Tier 4 (0.25%)', 'Tier 5 (2%)', 'Grand Total'])
    for u in users:
        writer.writerow([
            u["referral_id"],
            u["name"],
            u["email"],
            f"{u['tier2']:.2f}",
            f"{u['tier3']:.2f}",
            f"{u['tier4']:.2f}",
            f"{u['tier5']:.2f}",
            f"{u['grand_total']:.2f}",
        ])
    output = si.getvalue()
    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=commissions_paid.csv"})

PERKMINER_WEBHOOK_SECRET = "SuperSecretSharedKeyWithPartner"  # You will issue a unique one to each business-partner for real security

@app.route('/api/report_purchase', methods=['POST'])
def report_purchase():
    data = request.json
    session_id = data.get("perkminer_session")
    user_referral_code = data.get("perkminer_user")
    business_referral_code = data.get("perkminer_biz")
    amount = float(data.get("amount", 0))
    signature = data.get("signature")

    # Simple HMAC signature validation (optional but highly recommended)
    expected = hmac.new(
        PERKMINER_WEBHOOK_SECRET.encode(),
        f"{session_id}{user_referral_code}{business_referral_code}{amount}".encode(),
        hashlib.sha256
    ).hexdigest()
    if signature != expected:
        return jsonify({"status": "error", "message": "Signature validation failed"}), 403

    interaction = Interaction.query.get(session_id)
    user = User.query.filter_by(referral_code=user_referral_code).first()
    business = Business.query.filter_by(referral_code=business_referral_code).first()
    if not interaction or not user or not business:
        return jsonify({"status": "error", "message": "Invalid purchase identifiers"}), 400

    # --- Insert your full payout logic here as you do for QR and business finalization ---
    # e.g. create UserTransaction, BusinessTransaction, deduct ad fees, assign commissions

    # All done!
    return jsonify({"status": "success", "message": "Transaction recorded and rewards credited."})

@app.route("/seed_admins_once")
def seed_admins_once():
    from app import db, User, Role, bcrypt
    response = []

    # Roles to create
    role_names = [
        "approve_reject_listings",
        "finance",
        "feedback_moderation",
        "customer_support"
    ]
    roles = {}
    for name in role_names:
        role = Role.query.filter_by(name=name).first()
        if not role:
            role = Role(name=name)
            db.session.add(role)
            response.append(f"Added role: {name}")
        roles[name] = role
    db.session.commit()

    # Create demo admin users if needed
    admins = [
        {
            "email": "admin1@perkminer.com",
            "password": "admin1secure",
            "role_names": [
                "approve_reject_listings", "feedback_moderation", "customer_support"
            ]
        },
        {
            "email": "finance1@perkminer.com",
            "password": "finance1secure",
            "role_names": ["finance"]
        }
    ]
    for admin in admins:
        user = User.query.filter_by(email=admin["email"]).first()
        if not user:
            hashed_pw = bcrypt.generate_password_hash(admin["password"]).decode("utf-8")
            user = User(
                email=admin["email"],
                password=hashed_pw,
                email_confirmed=True
            )
            db.session.add(user)
            db.session.commit()
            response.append(f"Created user: {admin['email']}")
        # Assign roles
        for role_name in admin["role_names"]:
            role = Role.query.filter_by(name=role_name).first()
            if role and role not in user.roles:
                user.roles.append(role)
                response.append(f"Granted {role_name} to {admin['email']}")
        db.session.commit()

    # Assign roles to your own account if needed
    target_email = "joejmendez@gmail.com"
    target_roles = ["finance"]  # Change or add as needed
    user = User.query.filter_by(email=target_email).first()
    if user:
        for role_name in target_roles:
            role = Role.query.filter_by(name=role_name).first()
            if role and role not in user.roles:
                user.roles.append(role)
                response.append(f"Granted {role_name} to {target_email}")
        db.session.commit()
    else:
        response.append(f"User {target_email} not found; cannot assign roles.")

    response.append("Seeding complete!")
    return "<br>".join(response)

for rule in app.url_map.iter_rules():
    print(f"{rule.endpoint:25s} {rule.methods} {rule}")

if __name__ == "__main__":
    app.run(debug=True)