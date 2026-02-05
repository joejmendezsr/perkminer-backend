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

class ServiceRequestForm(FlaskForm):
    service_type = SelectField(
        "Type of Service Requested",
        choices=[
            ("handyman", "Handyman Service"),
            ("contractor", "Contractor Services"),
            ("cleaning", "Cleaning Services"),
            ("lawn", "Lawn Care"),
            # Add more as needed
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

import os, re, random, string, time, logging
import cloudinary
import cloudinary.uploader
import random  # put this at the top of your file if not already imported

cloudinary.config(
  cloud_name = 'dmrntlcfd',
  api_key = '786387955898581',
  api_secret = 'cLtDoC44BarYjVrr3dIgi_0XiKo'
)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'perkminer_hardcoded_secret_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', "sqlite:///site.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER']   = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT']     = int(os.environ.get('MAIL_PORT', 465))
app.config['MAIL_USE_SSL']  = True
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
    category = db.Column(db.String(50), nullable=False, default="Other")
    business_email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    referral_code = db.Column(db.String(32), unique=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('business.id'))
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
    is_suspended = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), nullable=False, default='not_submitted')

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class UserRoles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))

    # Optional: User and Role relationships for convenience
    user = db.relationship('User', backref=db.backref('user_roles', cascade='all, delete-orphan'))
    role = db.relationship('Role', backref=db.backref('user_roles', cascade='all, delete-orphan'))

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

EMAIL_REGEX = r'^[\w\.-]+@[\w\.-]+\.\w{2,}$'
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
    msg = Message(subject, recipients=[to], html=html_body, sender=app.config['MAIL_USERNAME'])
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

        <!-- Hero Banner with Logo -->
                <tr>
                    <td style="position:relative;">
                        <img src="https://res.cloudinary.com/dmrntlcfd/image/upload/v1769979390/Email_Background_yn4vvi.jpg" width="600"
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

# ...ROUTES start below...
@app.route("/admin-roles")
@login_required
def admin_roles_landing():
    return render_template("admin_roles_landing.html")

@app.route("/")
def home():
    approved_listings = Business.query.filter_by(status="approved").all()
    return render_template("home.html", approved_listings=approved_listings)

@app.route("/business")
def business_home():
    return render_template("business_home.html")

@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    query = Business.query.filter_by(status="approved")  # add this!
    if category:
        query = query.filter(Business.category == category)
    if q:
        query = query.filter(Business.search_keywords.ilike(f"%{q}%"))
    results = query.all()
    return render_template("search_results.html", results=results, q=q, category=category)

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

@app.route('/uploads/<filename>')
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
    subject = f"{inviter_name} has invited you to join PerkMiner."
    reg_url = url_for('register', ref=current_user.referral_code, _external=True)
    video_url = url_for('intro', ref=current_user.referral_code, _external=True)
    html_body = build_invite_email(inviter_name, reg_url, video_url)
    send_email(invitee_email, subject, html_body)
    flash('Invitation sent!')
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
    return render_template("dashboard.html", form=form, profile_form=profile_form, invite_form=invite_form,
         email=current_user.email,
         referral_code=current_user.referral_code, sponsor=sponsor if sponsor else None,
         rewards_table=rewards_table, level2=level2, level3=level3, level4=level4, level5=level5,
         user_name=current_user.name,
         profile_img_url=current_user.profile_photo
    )

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

# ...business user registration, verification, login, dashboard...
# ...business invite route has already been provided above...

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
        if referral_code:
            sponsor = Business.query.filter_by(referral_code=referral_code).first()
            if sponsor:
                sponsor_id = sponsor.id
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
                # --- END 2FA ---
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

    def get_service_field(n):
        return request.form.get(f"service_{n}", "")

    if request.method == "POST":
        updated = False
        # Business profile fields—set updated=True for any real change
        if 'business_name' in request.form:
            biz.business_name = request.form.get('business_name', biz.business_name)
            updated = True
        if 'category' in request.form:
            biz.category = request.form.get('category', biz.category)
            updated = True
        biz.phone_number = request.form.get('phone_number', biz.phone_number)
        biz.address = request.form.get('address', biz.address)
        try:
            if request.form.get('latitude'):
                biz.latitude = float(request.form.get('latitude'))
            if request.form.get('longitude'):
                biz.longitude = float(request.form.get('longitude'))
        except ValueError:
            pass
        file = request.files.get('profile_photo')
        if file and allowed_file(file.filename):
            upload_result = cloudinary.uploader.upload(file)
            biz.profile_photo = upload_result.get('secure_url')
            updated = True
        biz.hours_of_operation = request.form.get('hours_of_operation', biz.hours_of_operation)
        biz.website_url = request.form.get('website_url', biz.website_url)
        biz.about_us = request.form.get('about_us', biz.about_us)
        biz.search_keywords = request.form.get('search_keywords', biz.search_keywords)
        for n in range(1, 11):
            setattr(biz, f'service_{n}', get_service_field(n))
        if updated:
            db.session.commit()
            flash("Business profile updated!")
        return redirect(url_for('business_dashboard'))

    latitude = biz.latitude if biz.latitude else ""
    longitude = biz.longitude if biz.longitude else ""
    profile_img_url = biz.profile_photo if biz.profile_photo else None

    # Reward calculator logic (unchanged)
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
            reward = invoice_amount * 0.01; rewards_desc = "As the business, for an invoice you create and get paid for in the amount"; cap = None
        elif downline_level in [2, 3, 4]:
            rate = 0.002; cap = 3.75; reward = min(invoice_amount * rate, cap)
            rewards_desc = f"If a Tier {downline_level} business creates and gets paid for an invoice in the amount"
        elif downline_level == 5:
            rate = 0.02; cap = 25; reward = min(invoice_amount * rate, cap)
            rewards_desc = "If a Tier 5 business creates and gets paid for an invoice in the amount"
        else: reward = 0; rewards_desc = ""
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
    return render_template("business_dashboard.html",
        form=form,
        profile_form=profile_form,
        invite_form=invite_form,
        biz=biz,
        sponsor=sponsor,
        referral_code=biz.referral_code,
        rewards_table=rewards_table,
        level2=level2, level3=level3, level4=level4, level5=level5,
        profile_img_url=profile_img_url,
        phone_number=biz.phone_number,
        address=biz.address,
        latitude=latitude,
        longitude=longitude
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

@app.route("/finance-dashboard")
@role_required("finance")
def finance_dashboard():
    return render_template("finance_dashboard.html")

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
    if biz.status in ["pending", "in_review"]:
        biz.status = "approved"
        db.session.commit()
        flash(f"Listing {biz.business_name} approved!")
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

@app.route("/listing-disclaimer", methods=["POST", "GET"])
def listing_disclaimer():
    if request.method == "POST":
        listing_id = request.form.get("listing_id")
        referral_code = request.form.get("referral_code")
        return render_template(
            "listing_disclaimer.html",
            listing_id=listing_id,
            referral_code=referral_code
        )
    return redirect(url_for("business_dashboard"))

@app.route("/send-for-review", methods=["POST"])
def send_for_review():
    listing_id = request.form.get("listing_id")
    referral_code = request.form.get("referral_code")
    accept_terms = request.form.get("accept_terms")
    if not accept_terms:
        flash("You must accept the terms and conditions.")
        return redirect(url_for("listing_disclaimer"))

    biz = Business.query.get(listing_id)
    if biz:
        biz.status = "pending"
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

@app.route("/service-request/<int:biz_id>", methods=["GET", "POST"])
@login_required
def service_request(biz_id):
    biz = Business.query.get_or_404(biz_id)
    form = ServiceRequestForm()
    if form.validate_on_submit():
        # You will save or process the request here
        flash("Service request submitted! (AI cost suggestion coming soon.)")
        return redirect(url_for('view_listing', biz_id=biz.id))
    return render_template("service_request.html", form=form, biz=biz)

@app.route("/seed_admins_once")
def seed_admins_once():
    from app import db, User, Role, bcrypt
    response = []

    # --- Roles to create ---
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

    # --- Create demo admin users if needed ---
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

    # --- Assign roles to existing user(s) by email ---
    target_email = "joejmendez@gmail.com"
    target_roles = ["finance"]  # Change or add roles as needed, e.g. ["finance", "customer_support"]
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