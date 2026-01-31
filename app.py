from flask import Flask, request, redirect, url_for, render_template, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, DecimalField, SelectField, FileField
from wtforms.validators import DataRequired, Email, Length, Optional, NumberRange
from werkzeug.utils import secure_filename
import os, re, random, string, time, logging
import cloudinary
import cloudinary.uploader

cloudinary.config(
  cloud_name = 'dmrntlcfd',
  api_key = '786387955898581',
  api_secret = 'CLOUDINARY_URL=cloudinary://786387955898581:**********@dmrntlcfd'
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', "sqlite:///site.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER']   = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT']     = int(os.environ.get('MAIL_PORT', 465))
app.config['MAIL_USE_SSL']  = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')

UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

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
    name = db.Column(db.String(100))
    profile_photo = db.Column(db.String(200))

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
    try: mail.send(msg)
    except Exception as e: logging.error("EMAIL SEND ERROR: %s", e)
def send_verification_email(user):
    code = user.email_code
    verify_url = url_for("activate", code=code, _external=True)
    html_body = f"""<p>Click <a href="{verify_url}">here</a> to confirm your email, or use code: <b>{code}</b></p>"""
    send_email(user.email, "Confirm your PerkMiner email!", html_body)
def send_business_verification_email(biz):
    code = biz.email_code
    verify_url = url_for("business_activate", code=code, _external=True)
    html_body = f"""<p>Click <a href="{verify_url}">here</a> to verify your business email, or use code: <b>{code}</b></p>"""
    send_email(biz.business_email, "[PerkMiner] Verify your business email!", html_body)
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
    submit = SubmitField('Register')
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
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

# ...ROUTES start below...
@app.route("/")
def home():
    return render_template("home.html")
@app.route("/business")
def business_home():
    return render_template("business_home.html")

@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    query = Business.query
    if category:
        query = query.filter(Business.category == category)
    if q:
        # Simple ILIKE keyword filter (later: full-text search)
        query = query.filter(Business.search_keywords.ilike(f"%{q}%"))
    results = query.all()
    return render_template("search_results.html", results=results, q=q, category=category)

@app.route("/category/<name>")
def category_browse(name):
    results = Business.query.filter(Business.category == name).all()
    return render_template("category_results.html", results=results, category=name)

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
                login_user(user)
                return redirect(url_for("dashboard"))
        else:
            message = "Login failed. Check email and password."
    return render_template("login.html", message=message, form=form)

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
    subject = f"You have been invited by {inviter_name} to join Perkminer."
    reg_url = url_for('register', ref=current_user.referral_code, _external=True)
    html_body = f"""
    <p>You have been invited by {inviter_name} to join PerkMiner. Here are the benefits of joining.</p>
    <p><a href="{reg_url}">Join PerkMiner</a></p>
    """
    send_email(invitee_email, subject, html_body)
    flash('Invitation sent!')
    return redirect(url_for('dashboard'))

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    form = RewardForm(request.form)
    profile_form = UserProfileForm()
    invite_form = InviteForm()
    if request.method == "POST" and profile_form.submit.data and profile_form.validate():
        user = current_user
        if profile_form.name.data:
            user.name = profile_form.name.data
            file = request.files.get('profile_photo')
            if file and allowed_file(file.filename):
                upload_result = cloudinary.uploader.upload(file)
                user.profile_photo = upload_result.get('secure_url')  # this is the image URL        db.session.commit()
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
         profile_img_url=url_for('uploaded_file', filename=current_user.profile_photo) if current_user.profile_photo else None)

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
                session['business_id'] = biz.id
                return redirect(url_for("business_dashboard"))
        else:
            message = "Login failed. Check business email and password."
    return render_template("business_login.html", message=message, form=form)

@app.route('/business/invite', methods=['POST'])
def business_invite():
    invite_form = BusinessInviteForm()
    biz_id = session.get('business_id')
    biz = Business.query.get(biz_id) if biz_id else None
    if not biz or not invite_form.validate_on_submit():
        flash("Business invite failed. Please log in and use a valid email.")
        return redirect(url_for("business_login"))
    invitee_email = invite_form.invitee_email.data.strip()
    subject = f"You have been invited by {biz.business_name} to join Perkminer."
    reg_url = url_for('business_register', ref=biz.referral_code, _external=True)
    html_body = f"""
    <p>You have been invited by {biz.business_name} to join PerkMiner. Here are the benefits of joining.</p>
    <p><a href="{reg_url}">Join PerkMiner as a Business</a></p>
    """
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
        if 'business_name' in request.form:
            biz.business_name = request.form.get('business_name', biz.business_name)

        if (
            'profile_photo' in request.files or
            any(x in request.form for x in [
                'phone_number', 'address', 'latitude', 'longitude', 'hours_of_operation',
                'website_url', 'about_us', 'category', 'search_keywords', 'service_1'
            ])
        ):
            if 'category' in request.form:
                biz.category = request.form.get('category', biz.category)
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
                biz.hours_of_operation = request.form.get('hours_of_operation', biz.hours_of_operation)
            biz.website_url = request.form.get('website_url', biz.website_url)
            biz.about_us = request.form.get('about_us', biz.about_us)
            biz.search_keywords = request.form.get('search_keywords', biz.search_keywords)
            for n in range(1, 11):
                setattr(biz, f'service_{n}', get_service_field(n))
            db.session.commit()
            flash("Business profile updated!")
            return redirect(url_for('business_dashboard'))

    latitude = biz.latitude if biz.latitude else ""
    longitude = biz.longitude if biz.longitude else ""
    profile_img_url = url_for('uploaded_file', filename=biz.profile_photo) if biz.profile_photo else None

    # Calculators - unchanged!
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

for rule in app.url_map.iter_rules():
    print(f"{rule.endpoint:25s} {rule.methods} {rule}")

if __name__ == "__main__":
    app.run(debug=True)