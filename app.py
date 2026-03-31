import os
import sys
import secrets
import re
import stripe
import json
import base64
import io
import atexit

from datetime import datetime, date, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from sqlalchemy.orm import relationship
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageEnhance, ImageFilter, ImageOps
from dotenv import load_dotenv
import anthropic
from apscheduler.schedulers.background import BackgroundScheduler

# Google Sign-In
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Database Configuration
database_url = os.environ.get('POSTGRES_URL') or os.environ.get('DATABASE_URL')
if not database_url or not database_url.startswith(('postgres', 'postgresql', 'sqlite')):
    database_url = 'sqlite:///household.db'
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

print(f"Using database: {database_url.split('@')[0]}...", file=sys.stderr)

# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'RoomSync <noreply@roomsync.app>')

db = SQLAlchemy(app)
mail = Mail(app)

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY')
BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')


# =============================================================================
# MODELS
# =============================================================================

class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=False)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(50), nullable=True)
    password = db.Column(db.String(255), nullable=True)  # Nullable for OAuth users
    auth_provider = db.Column(db.String(20), default='email')  # 'email', 'google'
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'))
    stripe_account_id = db.Column(db.String(255), nullable=True)  # Stripe Connect Express
    group = relationship('Group', backref='users')



class GroupMember(db.Model):
    __tablename__ = 'group_members'

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='member')

    user = db.relationship('User', backref='group_memberships')
    group = db.relationship('Group', backref='members')


class GroupInvite(db.Model):
    __tablename__ = 'group_invites'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    code = db.Column(db.String(10), nullable=False)
    accepted = db.Column(db.Boolean, default=False)

    group = db.relationship('Group', backref='invites')


# Association table for chore assignments
chore_assignments = db.Table('chore_assignments',
    db.Column('chore_id', db.Integer, db.ForeignKey('chores.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True)
)


class Chore(db.Model):
    __tablename__ = 'chores'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    next_due_date = db.Column(db.Date, nullable=True)
    completed = db.Column(db.Boolean, default=False)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    assignments = db.relationship('User', secondary=chore_assignments, lazy='subquery',
        backref=db.backref('assigned_chores', lazy=True))
    completions = db.relationship('ChoreCompletion', backref='chore', lazy=True,
        cascade="all, delete-orphan")


class ChoreCompletion(db.Model):
    __tablename__ = 'chore_completions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    chore_id = db.Column(db.Integer, db.ForeignKey('chores.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='chore_completions')

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    users_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    related_id = db.Column(db.Integer, nullable=True)
    users = relationship('User', backref='notifications')


class Expense(db.Model):
    __tablename__ = 'expenses'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, nullable=False)
    paid_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    paid_by = relationship('User', foreign_keys=[paid_by_user_id])
    splits = relationship('ExpenseSplit', backref='expense', cascade="all, delete-orphan")
    payments = relationship('Payment', backref='expense', lazy=True)


class ExpenseSplit(db.Model):
    __tablename__ = 'expense_splits'
    id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey('expenses.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    percentage = db.Column(db.Float, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    user = relationship('User', foreign_keys=[user_id])


class ExpenseReminder(db.Model):
    __tablename__ = 'expense_reminders'
    id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey('expenses.id'), nullable=False)
    split_id = db.Column(db.Integer, db.ForeignKey('expense_splits.id'), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    reminder_type = db.Column(db.String(20), nullable=False)  # 'manual' or 'automated'

    expense = db.relationship('Expense', backref='reminders')
    split = db.relationship('ExpenseSplit', backref='reminders')



class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    expense_id = db.Column(db.Integer, db.ForeignKey('expenses.id'), nullable=True)
    amount_cents = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(3), default='usd')
    status = db.Column(db.String(20), default='pending')
    stripe_session_id = db.Column(db.String(255), unique=True, nullable=False)
    stripe_payment_intent_id = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class GroceryItem(db.Model):
    __tablename__ = 'grocery_items'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    price = db.Column(db.Float)
    purchased = db.Column(db.Boolean, default=False)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)


# =============================================================================
# AUTH HELPERS
# =============================================================================

def login_required(f):
    """Requires login; loads the user into g.user. No group required."""
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = db.session.get(User, session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login'))
        g.user = user
        return f(*args, **kwargs)
    return wrap


def api_login_required(f):
    """For JSON API routes: enforces login + group membership, loads g.user."""
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        user = db.session.get(User, session['user_id'])
        if not user:
            session.clear()
            return jsonify({'error': 'Unauthorized'}), 401
        if not user.group_id:
            return jsonify({'error': 'No group'}), 403
        g.user = user
        return f(*args, **kwargs)
    return wrap


def page_login_required(f):
    """For HTML page routes: enforces login + group membership, loads g.user."""
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = db.session.get(User, session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login'))
        g.user = user
        if not user.group_id:
            return redirect(url_for('group'))
        return f(*args, **kwargs)
    return wrap


def get_current_user():
    if 'user_id' not in session:
        return None
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
    return user


def is_group_admin(user):
    if not user or not user.group_id:
        return False

    membership = GroupMember.query.filter_by(
        group_id=user.group_id,
        user_id=user.id,
        role='admin'
    ).first()

    return membership is not None


def display_name(user):
    """Return the user's display name: username if set, otherwise email prefix."""
    return user.username if user.username else user.email.split('@')[0]


@app.context_processor
def inject_user():
    return dict(current_user=get_current_user())


def create_notification(user_id, group_id, notif_type, title, message, related_id=None):
    notif = Notification(
        user_id=user_id,
        group_id=group_id,
        type=notif_type,
        title=title,
        message=message,
        related_id=related_id
    )
    db.session.add(notif)
    return notif


# =============================================================================
# EMAIL HELPERS
# =============================================================================

def send_expense_reminder_email(debtor_email, debtor_name, creditor_name, amount, description):
    """Send a reminder email to someone who owes money."""
    try:
        msg = Message(
            subject=f"Payment Reminder: ${amount:.2f} owed to {creditor_name}",
            recipients=[debtor_email]
        )

        msg.body = f"""Hi {debtor_name},

This is a friendly reminder that you have an outstanding expense in RoomSync.

Expense Details:
- Description: {description}
- Amount Owed: ${amount:.2f}
- Owed To: {creditor_name}

Please settle this expense at your earliest convenience.

Log in to RoomSync to view details: {BASE_URL}

Thanks,
The RoomSync Team
"""

        msg.html = f"""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <h2 style="color: #4A90E2;">Payment Reminder</h2>
    <p>Hi {debtor_name},</p>
    <p>This is a friendly reminder that you have an outstanding expense in RoomSync.</p>

    <div style="background-color: #f4f4f4; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <h3 style="margin-top: 0; color: #4A90E2;">Expense Details</h3>
        <p><strong>Description:</strong> {description}</p>
        <p><strong>Amount Owed:</strong> <span style="font-size: 1.2em; color: #E74C3C;">${amount:.2f}</span></p>
        <p><strong>Owed To:</strong> {creditor_name}</p>
    </div>

    <p>Please settle this expense at your earliest convenience.</p>
    <p><a href="{BASE_URL}/expenses" style="background-color: #4A90E2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">View in RoomSync</a></p>

    <p style="color: #666; font-size: 0.9em; margin-top: 30px;">Thanks,<br>The RoomSync Team</p>
</body>
</html>
"""

        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}", file=sys.stderr)
        return False


def check_and_send_weekly_reminders():
    """Automated job — checks for expenses older than 7 days and sends reminders."""
    print(f"Running weekly reminder check at {datetime.utcnow()}", file=sys.stderr)
    with app.app_context():
        try:
            seven_days_ago = datetime.utcnow() - timedelta(days=7)

            splits = db.session.query(ExpenseSplit).join(Expense).filter(
                Expense.created_at <= seven_days_ago,
                ExpenseSplit.user_id != Expense.paid_by_user_id
            ).all()

            reminders_sent = 0
            for split in splits:
                expense = split.expense

                recent_reminder = ExpenseReminder.query.filter(
                    ExpenseReminder.split_id == split.id,
                    ExpenseReminder.reminder_type == 'automated',
                    ExpenseReminder.sent_at >= seven_days_ago
                ).first()

                if recent_reminder:
                    continue

                debtor = split.user
                creditor = expense.paid_by

                success = send_expense_reminder_email(
                    debtor_email=debtor.email,
                    debtor_name=display_name(debtor),
                    creditor_name=display_name(creditor),
                    amount=split.amount,
                    description=expense.description
                )

                if success:
                    reminder = ExpenseReminder(
                        expense_id=expense.id,
                        split_id=split.id,
                        reminder_type='automated'
                    )
                    db.session.add(reminder)
                    reminders_sent += 1

            db.session.commit()
            print(f"Sent {reminders_sent} automated reminders", file=sys.stderr)

        except Exception as e:
            print(f"Error in automated reminders: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            db.session.rollback()


        try:
            conn.execute(db.text(
                "CREATE TABLE IF NOT EXISTS group_members ("
                "id INTEGER PRIMARY KEY, "
                "group_id INTEGER NOT NULL, "
                "user_id INTEGER NOT NULL, "
                "role TEXT NOT NULL DEFAULT 'member'"
                ")"
            ))
            conn.commit()
        except Exception:
            conn.rollback()


        try:
            conn.execute(db.text(
                "CREATE TABLE IF NOT EXISTS group_invites ("
                "id INTEGER PRIMARY KEY, "
                "email TEXT NOT NULL, "
                "group_id INTEGER NOT NULL, "
                "code TEXT NOT NULL, "
                "accepted BOOLEAN DEFAULT FALSE"
                ")"
            ))
            conn.commit()
        except Exception:
            conn.rollback()


# =============================================================================
# SCHEDULER
# =============================================================================

scheduler = BackgroundScheduler()
scheduler.add_job(
    func=check_and_send_weekly_reminders,
    trigger='cron',
    hour=9,
    minute=0,
    id='weekly_expense_reminders'
)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())


# =============================================================================
# RECEIPT / CLAUDE HELPERS
# =============================================================================

def parse_receipt_with_claude(image_bytes):
    """Parse receipt image using Anthropic Claude."""
    if not ANTHROPIC_API_KEY:
        raise ValueError("Missing ANTHROPIC_API_KEY environment variable")

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    image_base64 = base64.b64encode(image_bytes).decode('utf-8')

    prompt = """
    Extract grocery items as JSON: {"items": [...]}

    Each item:
    - "name": item name only (exclude codes/quantities)
    - "amt": quantity (parse from EA/QTY/@, default 1)
    - "price": line total (not unit price)
    - "unit_price": price per single unit
    - "price": line total (qty × unit_price)

    Ignore tax/subtotals. JSON only.
    """

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        messages=[{
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/jpeg",
                        "data": image_base64,
                    },
                },
                {"type": "text", "text": prompt}
            ],
        }],
    )

    response_text = message.content[0].text
    try:
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            return [
                {
                    'name': item.get('name', ''),
                    'quantity': item.get('amt', 1),
                    'unit_price': item.get('unit_price'),
                    'price': item.get('price')
                }
                for item in data.get('items', [])
            ]
        return []
    except Exception as e:
        print(f"Error parsing Claude response: {e}", file=sys.stderr)
        return []


def extract_image_from_request():
    """Extract image bytes from file upload or base64 JSON request."""
    if 'receipt' in request.files:
        file = request.files['receipt']
        if file.filename:
            return file.read()
    elif request.is_json:
        data = request.get_json()
        if 'image' in data:
            img_data = data['image']
            if ',' in img_data:
                img_data = img_data.split(',')[1]
            return base64.b64decode(img_data)
    return None


def ensure_jpeg_bytes(image_bytes):
    """Convert image bytes to JPEG format."""
    image = Image.open(io.BytesIO(image_bytes))
    if image.mode in ('RGBA', 'P'):
        image = image.convert('RGB')
    buf = io.BytesIO()
    image.save(buf, format='JPEG')
    return buf.getvalue()


def preprocess_receipt_image(image_bytes):
    """Pre-process receipt image for better text recognition.

    Applies grayscale, contrast enhancement, sharpening, and
    upscaling (if needed) so the AI model can read text more accurately.
    """
    image = Image.open(io.BytesIO(image_bytes))

    # Convert to grayscale to remove colour noise
    image = ImageOps.grayscale(image)

    # Upscale small images so text has enough pixel data
    MIN_WIDTH = 1500
    if image.width < MIN_WIDTH:
        scale = MIN_WIDTH / image.width
        new_size = (MIN_WIDTH, int(image.height * scale))
        image = image.resize(new_size, Image.LANCZOS)

    # Boost contrast to separate text from background
    image = ImageEnhance.Contrast(image).enhance(1.8)

    # Sharpen to define character edges
    image = ImageEnhance.Sharpness(image).enhance(2.0)

    # Convert back to RGB (required for JPEG) and save
    image = image.convert('RGB')
    buf = io.BytesIO()
    image.save(buf, format='JPEG', quality=95)
    return buf.getvalue()


# =============================================================================
# AUTH ROUTES
# =============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not email or not password:
            flash('Email and password required')
            return render_template('login.html', google_client_id=GOOGLE_CLIENT_ID)
        user = User.query.filter_by(email=email).first()
        if user and user.password and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('home') if user.group_id else url_for('group'))
        flash('Invalid credentials')
    return render_template('login.html', google_client_id=GOOGLE_CLIENT_ID)


@app.route('/auth/google', methods=['POST'])
def auth_google():
    """Handle Google Sign-In callback."""
    token = request.form.get('credential')
    if not token:
        flash('Google authentication failed')
        return redirect(url_for('login'))
    try:
        idinfo = google_id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID
        )
        email = idinfo['email'].strip().lower()
        google_name = idinfo.get('name', '').strip()
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                email=email, password=None, auth_provider='google',
                username=google_name or email.split('@')[0]
            )
            db.session.add(user)
            db.session.commit()
        elif not user.username and google_name:
            user.username = google_name
            db.session.commit()
        session['user_id'] = user.id
        return redirect(url_for('home') if user.group_id else url_for('group'))
    except Exception as e:
        print(f'Google auth error: {e}', file=sys.stderr)
        flash('Google authentication failed')
        return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        username = request.form.get('username', '').strip()
        if not email or not password:
            flash('Email and password required')
            return render_template('register.html', google_client_id=GOOGLE_CLIENT_ID)
        if len(password) < 6:
            flash('Password must be at least 6 characters')
            return render_template('register.html', google_client_id=GOOGLE_CLIENT_ID)
        existing_user = User.query.filter_by(email=email).first()
        if existing_user and existing_user.password and check_password_hash(existing_user.password, password):
            session['user_id'] = existing_user.id
            return redirect(url_for('home') if existing_user.group_id else url_for('group'))

        user = User(
            email=email,
            password=generate_password_hash(password),
            auth_provider='email',
            username=username or None
        )
        try:
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return redirect(url_for('group'))
        except IntegrityError:
            db.session.rollback()
            flash('Email already exists')
    return render_template('register.html', google_client_id=GOOGLE_CLIENT_ID)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# =============================================================================
# GROUP ROUTES
# =============================================================================

@app.route('/group', methods=['GET', 'POST'])
@login_required
def group():
    user = g.user
    if user.group_id:
        return redirect(url_for('home'))
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            return handle_create_group(user)
        elif action == 'join':
            return handle_join_group(user)
    return render_template('group.html')

@app.route('/group/invite', methods=['POST'])
@login_required
def invite_to_group():
    user = g.user
    if not user.group_id:
        return redirect(url_for('group'))

    email = request.form.get('email', '').strip().lower()
    if not email:
        flash('Email required')
        return redirect(url_for('account'))

    invite = GroupInvite(
        email=email,
        group_id=user.group_id,
        code=secrets.token_hex(4).upper()
    )

    db.session.add(invite)
    db.session.commit()

    flash(f'Invite sent to {email}')
    return redirect(url_for('account'))


@app.route('/group/remove-member/<int:user_id>', methods=['POST'])
@login_required
def remove_member(user_id):
    current_user = g.user
    if not current_user.group_id:
        return redirect(url_for('group'))

    if not is_group_admin(current_user):
        flash('Only admins can remove members')
        return redirect(url_for('account'))

    if current_user.id == user_id:
        flash('You cannot remove yourself')
        return redirect(url_for('account'))

    member = User.query.filter_by(id=user_id, group_id=current_user.group_id).first()
    if not member:
        flash('Member not found')
        return redirect(url_for('account'))

    membership = GroupMember.query.filter_by(
        group_id=current_user.group_id,
        user_id=member.id
    ).first()

    try:
        member.group_id = None
        if membership:
            db.session.delete(membership)

        db.session.commit()
        flash(f'{display_name(member)} was removed from the group')
    except Exception:
        db.session.rollback()
        flash('Failed to remove member')

    return redirect(url_for('account'))


def handle_create_group(user):
    name = request.form.get('name', '').strip()
    if not name:
        flash('Group name required')
        return render_template('group.html')

    for _ in range(5):
        code = secrets.token_hex(4).upper()
        new_group = Group(name=name, code=code)
        try:
            db.session.add(new_group)
            db.session.flush()

            user.group_id = new_group.id

            db.session.add(GroupMember(
                group_id=new_group.id,
                user_id=user.id,
                role='admin'
            ))

            db.session.commit()
            flash(f'Group created! Code: {code}')
            return redirect(url_for('home'))
        except IntegrityError:
            db.session.rollback()

    flash('Failed to create group, try again')
    return render_template('group.html')


def handle_join_group(user):
    code = request.form.get('code', '').strip().upper()
    if not code:
        flash('Group code required')
        return render_template('group.html')

    invite = GroupInvite.query.filter_by(code=code, accepted=False).first()

    if not invite:
        flash('Invalid or expired invite')
        return render_template('group.html')

    target_group = invite.group

    try:
        user.group_id = target_group.id


        db.session.add(GroupMember(
            group_id=target_group.id,
            user_id=user.id,
            role='member'
        ))

        invite.accepted = True

        db.session.commit()
        flash(f'Joined {target_group.name}!')
        return redirect(url_for('home'))
    except Exception:
        db.session.rollback()
        flash('Failed to join group')

    return render_template('group.html')


# =============================================================================
# PAGE ROUTES
# =============================================================================

@app.route('/')
@page_login_required
def home():
    return render_template('home.html', group=g.user.group)


@app.route('/chores')
@page_login_required
def chores():
    return render_template('chores.html', group=g.user.group)


@app.route('/groceries')
@page_login_required
def groceries():
    items = GroceryItem.query.filter_by(group_id=g.user.group_id).order_by(
        GroceryItem.purchased, GroceryItem.id.desc()
    ).all()
    return render_template('groceries.html', group=g.user.group, items=items)


@app.route('/expenses')
@page_login_required
def expenses():
    return render_template('expenses.html', group=g.user.group)


@app.route('/account')
@login_required
def account():
    user = g.user
    members = []
    if user.group_id:
        members = User.query.filter_by(group_id=user.group_id).all()

    return render_template(
        'account.html',
        user=user,
        display_name=display_name(user),
        members=members,
        is_admin=is_group_admin(user)
    )


@app.route('/account/update-username', methods=['POST'])
@login_required
def update_username():
    user = g.user
    data = request.get_json()
    new_username = data.get('username', '').strip() if data else ''
    if not new_username:
        return jsonify({'error': 'Username is required'}), 400
    if len(new_username) > 50:
        return jsonify({'error': 'Username must be 50 characters or less'}), 400
    user.username = new_username
    db.session.commit()
    return jsonify({'success': True, 'username': user.username})


@app.route('/account/update-email', methods=['POST'])
@login_required
def update_email():
    user = g.user
    data = request.get_json()
    new_email = data.get('email', '').strip().lower() if data else ''
    if not new_email or '@' not in new_email:
        return jsonify({'error': 'A valid email is required'}), 400
    if new_email == user.email:
        return jsonify({'success': True, 'email': user.email})
    existing = User.query.filter_by(email=new_email).first()
    if existing:
        return jsonify({'error': 'That email is already in use'}), 400
    user.email = new_email
    db.session.commit()
    return jsonify({'success': True, 'email': user.email})


# =============================================================================
# GROCERY API ROUTES
# =============================================================================

@app.route('/groceries/upload', methods=['POST'])
@api_login_required
def upload_receipt():
    try:
        image_bytes = extract_image_from_request()
        if not image_bytes:
            return jsonify({'error': 'No image provided'}), 400
        image_bytes = ensure_jpeg_bytes(image_bytes)
        image_bytes = preprocess_receipt_image(image_bytes)
        items = parse_receipt_with_claude(image_bytes)
        return jsonify({'items': items})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/groceries/add', methods=['POST'])
@api_login_required
def add_grocery():
    user = g.user
    data = request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Name required'}), 400
    price = data.get('price')
    quantity = data.get('quantity', 1)

    # Check for existing item with same name and price
    existing = GroceryItem.query.filter(
        GroceryItem.group_id == user.group_id,
        db.func.lower(GroceryItem.name) == name.lower(),
        GroceryItem.purchased == False
    ).first()

    if existing and existing.price == price:
        existing.quantity = (existing.quantity or 1) + (quantity or 1)
        db.session.commit()
        return jsonify({
            'id': existing.id, 'name': existing.name,
            'quantity': existing.quantity, 'price': existing.price,
            'merged': True
        })

    item = GroceryItem(
        name=name,
        quantity=quantity,
        price=price,
        group_id=user.group_id
    )
    db.session.add(item)
    db.session.commit()
    return jsonify({
        'id': item.id, 'name': item.name,
        'quantity': item.quantity, 'price': item.price,
        'merged': False
    })


@app.route('/groceries/bulk-add', methods=['POST'])
@api_login_required
def bulk_add_groceries():
    user = g.user
    data = request.get_json()
    added = []
    for item_data in data.get('items', []):
        if name := item_data.get('name', '').strip():
            item = GroceryItem(
                name=name,
                quantity=item_data.get('quantity', 1),
                price=item_data.get('price'),
                group_id=user.group_id
            )
            db.session.add(item)
            added.append(item)
    db.session.commit()
    return jsonify({'added': len(added)})


@app.route('/groceries/<int:item_id>', methods=['PUT', 'DELETE'])
@api_login_required
def modify_grocery(item_id):
    user = g.user
    item = GroceryItem.query.filter_by(id=item_id, group_id=user.group_id).first()
    if not item:
        return jsonify({'error': 'Item not found'}), 404
    if request.method == 'DELETE':
        db.session.delete(item)
        db.session.commit()
        return jsonify({'deleted': True})
    data = request.get_json()
    if 'name' in data:
        item.name = data['name']
    if 'quantity' in data:
        item.quantity = data['quantity']
    if 'price' in data:
        item.price = data['price']
    if 'purchased' in data:
        item.purchased = data['purchased']
    db.session.commit()
    return jsonify({'updated': True})


# =============================================================================
# CHORES API ROUTES
# =============================================================================

def chore_to_dict(chore):
    return {
        "choreId": chore.id,
        "name": chore.name,
        "assignedUsers": [
            {"user_id": u.id, "name": display_name(u)} for u in chore.assignments
        ],
        "lastCompletedBy": [
            {"user_id": c.user.id, "name": display_name(c.user)}
            for c in sorted(chore.completions, key=lambda x: x.completed_at, reverse=True)
        ],
        "createdBy": (
            {"user_id": chore.created_by_id, "name": "User"}
            if chore.created_by_id else None
        ),
        "nextDueBy": chore.next_due_date.isoformat() if chore.next_due_date else None,
        "completed": chore.completed,
    }


@app.route("/api/users", methods=["GET"])
@api_login_required
def get_users():
    group_users = User.query.filter_by(group_id=g.user.group_id).all()
    return jsonify([{"user_id": u.id, "name": display_name(u)} for u in group_users])


@app.route("/api/chores", methods=["GET", "POST"])
@api_login_required
def chores_api():
    user = g.user

    if request.method == "GET":
        all_chores = Chore.query.filter_by(group_id=user.group_id).order_by(
            Chore.completed, Chore.next_due_date
        ).all()
        return jsonify([chore_to_dict(c) for c in all_chores])

    data = request.get_json()
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    next_due_str = data.get("nextDueBy")
    next_due = date.fromisoformat(next_due_str) if next_due_str else None
    assigned_ids = data.get("assignedUserIds", [])
    assigned_users = User.query.filter(
        User.id.in_(assigned_ids), User.group_id == user.group_id
    ).all()

    chore = Chore(
        name=name,
        group_id=user.group_id,
        created_by_id=user.id,
        next_due_date=next_due,
        completed=False
    )
    chore.assignments.extend(assigned_users)
    db.session.add(chore)
    db.session.commit()
    return jsonify(chore_to_dict(chore)), 201


@app.route("/api/chores/<int:chore_id>/complete", methods=["POST"])
@api_login_required
def complete_chore_route(chore_id):
    user = g.user
    chore = Chore.query.filter_by(id=chore_id, group_id=user.group_id).first()
    if not chore:
        return jsonify({"error": "chore not found"}), 404
    chore.completed = True
    db.session.add(ChoreCompletion(user_id=user.id, chore_id=chore.id))
    db.session.commit()
    return jsonify(chore_to_dict(chore))


@app.route("/api/chores/<int:chore_id>/auto-assign", methods=["POST"])
@api_login_required
def auto_assign_chore_route(chore_id):
    user = g.user
    chore = Chore.query.filter_by(id=chore_id, group_id=user.group_id).first()
    if not chore:
        return jsonify({"error": "chore not found"}), 404

    data = request.get_json() or {}
    completed_by_id = data.get("completedByUserID")
    completing_user = None
    if completed_by_id:
        completing_user = User.query.filter_by(
            id=completed_by_id, group_id=user.group_id
        ).first()
    if not completing_user:
        completing_user = user

    db.session.add(ChoreCompletion(user_id=completing_user.id, chore_id=chore.id))

    if chore.assignments:
        users = list(chore.assignments)
        users.append(users.pop(0))  # rotate: move first to end
        chore.assignments = users

    chore.completed = False

    next_person = chore.assignments[0] if chore.assignments else None
    group_members = User.query.filter_by(group_id=user.group_id).all()
    for member in group_members:
        create_notification(
            user_id=member.id,
            group_id=member.group_id,
            notif_type="chore",
            title="Chore Rotated 🧹",
            message=f'"{chore.name}" was completed by {display_name(completing_user)}' + (f' and is now assigned to {display_name(next_person)}.' if next_person else '.'),
            related_id=chore_id
        )
    db.session.commit()
    return jsonify(chore_to_dict(chore))


@app.route("/api/chores/<int:chore_id>", methods=["DELETE"])
@api_login_required
def delete_chore(chore_id):
    user = g.user

    chore = Chore.query.filter_by(id=chore_id, group_id=user.group_id).first()
    if not chore:
        return jsonify({"error": "Chore not found"}), 404

    chore_name = chore.name
    db.session.delete(chore)

    group_members = User.query.filter_by(group_id=user.group_id).all()
    for member in group_members:
        create_notification(
            user_id=member.id,
            group_id=user.group_id,
            notif_type="chore",
            title="Chore Deleted 🧹",
            message=f'"{chore_name}" was deleted by {display_name(user)}.',
            related_id=chore_id
        )

    db.session.commit()
    return jsonify({"deleted": True})


# =============================================================================
# EXPENSES API ROUTES
# =============================================================================

@app.route('/api/expenses', methods=['GET'])
@api_login_required
def get_expenses():
    user = g.user

    all_expenses = Expense.query.filter_by(group_id=user.group_id).order_by(
        Expense.date.desc(), Expense.created_at.desc()
    ).all()

    return jsonify([{
        'expenseId': e.id,
        'description': e.description,
        'amount': float(e.amount),
        'date': e.date.isoformat(),
        'paidBy': {'user_id': e.paid_by_user_id, 'name': display_name(e.paid_by)},
        'splits': [{
            'user_id': s.user_id,
            'user_name': display_name(s.user),
            'percentage': float(s.percentage),
            'amount': float(s.amount)
        } for s in e.splits],
        'payments': [{
            'payment_id': p.id,
            'user_id': p.user_id,
            'amount_cents': p.amount_cents,
            'status': p.status,
            'transaction_id': p.stripe_session_id,
            'created_at': p.created_at.isoformat() if p.created_at else None
        } for p in e.payments]
    } for e in all_expenses])


@app.route('/api/expenses', methods=['POST'])
@api_login_required
def create_expense():
    user = g.user

    data = request.get_json()
    paid_by_user = User.query.filter_by(
        id=data['paidByUserId'], group_id=user.group_id
    ).first()
    if not paid_by_user:
        return jsonify({'error': 'Invalid user'}), 400

    expense = Expense(
        description=data['description'],
        amount=float(data['amount']),
        date=date.fromisoformat(data['date']),
        paid_by_user_id=data['paidByUserId'],
        group_id=user.group_id
    )
    db.session.add(expense)
    db.session.flush()

    for split in data['splits']:
        db.session.add(ExpenseSplit(
            expense_id=expense.id,
            user_id=split['user_id'],
            percentage=float(split['percentage']),
            amount=float(data['amount']) * (float(split['percentage']) / 100.0)
        ))

    db.session.commit()
    return jsonify({'expenseId': expense.id}), 201


@app.route('/api/expenses/<int:expense_id>', methods=['PUT'])
@api_login_required
def update_expense(expense_id):
    user = g.user

    expense = Expense.query.filter_by(id=expense_id, group_id=user.group_id).first()
    if not expense:
        return jsonify({'error': 'Expense not found'}), 404

    data = request.get_json()
    old_amount = float(expense.amount)
    expense.description = data['description']
    expense.amount = float(data['amount'])
    expense.date = date.fromisoformat(data['date'])
    expense.paid_by_user_id = data['paidByUserId']

    if old_amount != float(data['amount']):
        for split in expense.splits:
            split.amount = float(data['amount']) * (float(split.percentage) / 100.0)

    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/expenses/<int:expense_id>', methods=['DELETE'])
@api_login_required
def delete_expense(expense_id):
    user = g.user

    expense = Expense.query.filter_by(id=expense_id, group_id=user.group_id).first()
    if not expense:
        return jsonify({'error': 'Expense not found'}), 404

    db.session.delete(expense)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/expenses/<int:expense_id>/remind/<int:user_id>', methods=['POST'])
@api_login_required
def send_expense_reminder(expense_id, user_id):
    current_user = g.user

    expense = Expense.query.filter_by(id=expense_id, group_id=current_user.group_id).first()
    if not expense:
        return jsonify({'error': 'Expense not found'}), 404

    split = ExpenseSplit.query.filter_by(expense_id=expense_id, user_id=user_id).first()
    if not split:
        return jsonify({'error': 'User not part of this expense'}), 404

    if user_id == expense.paid_by_user_id:
        return jsonify({'error': 'Cannot remind the person who paid'}), 400

    debtor = db.session.get(User, user_id)
    creditor = expense.paid_by

    success = send_expense_reminder_email(
        debtor_email=debtor.email,
        debtor_name=display_name(debtor),
        creditor_name=display_name(creditor),
        amount=split.amount,
        description=expense.description
    )

    if success:
        db.session.add(ExpenseReminder(
            expense_id=expense_id,
            split_id=split.id,
            reminder_type='manual'
        ))
        db.session.commit()
        return jsonify({'success': True, 'message': f'Reminder sent to {display_name(debtor)}'}), 200

    return jsonify({'error': 'Failed to send reminder'}), 500


# =============================================================================
# STRIPE / PAYMENT ROUTES
# =============================================================================

@app.route("/api/expenses/<int:expense_id>/pay", methods=["POST"])
@api_login_required
def pay_expense(expense_id):
    user = g.user

    expense = Expense.query.filter_by(id=expense_id, group_id=user.group_id).first()
    if not expense:
        return jsonify({"error": "Expense not found"}), 404

    split = ExpenseSplit.query.filter_by(expense_id=expense.id, user_id=user.id).first()
    if not split:
        return jsonify({"error": "You are not part of this expense"}), 403

    amount_cents = int(round(float(split.amount) * 100))
    if amount_cents <= 0:
        return jsonify({"error": "Nothing to pay for this expense"}), 400

    if Payment.query.filter_by(
        user_id=user.id, group_id=user.group_id,
        expense_id=expense.id, status="completed"
    ).first():
        return jsonify({"error": "You already paid this expense"}), 400

    try:
        base_url = os.environ.get("BASE_URL", request.host_url.rstrip("/"))
        session_params = dict(
            mode="payment",
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {
                        "name": f"Expense: {expense.description}",
                        "description": f"Your share for expense #{expense.id}",
                    },
                    "unit_amount": amount_cents,
                },
                "quantity": 1,
            }],
            success_url=f"{base_url}/payments/success?redirect=expenses",
            cancel_url=f"{base_url}/payments/cancel?redirect=expenses",
            metadata={
                "type": "expense",
                "expense_id": str(expense.id),
                "user_id": str(user.id),
                "group_id": str(user.group_id),
            },
        )

        # Route payment to the expense creator's connected Stripe account
        creditor = expense.paid_by
        if creditor.stripe_account_id:
            session_params["payment_intent_data"] = {
                "transfer_data": {"destination": creditor.stripe_account_id}
            }

        checkout_session = stripe.checkout.Session.create(**session_params)
    except Exception as e:
        return jsonify({"error": f"Stripe error: {str(e)}"}), 500

    payment = Payment(
        user_id=user.id,
        group_id=user.group_id,
        expense_id=expense.id,
        amount_cents=amount_cents,
        currency="usd",
        status="pending",
        stripe_session_id=checkout_session.id,
    )
    db.session.add(payment)
    db.session.commit()

    return jsonify({
        "success": True,
        "checkout_url": checkout_session.url,
    }), 201


@app.route("/groceries/pay", methods=["POST"])
@api_login_required
def pay_groceries():
    user = g.user

    data = request.get_json()
    item_ids = data.get("item_ids", [])
    recipient_user_id = data.get("recipient_user_id")
    if not item_ids:
        return jsonify({"error": "No items selected"}), 400

    # Validate recipient
    recipient = None
    if recipient_user_id:
        recipient = User.query.filter_by(id=recipient_user_id, group_id=user.group_id).first()
        if not recipient:
            return jsonify({"error": "Invalid recipient"}), 400

    items = GroceryItem.query.filter(
        GroceryItem.id.in_(item_ids),
        GroceryItem.group_id == user.group_id
    ).all()

    if not items:
        return jsonify({"error": "No valid items found"}), 404

    total_cents = 0
    line_items = []
    for item in items:
        price = item.price or 0
        qty = item.quantity or 1
        item_total_cents = int(round(price * qty * 100))
        if item_total_cents <= 0:
            continue
        total_cents += item_total_cents
        line_items.append({
            "price_data": {
                "currency": "usd",
                "product_data": {"name": item.name},
                "unit_amount": int(round(price * 100)),
            },
            "quantity": qty,
        })

    if not line_items:
        return jsonify({"error": "Selected items have no price"}), 400

    try:
        base_url = os.environ.get("BASE_URL", request.host_url.rstrip("/"))
        session_params = dict(
            mode="payment",
            payment_method_types=["card"],
            line_items=line_items,
            success_url=f"{base_url}/payments/success?redirect=groceries",
            cancel_url=f"{base_url}/payments/cancel?redirect=groceries",
            metadata={
                "type": "grocery",
                "item_ids": ",".join(str(i) for i in item_ids),
                "user_id": str(user.id),
                "group_id": str(user.group_id),
            },
        )

        # Route payment to recipient's connected Stripe account
        if recipient and recipient.stripe_account_id:
            session_params["payment_intent_data"] = {
                "transfer_data": {"destination": recipient.stripe_account_id}
            }

        checkout_session = stripe.checkout.Session.create(**session_params)
    except Exception as e:
        return jsonify({"error": f"Stripe error: {str(e)}"}), 500

    payment = Payment(
        user_id=user.id,
        group_id=user.group_id,
        amount_cents=total_cents,
        currency="usd",
        status="pending",
        stripe_session_id=checkout_session.id,
    )
    db.session.add(payment)
    db.session.commit()

    return jsonify({"success": True, "checkout_url": checkout_session.url}), 201


@app.route("/payments/success")
@login_required
def payments_success():
    redirect_to = request.args.get("redirect", "home")
    flash("Payment successful!")
    return redirect(url_for(redirect_to))


@app.route("/payments/cancel")
@login_required
def payments_cancel():
    redirect_to = request.args.get("redirect", "home")
    flash("Payment was cancelled.")
    return redirect(url_for(redirect_to))


@app.route("/payments/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature")
    endpoint_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
    try:
        event = stripe.Webhook.construct_event(
            payload=payload, sig_header=sig_header, secret=endpoint_secret
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    if event["type"] == "checkout.session.completed":
        s = event["data"]["object"]
        p = Payment.query.filter_by(stripe_session_id=s["id"]).first()
        if p:
            p.status = "completed"
            p.stripe_payment_intent_id = s.get("payment_intent")
            db.session.commit()

            # If grocery payment, mark items as purchased
            metadata = s.get("metadata", {})
            if metadata.get("type") == "grocery" and metadata.get("item_ids"):
                item_ids = [int(x) for x in metadata["item_ids"].split(",")]
                GroceryItem.query.filter(GroceryItem.id.in_(item_ids)).update(
                    {"purchased": True}, synchronize_session="fetch"
                )
                db.session.commit()

    return jsonify({"received": True}), 200


# =============================================================================
# ACCOUNT MANAGEMENT ROUTES
# =============================================================================

@app.route("/account/connect-stripe", methods=["POST"])
@login_required
def connect_stripe():
    user = g.user

    try:
        # Create a Stripe Express connected account
        acct = stripe.Account.create(
            type="express",
            email=user.email,
            capabilities={
                "card_payments": {"requested": True},
                "transfers": {"requested": True},
            },
        )

        user.stripe_account_id = acct.id
        db.session.commit()

        base_url = os.environ.get("BASE_URL", request.host_url.rstrip("/"))
        link = stripe.AccountLink.create(
            account=acct.id,
            refresh_url=f"{base_url}/account/stripe-callback?refresh=1",
            return_url=f"{base_url}/account/stripe-callback",
            type="account_onboarding",
        )
        return jsonify({"url": link.url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/account/stripe-callback")
@login_required
def stripe_callback():
    user = g.user

    if request.args.get("refresh"):
        # User needs to restart onboarding
        if user.stripe_account_id:
            try:
                base_url = os.environ.get("BASE_URL", request.host_url.rstrip("/"))
                link = stripe.AccountLink.create(
                    account=user.stripe_account_id,
                    refresh_url=f"{base_url}/account/stripe-callback?refresh=1",
                    return_url=f"{base_url}/account/stripe-callback",
                    type="account_onboarding",
                )
                return redirect(link.url)
            except Exception:
                pass

    flash("Stripe account connected successfully!")
    return redirect(url_for("account"))


@app.route("/account/disconnect-stripe", methods=["POST"])
@login_required
def disconnect_stripe():
    user = g.user

    user.stripe_account_id = None
    db.session.commit()
    return jsonify({"success": True})


@app.route("/account/delete", methods=["POST"])
@login_required
def delete_account():
    user = g.user

    # Clean up group membership and notifications before deleting
    if user.group_id:
        from sqlalchemy import text as sa_text
        membership = GroupMember.query.filter_by(group_id=user.group_id, user_id=user.id).first()
        if membership:
            db.session.delete(membership)
        user.group_id = None
    Notification.query.filter_by(user_id=user.id).delete()

    db.session.delete(user)
    db.session.commit()
    session.clear()
    flash("Your account has been deleted.")
    return redirect(url_for("login"))



#=============================================================================
# NOTIFICATION ROUTES
#=============================================================================
@app.route('/notifications')
@page_login_required
def notifications_page():
    return render_template('notifications.html', group=g.user.group)

@app.route('/api/notifications', methods=['GET'])
@api_login_required
def get_notifications():
    notifs = Notification.query.filter_by(user_id=g.user.id).order_by(Notification.created_at.desc()).limit(50).all()
    return jsonify([{
        'id': n.id, 'type': n.type, 'title': n.title,
        'message': n.message, 'is_read': n.is_read,
        'related_id': n.related_id,
        'created_at': n.created_at.isoformat()
    } for n in notifs])

@app.route('/api/notifications/unread-count', methods=['GET'])
@api_login_required
def get_unread_count():
    count = Notification.query.filter_by(user_id=g.user.id, is_read=False).count()
    return jsonify({'count': count})

@app.route('/api/notifications/<int:notif_id>/read', methods=['POST'])
@api_login_required
def mark_notification_read(notif_id):
    notif = Notification.query.filter_by(id=notif_id, user_id=g.user.id).first()
    if not notif:
        return jsonify({'error': 'Not found'}), 404
    notif.is_read = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/notifications/read-all', methods=['POST'])
@api_login_required
def mark_all_read():
    Notification.query.filter_by(user_id=g.user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    return jsonify({'success': True})


@app.route("/api/payments/summary", methods=["GET"])
@api_login_required
def get_payments_summary():
    user = g.user

    expenses = Expense.query.filter_by(group_id=user.group_id).all()

    you_owe = 0.0
    you_are_owed = 0.0

    for expense in expenses:
        # find all splits for this expense
        splits = expense.splits
        if not splits:
            continue

        # is current user part of this expense?
        current_user_split = next((s for s in splits if s.user_id == user.id), None)
        if not current_user_split:
            continue

        # if current user paid, others owe them
        if expense.paid_by_user_id == user.id:
            for split in splits:
                if split.user_id != user.id:
                    you_are_owed += float(split.amount)

        # if someone else paid, current user owes their split
        else:
            you_owe += float(current_user_split.amount)

    net_balance = you_are_owed - you_owe

    return jsonify({
        "youOwe": round(you_owe, 2),
        "youAreOwed": round(you_are_owed, 2),
        "netBalance": round(net_balance, 2)
    }), 200


# =============================================================================
# INIT
# =============================================================================

with app.app_context():
    db.create_all()
    # Migrate: add new columns to existing tables if missing
    with db.engine.connect() as conn:
        try:
            conn.execute(db.text("ALTER TABLE users ADD COLUMN stripe_account_id VARCHAR(255)"))
            conn.commit()
        except Exception:
            conn.rollback()  # Column already exists
        try:
            conn.execute(db.text(
                "CREATE TABLE IF NOT EXISTS payments ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "group_id INTEGER NOT NULL, "
                "expense_id INTEGER, "
                "amount_cents INTEGER NOT NULL, "
                "currency VARCHAR(3) DEFAULT 'usd', "
                "status VARCHAR(20) DEFAULT 'pending', "
                "stripe_session_id VARCHAR(255) UNIQUE NOT NULL, "
                "stripe_payment_intent_id VARCHAR(255), "
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
            ))
            conn.commit()
        except Exception:
            conn.rollback()

        try:
            conn.execute(db.text(
                "CREATE TABLE IF NOT EXISTS notifications ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "group_id INTEGER NOT NULL, "
                "type VARCHAR(50) NOT NULL, "
                "title VARCHAR(200) NOT NULL, "
                "message VARCHAR(500) NOT NULL, "
                "is_read BOOLEAN DEFAULT FALSE, "
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
                "related_id INTEGER)"
            ))
            conn.commit()
        except Exception:
            conn.rollback()

        # Add username column to users table (migration for existing databases)
        try:
            conn.execute(db.text(
                "ALTER TABLE users ADD COLUMN username VARCHAR(50)"
            ))
            conn.commit()
        except Exception:
            conn.rollback()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
