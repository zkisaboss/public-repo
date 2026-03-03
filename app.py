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

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from sqlalchemy.orm import relationship
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
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
if not database_url:
    raise ValueError("Missing POSTGRES_URL or DATABASE_URL environment variable")
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
    password = db.Column(db.String(255), nullable=True)  # Nullable for OAuth users
    auth_provider = db.Column(db.String(20), default='email')  # 'email', 'google'
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'))
    group = relationship('Group', backref='users')


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
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap


def get_current_user():
    if 'user_id' not in session:
        return None
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
    return user


@app.context_processor
def inject_user():
    return dict(current_user=get_current_user())


def require_group(user):
    return None if user.group_id else redirect(url_for('group'))


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
                    debtor_name=debtor.email.split('@')[0],
                    creditor_name=creditor.email.split('@')[0],
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
<<<<<<< HEAD
    - "price": line total (not unit price)
=======
    - "unit_price": price per single unit
    - "price": line total (qty × unit_price)
>>>>>>> 3590173c9a9322bef6c883cae56ef7b2502bee5d

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
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, password=None, auth_provider='google')
            db.session.add(user)
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

        user = User(email=email, password=generate_password_hash(password), auth_provider='email')
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
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    if user.group_id:
        return redirect(url_for('home'))
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            return handle_create_group(user)
        elif action == 'join':
            return handle_join_group(user)
    return render_template('group.html')


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
    target_group = Group.query.filter_by(code=code).first()
    if not target_group:
        flash('Invalid code')
        return render_template('group.html')
    try:
        user.group_id = target_group.id
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
@login_required
def home():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    if redirect_response := require_group(user):
        return redirect_response
    return render_template('home.html', group=user.group)


@app.route('/chores')
@login_required
def chores():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    if redirect_response := require_group(user):
        return redirect_response
    return render_template('chores.html', group=user.group)


@app.route('/groceries')
@login_required
def groceries():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    if redirect_response := require_group(user):
        return redirect_response
    items = GroceryItem.query.filter_by(group_id=user.group_id).order_by(
        GroceryItem.purchased, GroceryItem.id.desc()
    ).all()
    return render_template('groceries.html', group=user.group, items=items)


@app.route('/expenses')
@login_required
def expenses():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    if redirect_response := require_group(user):
        return redirect_response
    return render_template('expenses.html', group=user.group)


@app.route('/payments')
@login_required
def payments():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    if redirect_response := require_group(user):
        return redirect_response
    return render_template('payments.html', group=user.group)


# =============================================================================
# GROCERY API ROUTES
# =============================================================================

@app.route('/groceries/upload', methods=['POST'])
@login_required
def upload_receipt():
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        image_bytes = extract_image_from_request()
        if not image_bytes:
            return jsonify({'error': 'No image provided'}), 400
        image_bytes = ensure_jpeg_bytes(image_bytes)
        items = parse_receipt_with_claude(image_bytes)
        return jsonify({'items': items})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/groceries/add', methods=['POST'])
@login_required
def add_grocery():
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Name required'}), 400
    item = GroceryItem(
        name=name,
        quantity=data.get('quantity', 1),
        price=data.get('price'),
        group_id=user.group_id
    )
    db.session.add(item)
    db.session.commit()
    return jsonify({'id': item.id, 'name': item.name, 'quantity': item.quantity, 'price': item.price})


@app.route('/groceries/bulk-add', methods=['POST'])
@login_required
def bulk_add_groceries():
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
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
@login_required
def modify_grocery(item_id):
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
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
            {"user_id": u.id, "name": u.email.split('@')[0]} for u in chore.assignments
        ],
        "lastCompletedBy": [
            {"user_id": c.user.id, "name": c.user.email.split('@')[0]}
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
@login_required
def get_users():
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify([])
    group_users = User.query.filter_by(group_id=user.group_id).all()
    return jsonify([{"user_id": u.id, "name": u.email.split('@')[0]} for u in group_users])


@app.route("/api/chores", methods=["GET", "POST"])
@login_required
def chores_api():
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401

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
@login_required
def complete_chore_route(chore_id):
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
    chore = Chore.query.filter_by(id=chore_id, group_id=user.group_id).first()
    if not chore:
        return jsonify({"error": "chore not found"}), 404
    chore.completed = True
    db.session.add(ChoreCompletion(user_id=user.id, chore_id=chore.id))
    db.session.commit()
    return jsonify(chore_to_dict(chore))


@app.route("/api/chores/<int:chore_id>/auto-assign", methods=["POST"])
@login_required
def auto_assign_chore_route(chore_id):
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
    chore = Chore.query.filter_by(id=chore_id, group_id=user.group_id).first()
    if not chore:
        return jsonify({"error": "chore not found"}), 404
    if chore.assignments:
        users = list(chore.assignments)
        users.append(users.pop(0))  # rotate: move first to end
        chore.assignments = users
    chore.completed = False
    db.session.commit()
    return jsonify(chore_to_dict(chore))


# =============================================================================
# PAYMENTS / STRIPE ROUTES
# =============================================================================

@app.route("/payments/create-checkout-session", methods=["POST"])
@login_required
def create_checkout_session():
    user = get_current_user()
    if not user or not user.group_id:
        flash("You must be in a group to pay.")
        return redirect(url_for("payments"))

    amount_cents = int(request.form.get("amount_cents", "500"))
    base_url = os.environ.get("BASE_URL", request.host_url.rstrip("/"))

    checkout_session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[{
            "price_data": {
                "currency": "usd",
                "product_data": {"name": "RoomSync payment"},
                "unit_amount": amount_cents,
            },
            "quantity": 1,
        }],
        success_url=f"{base_url}/payments/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{base_url}/payments/cancel",
        metadata={"user_id": str(user.id), "group_id": str(user.group_id)},
    )

    p = Payment(
        user_id=user.id,
        group_id=user.group_id,
        amount_cents=amount_cents,
        currency="usd",
        status="pending",
        stripe_session_id=checkout_session.id
    )
    db.session.add(p)
    db.session.commit()
    return redirect(checkout_session.url, code=303)


@app.route("/payments/success")
@login_required
def payments_success():
    session_id = request.args.get("session_id")
    return render_template("payment_success.html", session_id=session_id)


@app.route("/payments/cancel")
@login_required
def payments_cancel():
    return render_template("payment_cancel.html")


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
            p.status = "confirmed"
            p.stripe_payment_intent_id = s.get("payment_intent")
            db.session.commit()

    return jsonify({"received": True}), 200


# =============================================================================
# EXPENSES API ROUTES
# =============================================================================

@app.route('/api/expenses', methods=['GET'])
@login_required
def get_expenses():
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401

    all_expenses = Expense.query.filter_by(group_id=user.group_id).order_by(
        Expense.date.desc(), Expense.created_at.desc()
    ).all()

    return jsonify([{
        'expenseId': e.id,
        'description': e.description,
        'amount': float(e.amount),
        'date': e.date.isoformat(),
        'paidBy': {'user_id': e.paid_by_user_id, 'name': e.paid_by.email.split('@')[0]},
        'splits': [{
            'user_id': s.user_id,
            'user_name': s.user.email.split('@')[0],
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
@login_required
def create_expense():
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401

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
@login_required
def update_expense(expense_id):
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401

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
@login_required
def delete_expense(expense_id):
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401

    expense = Expense.query.filter_by(id=expense_id, group_id=user.group_id).first()
    if not expense:
        return jsonify({'error': 'Expense not found'}), 404

    db.session.delete(expense)
    db.session.commit()
    return jsonify({'success': True})


@app.route("/api/expenses/<int:expense_id>/pay", methods=["POST"])
@login_required
def pay_expense(expense_id):
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({"error": "Unauthorized"}), 401

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
        checkout_session = stripe.checkout.Session.create(
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
            success_url=url_for("payments_success", _external=True)
                        + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("payments_cancel", _external=True),
            metadata={
                "expense_id": str(expense.id),
                "user_id": str(user.id),
                "group_id": str(user.group_id),
            },
        )
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
        "payment": {
            "payment_id": payment.id,
            "expense_id": payment.expense_id,
            "amount_cents": payment.amount_cents,
            "status": payment.status,
            "transaction_id": payment.stripe_session_id,
            "created_at": payment.created_at.isoformat() if payment.created_at else None
        }
    }), 201


@app.route('/api/expenses/<int:expense_id>/remind/<int:user_id>', methods=['POST'])
@login_required
def send_expense_reminder(expense_id, user_id):
    current_user = get_current_user()
    if not current_user or not current_user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401

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
        debtor_name=debtor.email.split('@')[0],
        creditor_name=creditor.email.split('@')[0],
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
        return jsonify({'success': True, 'message': f'Reminder sent to {debtor.email.split("@")[0]}'}), 200

    return jsonify({'error': 'Failed to send reminder'}), 500


@app.route("/api/payments", methods=["GET"])
@login_required
def get_payments():
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({"error": "Unauthorized"}), 401

    all_payments = Payment.query.filter_by(group_id=user.group_id).order_by(
        Payment.created_at.desc()
    ).all()

    result = []
    for p in all_payments:
        payer = db.session.get(User, p.user_id)
        status = (p.status or "pending").lower()
        if status in ("paid", "succeeded", "success"):
            status = "completed"
        result.append({
            "payment_id": p.id,
            "expense_id": p.expense_id,
            "payer_user_id": p.user_id,
            "payer_name": payer.email.split("@")[0] if payer else str(p.user_id),
            "amount": (float(p.amount_cents) / 100.0) if p.amount_cents is not None else 0.0,
            "currency": p.currency or "usd",
            "status": status,
            "transaction_id": p.stripe_session_id,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        })

    return jsonify(result), 200


# =============================================================================
# INIT
# =============================================================================

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
