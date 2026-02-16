from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.exc import IntegrityError

db = SQLAlchemy()

# --- MODELS --- (In-lined to avoid missing files)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'))
    group = relationship('Group', backref='users')

class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=False)

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

class Expense(db.Model):
    __tablename__ = 'expenses'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, nullable=False)
    paid_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    paid_by = relationship('User', foreign_keys=[paid_by_user_id])
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    splits = relationship('ExpenseSplit', backref='expense', cascade="all, delete-orphan")
    payments = relationship('Payment', backref='expense', lazy=True)


class ExpenseSplit(db.Model):
    __tablename__ = 'expense_splits'
    id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey('expenses.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', foreign_keys=[user_id])
    percentage = db.Column(db.Float, nullable=False)
    amount = db.Column(db.Float, nullable=False)

# Chore models
chore_assignments = db.Table('chore_assignments',
    db.Column('chore_id', db.Integer, db.ForeignKey('chores.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True)
)

class Chore(db.Model):
    __tablename__ = 'chores'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    next_due_date = db.Column(db.Date) # stored as date
    completed = db.Column(db.Boolean, default=False)
    # last_completed_by logic: simple string or FK for now
    last_completed_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    last_completed_by = relationship('User', foreign_keys=[last_completed_by_id])
    assignees = relationship('User', secondary=chore_assignments, backref='assigned_chores')


# Auth helpers
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap
import os
import sys
import secrets
import stripe
import json
import base64
import re
import io

from datetime import datetime, date
from dotenv import load_dotenv
from PIL import Image
import anthropic

# Load environment variables
load_dotenv()

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
print("Stripe key loaded:", stripe.api_key)
print("STRIPE KEY starts with:", (stripe.api_key or "")[:12])

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')


# Database Configuration
database_url = os.environ.get('POSTGRES_URL') or os.environ.get('DATABASE_URL')

if not database_url:
    raise ValueError("Missing POSTGRES_URL or DATABASE_URL environment variable")

# Fix incompatible postgres:// scheme for SQLAlchemy if present
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
print(f"Using database: {database_url.split('@')[0]}...", file=sys.stderr)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


db.init_app(app)
# --- CHORES API ---

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    users = User.query.filter_by(group_id=user.group_id).all()
    # Filter out current user? Typically optional but UI allows multi select so list all.
    return jsonify([
        {'user_id': u.id, 'name': u.email.split('@')[0]} 
        for u in users
    ])


@app.route('/api/chores', methods=['GET'])
@login_required
def get_chores():
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    chores = Chore.query.filter_by(group_id=user.group_id).order_by(Chore.next_due_date).all()
    result = []
    for chore in chores:
        result.append({
            'choreId': chore.id,
            'name': chore.name,
            # Format date as YYYY-MM-DD
            'nextDueBy': chore.next_due_date.isoformat() if chore.next_due_date else None,
            'completed': chore.completed,
            'assignedUsers': [{'name': u.email.split('@')[0]} for u in chore.assignees],
            'lastCompletedBy': [{'name': chore.last_completed_by.email.split('@')[0]}] if chore.last_completed_by else []
        })
    return jsonify(result)

@app.route('/api/chores', methods=['POST'])
@login_required
def create_chore():
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    name = data.get('name')
    if not name:
        return jsonify({'error': 'Name required'}), 400
        
    next_due = None
    if val := data.get('nextDueBy'):
        try:
            next_due = date.fromisoformat(val)
        except ValueError:
            pass
            
    chore = Chore(
        name=name,
        group_id=user.group_id,
        next_due_date=next_due
    )
    
    if 'assignedUserIds' in data:
        ids = data['assignedUserIds']
        # Ensure ids is a list of methods
        if isinstance(ids, list):
           users = User.query.filter(User.id.in_(ids)).all()
           chore.assignees.extend(users)
        
    db.session.add(chore)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/chores/<int:chore_id>/complete', methods=['POST'])
@login_required
def complete_chore(chore_id):
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    chore = Chore.query.filter_by(id=chore_id, group_id=user.group_id).first()
    if not chore:
        return jsonify({'error': 'Chore not found'}), 404
        
    chore.completed = True
    chore.last_completed_by = user
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/chores/<int:chore_id>/auto-assign', methods=['POST'])
@login_required
def auto_assign_chore(chore_id):
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401

    chore = Chore.query.filter_by(id=chore_id, group_id=user.group_id).first()
    if not chore:
        return jsonify({'error': 'Chore not found'}), 404
    
    # Just reset completion for now
    chore.completed = False
    db.session.commit()
    return jsonify({'success': True})


def get_current_user():
    if 'user_id' not in session:
        return None
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
    return user


def require_group(user):
    return None if user.group_id else redirect(url_for('group'))


# Auth routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not email or not password:
            flash('Email and password required')
            return render_template('login.html')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('home') if user.group_id else url_for('group'))
        flash('Invalid credentials')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not email or not password:
            flash('Email and password required')
            return render_template('register.html')
        if len(password) < 6:
            flash('Password must be at least 6 characters')
            return render_template('register.html')
        user = User(email=email, password=generate_password_hash(password))
        try:
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return redirect(url_for('group'))
        except IntegrityError:
            db.session.rollback()
            flash('Email already exists')
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

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
        metadata={
            "user_id": str(user.id),
            "group_id": str(user.group_id),
        },
    )


    # Save a "pending" record now 
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
        session_id = s["id"]
        payment_intent_id = s.get("payment_intent")

        # Find the pending record and mark confirmed
        p = Payment.query.filter_by(stripe_session_id=session_id).first()
        if p:
            p.status = "confirmed"
            p.stripe_payment_intent_id = payment_intent_id
            db.session.commit()

    return jsonify({"received": True}), 200




# Group management
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


# App routes
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

# Grocery Receipt OCR - Anthropic Claude



ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY')

def parse_receipt_with_claude(image_bytes):
    """Parse receipt image using Anthropic Claude."""
    if not ANTHROPIC_API_KEY:
        raise ValueError("Missing ANTHROPIC_API_KEY environment variable")
    
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    
    # Encode image to base64
    image_base64 = base64.b64encode(image_bytes).decode('utf-8')
    
    prompt = """
    Extract grocery items as JSON: {"items": [...]}
    
    Each item:
    - "name": item name only (exclude codes/quantities)
    - "amt": quantity (parse from EA/QTY/@, default 1)
    - "price": line total (not unit price)
    
    Ignore tax/subtotals. JSON only.
    """

    # Model selection
    CLAUDE_HAIKU = "claude-haiku-4-5-20251001"    # $1/$5 - Fastest, cheapest
    CLAUDE_SONNET = "claude-sonnet-4-5-20250929"  # $3/$15 - Balanced (recommended)
    CLAUDE_OPUS = "claude-opus-4-5-20251101"      # $5/$25 - Highest accuracy

    message = client.messages.create(
        model=CLAUDE_SONNET,
        max_tokens=2048,
        messages=[
            {
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
                    {
                        "type": "text",
                        "text": prompt
                    }
                ],
            }
        ],
    )

    # Extract JSON from response
    response_text = message.content[0].text
    try:
        # Simple extraction in case Claude adds some text
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            raw_items = data.get('items', [])
            
            # Map 'amt' back to 'quantity' for internal app consistency
            items = []
            for item in raw_items:
                items.append({
                    'name': item.get('name', ''),
                    'quantity': item.get('amt', 1),
                    'price': item.get('price')
                })
            return items
        else:
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
    """Convert image bytes to JPEG format for Gemini API."""
    image = Image.open(io.BytesIO(image_bytes))
    if image.mode in ('RGBA', 'P'):
        image = image.convert('RGB')
    buffer = io.BytesIO()
    image.save(buffer, format='JPEG')
    return buffer.getvalue()


# Grocery API Routes


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

    return jsonify({
        'id': item.id, 'name': item.name,
        'quantity': item.quantity, 'price': item.price
    })


@app.route('/groceries/bulk-add', methods=['POST'])
@login_required
def bulk_add_groceries():
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    items_data = data.get('items', [])

    added = []
    for item_data in items_data:
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


# Chores API Routes are now in chores.py

# ===== Payment API Routes =====

@app.route("/payments")
@login_required
def payments():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    if redirect_response := require_group(user):
        return redirect_response
    return render_template("payments.html", group=user.group)


# ===== Expenses API Routes =====

@app.route('/api/expenses', methods=['GET'])
@login_required
def get_expenses():
    """Get all expenses for the household."""
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    expenses = Expense.query.filter_by(group_id=user.group_id).order_by(
        Expense.date.desc(), Expense.created_at.desc()
    ).all()
    
    result = []
    for expense in expenses:
        result.append({
            'expenseId': expense.id,
            'description': expense.description,
            'amount': float(expense.amount),
            'date': expense.date.isoformat(),
            'paidBy': {
                'user_id': expense.paid_by_user_id,
                'name': expense.paid_by.email.split('@')[0]
             },
             'splits': [{
                'user_id': s.user_id,
                'user_name': s.user.email.split('@')[0],
                'percentage': float(s.percentage),
                'amount': float(s.amount)
            } for s in expense.splits],

            'payments': [{
                'payment_id': p.id,
                'user_id': p.user_id,
                'amount_cents': p.amount_cents,
                'status': p.status,
                'transaction_id': p.stripe_session_id,
                'created_at': p.created_at.isoformat() if p.created_at else None
            } for p in expense.payments]
        })

    return jsonify(result)



@app.route("/api/payments", methods=["GET"])
@login_required
def get_payments():
    """Return payment history for the current user's group."""
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({"error": "Unauthorized"}), 401

    payments = (
        Payment.query
        .filter_by(group_id=user.group_id)
        .order_by(Payment.created_at.desc())
        .all()
    )

    result = []
    for p in payments:
        payer = User.query.get(p.user_id)

        status = (p.status or "pending").lower()
        if status in ["paid", "succeeded", "success"]:
            status = "completed"

        result.append({
            "payment_id": p.id,
            "expense_id": getattr(p, "expense_id", None),
            "payer_user_id": p.user_id,
            "payer_name": (payer.email.split("@")[0] if payer else str(p.user_id)),
            "amount": (float(p.amount_cents) / 100.0) if p.amount_cents is not None else 0.0,
            "currency": p.currency or "usd",
            "status": status,
            "transaction_id": p.stripe_session_id,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        })

    return jsonify(result), 200


    



@app.route('/api/expenses', methods=['POST'])
@login_required
def create_expense():
    """Create a new expense with splits."""
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    # Verify paid_by user belongs to group
    paid_by_user = User.query.filter_by(
        id=data['paidByUserId'], 
        group_id=user.group_id
    ).first()
    
    if not paid_by_user:
        return jsonify({'error': 'Invalid user'}), 400
    
    # Parse date string to date object
    expense_date = date.fromisoformat(data['date'])
    
    # Create expense
    expense = Expense(
        description=data['description'],
        amount=float(data['amount']),
        date=expense_date,
        paid_by_user_id=data['paidByUserId'],
        group_id=user.group_id
    )
    
    db.session.add(expense)
    db.session.flush()  # Get expense.id
    
    # Create splits
    for split in data['splits']:
        split_amount = float(data['amount']) * (float(split['percentage']) / 100.0)
        expense_split = ExpenseSplit(
            expense_id=expense.id,
            user_id=split['user_id'],
            percentage=float(split['percentage']),
            amount=split_amount
        )
        db.session.add(expense_split)
    
    db.session.commit()
    return jsonify({'expenseId': expense.id}), 201


@app.route('/api/expenses/<int:expense_id>', methods=['PUT'])
@login_required
def update_expense(expense_id):
    """Update an expense (does not change splits)."""
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    expense = Expense.query.filter_by(
        id=expense_id, 
        group_id=user.group_id
    ).first()
    
    if not expense:
        return jsonify({'error': 'Expense not found'}), 404
    
    data = request.get_json()
    old_amount = float(expense.amount)
    
    # Update expense
    expense.description = data['description']
    expense.amount = float(data['amount'])
    expense.date = date.fromisoformat(data['date'])
    expense.paid_by_user_id = data['paidByUserId']
    
    # Recalculate split amounts if amount changed
    if old_amount != float(data['amount']):
        for split in expense.splits:
            split.amount = float(data['amount']) * (float(split.percentage) / 100.0)
    
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/expenses/<int:expense_id>', methods=['DELETE'])
@login_required
def delete_expense(expense_id):
    """Delete an expense and its splits."""
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    expense = Expense.query.filter_by(
        id=expense_id, 
        group_id=user.group_id
    ).first()
    
    if not expense:
        return jsonify({'error': 'Expense not found'}), 404
    
    db.session.delete(expense)
    db.session.commit()
    return jsonify({'success': True})

@app.route("/api/expenses/<int:expense_id>/pay", methods=["POST"])
@login_required
def pay_expense(expense_id):
    """
    Create a Stripe Checkout Session for the current user's share of an expense,
    create a pending Payment record, and return checkout_url as JSON.
    """
    user = get_current_user()
    if not user or not user.group_id:
        return jsonify({"error": "Unauthorized"}), 401

    # Make sure expense is in the same group
    expense = Expense.query.filter_by(id=expense_id, group_id=user.group_id).first()
    if not expense:
        return jsonify({"error": "Expense not found"}), 404

    # Find this user's split for the expense
    split = ExpenseSplit.query.filter_by(expense_id=expense.id, user_id=user.id).first()
    if not split:
        return jsonify({"error": "You are not part of this expense"}), 403

    amount_cents = int(round(float(split.amount) * 100))
    if amount_cents <= 0:
        return jsonify({"error": "Nothing to pay for this expense"}), 400

    # Optional: prevent duplicate "completed" payment for same user+expense
    existing_paid = Payment.query.filter_by(
        user_id=user.id,
        group_id=user.group_id,
        expense_id=expense.id,
        status="completed"
    ).first()
    if existing_paid:
        return jsonify({"error": "You already paid this expense"}), 400

    # If you want: prevent multiple pending sessions piling up
    existing_pending = Payment.query.filter_by(
        user_id=user.id,
        group_id=user.group_id,
        expense_id=expense.id,
        status="pending"
    ).first()
    if existing_pending and existing_pending.stripe_session_id:
        # You could either reuse it (if you store URL) or just create new.
        # We'll just continue and create a new session.
        pass

    # ---------------------------
    # Stripe Checkout Session
    # ---------------------------

    try:
        checkout_session = stripe.checkout.Session.create(
            mode="payment",
            payment_method_types=["card"],
            line_items=[
                {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {
                            "name": f"Expense: {expense.description}",
                            "description": f"Your share for expense #{expense.id}",
                        },
                        "unit_amount": amount_cents,
                    },
                    "quantity": 1,
                }
            ],
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

    # ---------------------------
    # DB Payment record (pending)
    # ---------------------------
    payment = Payment(
        user_id=user.id,
        group_id=user.group_id,
        expense_id=expense.id,
        amount_cents=amount_cents,
        currency="usd",
        status="pending",
        stripe_session_id=checkout_session.id,   # IMPORTANT: store session ID, not url
    )

    db.session.add(payment)
    db.session.commit()

    # Return JSON so frontend can redirect:
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


# Init
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
