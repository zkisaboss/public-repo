from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.exc import IntegrityError
import secrets
from PIL import Image
import io
import re
import base64

import os
from dotenv import load_dotenv



# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///household.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

db = SQLAlchemy(app)


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False, index=True)
    users = db.relationship('User', backref='group', lazy='dynamic')


class GroceryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    price = db.Column(db.Float, nullable=True)
    purchased = db.Column(db.Boolean, default=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)


# Auth helpers
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


# =============================================================================
# Grocery Receipt OCR - Google Document AI
# =============================================================================

from google.cloud import documentai_v1 as documentai

# Google Cloud configuration from environment variables
GOOGLE_CLOUD_PROJECT = os.environ.get('GOOGLE_CLOUD_PROJECT')
DOCUMENT_AI_LOCATION = os.environ.get('DOCUMENT_AI_LOCATION', 'us')
DOCUMENT_AI_PROCESSOR_ID = os.environ.get('DOCUMENT_AI_PROCESSOR_ID')

# Credentials path - set via environment variable
if credentials_path := os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'):
    # Environment variable is already set, Google client will use it automatically
    pass

documentai_client = documentai.DocumentProcessorServiceClient()


def parse_receipt_with_document_ai(image_bytes):
    """Parse receipt image using Google Document AI Expense Parser."""
    if not all([GOOGLE_CLOUD_PROJECT, DOCUMENT_AI_PROCESSOR_ID]):
        raise ValueError("Missing required Google Cloud configuration")
    
    processor_name = documentai_client.processor_path(
        GOOGLE_CLOUD_PROJECT, DOCUMENT_AI_LOCATION, DOCUMENT_AI_PROCESSOR_ID
    )

    raw_document = documentai.RawDocument(content=image_bytes, mime_type="image/jpeg")
    request = documentai.ProcessRequest(name=processor_name, raw_document=raw_document)

    result = documentai_client.process_document(request=request)
    document = result.document

    items = []

    # Extract line items from the expense document
    for entity in document.entities:
        if entity.type_ == "line_item":
            item = {'name': '', 'quantity': 1, 'price': None}

            for prop in entity.properties:
                if prop.type_ == "line_item/description":
                    item['name'] = prop.mention_text.strip()
                elif prop.type_ == "line_item/quantity":
                    try:
                        item['quantity'] = int(float(prop.mention_text.strip()))
                    except (ValueError, TypeError):
                        item['quantity'] = 1
                elif prop.type_ == "line_item/amount":
                    try:
                        price_text = re.sub(r'[^\d.]', '', prop.mention_text)
                        item['price'] = float(price_text)
                    except (ValueError, TypeError):
                        item['price'] = None

            if item['name']:
                items.append(item)

    return items


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


# =============================================================================
# Grocery API Routes
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
        items = parse_receipt_with_document_ai(image_bytes)

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


# Init
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)