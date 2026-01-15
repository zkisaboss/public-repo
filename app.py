from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.exc import IntegrityError
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///household.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False,
                      index=True)
    password = db.Column(db.String(200), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False, index=True)
    users = db.relationship('User', backref='group', lazy='dynamic')


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
    """Redirect if user lacks group membership."""
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
            redirect_url = (url_for('home') if user.group_id else url_for('group'))
            return redirect(redirect_url)

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
    return render_template('groceries.html', group=user.group)


# Init
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)