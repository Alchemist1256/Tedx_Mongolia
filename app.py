from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

# -----------------------
# Flask app setup
# -----------------------
app = Flask(__name__)

# -----------------------
# 1️⃣ Database URL (Supabase)
# Replace PASSWORD with your actual Supabase password
# If your password has special characters like $, URL-encode it (%24)
# Example: tedX123$adminPwd -> tedX123%24adminPwd
# -----------------------
DATABASE_URL = os.environ.get(
    'DATABASE_URL',
    'postgresql://postgres:tedX123%24adminPwd@db.iukbpbxmtyxynkfmyyxl.supabase.co:5432/postgres'
)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'connect_args': {'sslmode': 'require'}}

# -----------------------
# Secret key for session security
# -----------------------
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'Secret_Alchemist_randomkey_123$@')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# -----------------------
# Models
# -----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    tickets = db.relationship('Ticket', backref='user', lazy=True)

    def check_password(self, plain):
        return check_password_hash(self.password_hash, plain)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

# -----------------------
# Helpers
# -----------------------
def logged_in_user():
    email = session.get('user_email')
    if email:
        return User.query.filter_by(email=email).first()
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# -----------------------
# Initialize DB
# -----------------------
@app.before_request
def create_tables():
    db.create_all()

# -----------------------
# Routes
# -----------------------
@app.route('/')
def index():
    user = logged_in_user()
    return render_template('index.html', user=user)

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first = request.form.get('first_name', '').strip()
        last = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        error = None
        if not (first and last and email and phone and password and confirm):
            error = "All fields are required."
        elif not email.endswith('@gmail.com'):
            error = "Email must be a Gmail address."
        elif password != confirm:
            error = "Passwords do not match."
        elif User.query.filter_by(email=email).first():
            error = "Email already registered."

        if error:
            return render_template('signup.html', error=error,
                                   first=first, last=last, email=email, phone=phone)

        user = User(
            first_name=first,
            last_name=last,
            email=email,
            phone=phone,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        session['user_email'] = email
        return redirect(url_for('index'))

    return render_template('signup.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_email'] = user.email
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid credentials", email=email)

    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.pop('user_email', None)
    session.pop('is_admin', None)
    session.pop('admin_name', None)
    return redirect(url_for('index'))

# Buy tickets
@app.route('/buy', methods=['GET', 'POST'])
def buy():
    user = logged_in_user()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        ticket = Ticket(user_id=user.id)
        db.session.add(ticket)
        db.session.commit()
        return render_template('buy_success.html', user=user)

    return render_template('buy.html', user=user)

# -----------------------
# Admin routes
# -----------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username == 'admin' and password == 'admin':
            session['is_admin'] = True
            session['admin_name'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html', error="Invalid admin credentials")
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    session.pop('admin_name', None)
    return redirect(url_for('index'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.created_at.desc()).all()
    ticket_users = User.query.join(Ticket).order_by(Ticket.created_at.desc()).all()
    return render_template(
        'admin.html',
        admin_name=session.get('admin_name'),
        users=users,
        ticket_users=ticket_users
    )

@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_detail.html', user=user)

# -----------------------
# Run
# -----------------------
if __name__ == '__main__':
    app.run(debug=True)
