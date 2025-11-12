# app.py
from flask import Flask, render_template, session, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os
import requests
from sqlalchemy import text, inspect

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'postgresql://user:password@host:port/dbname'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ---------------- Models ----------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    tickets = db.relationship('Ticket', backref='user', lazy=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def check_password(self, plain):
        return self.password == plain

class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    order_id = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(50), default="pending")  # pending / paid
    created_at = db.Column(db.DateTime, server_default=db.func.now())

# ---------------- Helpers ----------------
def logged_in_user():
    email = session.get('user_email')
    if not email:
        return None
    return User.query.filter_by(email=email).first()

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

# ---------------- DB Setup ----------------
with app.app_context():
    db.create_all()
    inspector = inspect(db.engine)
    columns = [c['name'] for c in inspector.get_columns('tickets')]
    if 'order_id' not in columns:
        with db.engine.connect() as conn:
            conn.execute(text('ALTER TABLE tickets ADD COLUMN order_id VARCHAR(200);'))
            conn.commit()
    if 'status' not in columns:
        with db.engine.connect() as conn:
            conn.execute(text("ALTER TABLE tickets ADD COLUMN status VARCHAR(50) DEFAULT 'pending';"))
            conn.commit()

# ---------------- Routes ----------------
@app.route('/')
def index():
    user = logged_in_user()
    return render_template('index.html', user=user)

# ----- Signup / Login / Logout -----
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
            error = "Бүх талбаруудыг бөглөнө үү."
        elif not email.endswith('@gmail.com'):
            error = "Email зөвхөн Gmail байх ёстой."
        elif password != confirm:
            error = "Нууц үг таарахгүй байна."
        elif User.query.filter_by(email=email).first():
            error = "Email бүртгэлтэй байна."

        if error:
            return render_template('signup.html', error=error, first=first, last=last, email=email, phone=phone)

        user = User(first_name=first, last_name=last, email=email, phone=phone, password=password)
        db.session.add(user)
        db.session.commit()
        session['user_email'] = email
        return redirect(url_for('index'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_email'] = email
            return redirect(url_for('index'))
        return render_template('login.html', error="Email эсвэл нууц үг буруу", email=email)
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    session.pop('is_admin', None)
    session.pop('admin_name', None)
    return redirect(url_for('index'))

# ----- Buy / Payment -----
@app.route('/buy', methods=['GET', 'POST'])
def buy():
    user = logged_in_user()
    if not user:
        return redirect(url_for('login'))

    test_token = "3be353ef85434197a76dd0645a170dc6"
    amount = 20000  # Changed to integer
    callback_url = "https://tedx-mongolia.onrender.com/callback"

    payment_url = None
    error_msg = None
    api_response = None  # Added this

    if request.method == 'POST':
        payload = {
            "ecommerce_token": test_token,
            "amount": amount,
            "callback_url": callback_url
        }
        headers = {"Content-Type": "application/json"}

        try:
            resp = requests.post(
                "https://ecomstg.pass.mn/openapi/v1/ecom/create_order",
                json=payload,
                headers=headers,
                timeout=10
            )
            data = resp.json()
            api_response = data  # Store the response for debugging

            if data.get("status_code") == "ok" and "ret" in data:
                order_id = data["ret"].get("order_id")
                # Clean up the order_id if needed
                if order_id.startswith("http://") or order_id.startswith("https://"):
                    payment_url = order_id
                else:
                    payment_url = f"https://pass.mn/order/{order_id}"
            else:
                error_msg = f"Төлбөр үүсгэхэд алдаа гарлаа: {data}"

        except Exception as e:
            error_msg = f"Серверт алдаа гарлаа: {e}"

    return render_template(
        "buy.html",
        user=user,
        amount=amount,
        payment_url=payment_url,
        error_msg=error_msg,
        api_response=api_response  # Added this
    )


# ---------- Callback route ----------
@app.route('/callback', methods=['POST'])
def callback():
    data = request.json
    order_id = data.get('order_id')
    status = data.get('status')

    # Төлбөр амжилттай бол Ticket үүсгэх
    if status == "paid":
        user_email = data.get('user_email')  # API-аас илгээж байвал
        user = User.query.filter_by(email=user_email).first()
        if user:
            ticket = Ticket(user_id=user.id, order_id=order_id, status="paid")
            db.session.add(ticket)
            db.session.commit()

    return "", 200

@app.route('/ticket/<int:ticket_id>')
def ticket_success(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    return render_template('ticket_success.html', ticket=ticket, user=ticket.user)
@app.route('/buy_test', methods=['GET', 'POST'])
def buy_test():
    user = logged_in_user()
    if not user:
        return redirect(url_for('login'))

    test_token = "3be353ef85434197a76dd0645a170dc6"
    amount = 20000
    callback_url = "https://tedx-mongolia.onrender.com/callback"

    payment_url = None
    error_msg = None
    api_response = None

    if request.method == 'POST':
        payload = {
            "ecommerce_token": test_token,
            "amount": amount,
            "callback_url": callback_url
        }
        headers = {"Content-Type": "application/json"}

        try:
            resp = requests.post(
                "https://ecomstg.pass.mn/openapi/v1/ecom/create_order",
                json=payload,
                headers=headers,
                timeout=10
            )
            data = resp.json()
            api_response = data

            if data.get("status_code") == "ok" and "ret" in data:
                order_id = data["ret"].get("order_id")
                payment_url = f"https://pass.mn/order/{order_id}"
                error_msg = None
            else:
                error_msg = f"Төлбөр үүсгэхэд алдаа гарлаа: {data}"

        except Exception as e:
            error_msg = f"Серверт алдаа гарлаа: {e}"

    return render_template(
        "buy_test.html",
        user=user,
        amount=amount,
        payment_url=payment_url,
        error_msg=error_msg,
        api_response=api_response
    )


# ----- Admin -----
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username == 'admin' and password == 'adm1n123@randomSECURE':
            session['is_admin'] = True
            session['admin_name'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html', error="Нэвтрэх мэдээлэл буруу")
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
    return render_template('admin.html', admin_name=session.get('admin_name'), users=users)

@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_detail.html', user=user)

# ----- Run -----
if __name__ == '__main__':
    app.run(debug=True)
