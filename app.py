from flask import Flask, render_template, session, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os
import requests

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'postgresql://tedx_27iq_user:jUVHT7tYZ0jzUcTNhDiVl4FGX2WLiYZQ@dpg-d3v6osbipnbc739einfg-a.oregon-postgres.render.com/tedx_27iq'
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

    def check_password(self, plain):
        return self.password == plain

class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    status = db.Column(db.String(50), default="pending")  # pending / paid

with app.app_context():
    db.create_all()

# ---------------- Helpers ----------------
def logged_in_user():
    user_email = session.get('user_email')
    if not user_email:
        return None
    return User.query.filter_by(email=user_email).first()

# ---------------- Routes ----------------
@app.route('/')
def index():
    user = logged_in_user()
    return render_template('index.html', user=user)

# --------- Signup/Login ---------
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
        elif password != confirm:
            error = "Passwords do not match."
        elif User.query.filter_by(email=email).first():
            error = "Email already registered."

        if error:
            return render_template('signup.html', error=error)

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
            session['user_email'] = user.email
            return redirect(url_for('index'))
        return render_template('login.html', error="Email or password wrong")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    return redirect(url_for('index'))

# --------- Buy Ticket ---------
@app.route('/buy', methods=['GET', 'POST'])
def buy():
    user = logged_in_user()
    if not user:
        return redirect(url_for('login'))

    payment_url = None
    error_msg = None
    amount = "20000"

    if request.method == 'POST':
        # 1️⃣ Шинэ Ticket үүсгэх
        ticket = Ticket(user_id=user.id, status="pending")
        db.session.add(ticket)
        db.session.commit()  # ticket.id гарч ирнэ

        # 2️⃣ Төлбөрийн холбоос үүсгэх (API-д callback-д ticket.id дамжуулах)
        test_token = "3be353ef85434197a76dd0645a170dc6"
        callback_url = f"https://tedx-mongolia.onrender.com/callback?ticket_id={ticket.id}"
        payload = {"ecommerce_token": test_token, "amount": amount, "callback_url": callback_url}
        headers = {"Content-Type": "application/json"}

        try:
            resp = requests.post(
                "https://ecomstg.pass.mn/openapi/v1/ecom/create_order",
                json=payload,
                headers=headers,
                timeout=10
            )
            data = resp.json()
            if data.get("status_code") == "ok" and "ret" in data:
                payment_url = data["ret"].get("order_id")  # төлбөр хийх холбоос
            else:
                error_msg = "Төлбөр үүсгэхэд алдаа гарлаа."
        except Exception as e:
            error_msg = f"Серверт алдаа гарлаа: {e}"

    return render_template('buy.html', user=user, payment_url=payment_url, amount=amount, error_msg=error_msg)

# --------- Callback ---------
@app.route('/callback', methods=['POST'])
def callback():
    ticket_id = request.args.get('ticket_id')
    data = request.json
    status = data.get('status')

    if ticket_id:
        ticket = Ticket.query.get(int(ticket_id))
        if ticket and status == "paid":
            ticket.status = "paid"
            db.session.commit()

    return "", 200

# --------- Ticket Success ---------
@app.route('/ticket/<int:ticket_id>')
def ticket_success(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    user = ticket.user
    return render_template('ticket_success.html', ticket=ticket, user=user)

# ---------------- Run ----------------
if __name__ == '__main__':
    app.run(debug=True)
