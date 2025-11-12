from flask import Flask, render_template, session, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os
import requests

app = Flask(__name__)

# Secret key from environment
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

# PostgreSQL Database on Render
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    "DATABASE_URL",
    "postgresql://tedx_27iq_user:jUVHT7tYZ0jzUcTNhDiVl4FGX2WLiYZQ@dpg-d3v6osbipnbc739einfg-a.oregon-postgres.render.com/tedx_27iq"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ------------------- Models -------------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    tickets = db.relationship('Ticket', backref='user', lazy=True)

    def check_password(self, plain):
        return self.password == plain

class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    order_id = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(50), default="pending")  # pending / paid

# ------------------- Helpers -------------------
def logged_in_user():
    user_email = session.get('user_email')
    if not user_email:
        return None
    return User.query.filter_by(email=user_email).first()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

with app.app_context():
    db.create_all()

# ------------------- Routes -------------------
@app.route('/')
def index():
    user = logged_in_user()
    return render_template('index.html', user=user)

# ... [Signup, Login, Logout кодыг хэвээр хадгална] ...

# ------------------- Buy / Payment -------------------
@app.route('/buy', methods=['GET', 'POST'])
def buy():
    user = logged_in_user()
    if not user:
        return redirect(url_for('login'))

    test_token = "3be353ef85434197a76dd0645a170dc6"
    amount = "20000"

    # ✅ Render-н URL-д тохируулсан callback
    callback_url = "https://tedx-mongolia.onrender.com/callback"

    payment_url = None
    order_id = None
    error_msg = None

    if request.method == 'POST':
        payload = {
            "ecommerce_token": test_token,
            "amount": amount,
            "callback_url": callback_url
        }
        headers = {"Content-Type": "application/json"}

        try:
            resp = requests.post(
                "https://ecom.pass.mn/openapi/v1/ecom/create_order",
                json=payload,
                headers=headers,
                timeout=10
            )
            data = resp.json()
            print("API response:", data)

            if data and "ret" in data and data["ret"]:
                order_id = data["ret"].get("order_id")
                payment_url = data["ret"].get("payment_url")
            else:
                error_msg = "Төлбөр үүсгэхэд алдаа гарлаа. API хариу буруу байна."
        except Exception as e:
            print("Error calling API:", e)
            error_msg = "Төлбөр үүсгэхэд алдаа гарлаа. Серверт алдаа гарлаа."

        # Save ticket to DB
        if order_id:
            ticket = Ticket(user_id=user.id, order_id=order_id, status="pending")
            db.session.add(ticket)
            db.session.commit()

    return render_template("buy.html",
                           user=user,
                           amount=amount,
                           payment_url=payment_url,
                           error_msg=error_msg)

@app.route('/callback', methods=['POST'])
def callback():
    data = request.json
    order_id = data.get('order_id')
    status = data.get('status')

    ticket = Ticket.query.filter_by(order_id=order_id).first()
    if ticket and status == "paid":
        ticket.status = "paid"
        db.session.commit()

    return "", 200

# ------------------- Admin -------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username == 'admin' and password == 'adm1n123@randomSECURE':
            session['is_admin'] = True
            session['admin_name'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html', error="Invalid admin credentials")
    return render_template('admin_login.html')

@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin.html', admin_name=session.get('admin_name'), users=users)

# ------------------- Run -------------------
if __name__ == '__main__':
    app.run(debug=True)
