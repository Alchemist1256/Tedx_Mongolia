from flask import Flask, render_template, session, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os
import requests
from sqlalchemy import text, inspect
import qrcode
import io
import base64
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

# Database config
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
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def check_password(self, plain):
        return self.password == plain

class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    order_id = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(50), default="pending")
    amount = db.Column(db.String(20), nullable=True)
    payment_request_id = db.Column(db.String(100), nullable=True)
    payment_method = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    paid_at = db.Column(db.DateTime, nullable=True)

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
    if 'amount' not in columns:
        with db.engine.connect() as conn:
            conn.execute(text('ALTER TABLE tickets ADD COLUMN amount VARCHAR(20);'))
            conn.commit()
    if 'payment_request_id' not in columns:
        with db.engine.connect() as conn:
            conn.execute(text('ALTER TABLE tickets ADD COLUMN payment_request_id VARCHAR(100);'))
            conn.commit()
    if 'paid_at' not in columns:
        with db.engine.connect() as conn:
            conn.execute(text('ALTER TABLE tickets ADD COLUMN paid_at TIMESTAMP;'))
            conn.commit()
    if 'payment_method' not in columns:
        with db.engine.connect() as conn:
            conn.execute(text("ALTER TABLE tickets ADD COLUMN payment_method VARCHAR(50);"))
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

# ----- Payment -----
@app.route('/buy', methods=['GET', 'POST'])
def buy():
    user = logged_in_user()
    if not user:
        return redirect(url_for('login'))

    # Payment Configuration - PRODUCTION
    api_url = "https://ecom.pass.mn/openapi/v1/ecom/create_order"
    ecommerce_token = "0c8e9f21efcc45baa5a49ccb32e84836"
    amount = "50000"
    callback_url = "https://tedx-mongolia.onrender.com/callback"

    payment_url = None
    error_msg = None
    api_response = None
    qr_code_base64 = None
    show_bank_transfer = False

    if request.method == 'POST':
        payment_method = request.form.get('payment_method')
        
        # Handle bank transfer option
        if payment_method == 'bank':
            # Save ticket with bank transfer method
            ticket = Ticket(
                user_id=user.id,
                status="pending",
                amount=amount,
                payment_method="bank"
            )
            db.session.add(ticket)
            db.session.commit()
            
            show_bank_transfer = True
            return render_template(
                "buy.html",
                user=user,
                amount=amount,
                show_bank_transfer=show_bank_transfer
            )
        
        # Handle QR payment option
        if payment_method == 'qr':
            payload = {
                "ecommerce_token": ecommerce_token,
                "amount": amount,
                "callback_url": callback_url
            }
            headers = {"Content-Type": "application/json"}

            try:
                resp = requests.post(api_url, json=payload, headers=headers, timeout=60)
                data = resp.json()
                api_response = data

                if data.get("status_code") == "ok" and "ret" in data:
                    ret = data["ret"]
                    order_id_url = ret.get("order_id")
                    
                    if order_id_url:
                        payment_url = order_id_url
                        
                        # Generate QR code
                        qr = qrcode.QRCode(version=1, box_size=10, border=5)
                        qr.add_data(order_id_url)
                        qr.make(fit=True)
                        img = qr.make_image(fill_color="black", back_color="white")
                        
                        buffered = io.BytesIO()
                        img.save(buffered, format="PNG")
                        qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()
                        
                        # Save ticket to database with payment method
                        order_uuid = order_id_url.split("/")[-1]
                        ticket = Ticket(
                            user_id=user.id,
                            order_id=order_uuid,
                            status="pending",
                            amount=amount,
                            payment_method="qr"
                        )
                        db.session.add(ticket)
                        db.session.commit()
                        
                        print(f"✅ Order created: {order_uuid}")
                    else:
                        error_msg = "Order ID буцаагдсангүй"
                else:
                    msg = data.get("msg", {})
                    error_code = msg.get("code", "Unknown")
                    error_body = msg.get("body", "Алдаа гарлаа")
                    error_msg = f"Алдаа [{error_code}]: {error_body}"

            except requests.exceptions.Timeout:
                error_msg = "Хүсэлт хугацаа хэтрэв (60 секунд). Дахин оролдоно уу."
            except requests.exceptions.RequestException as e:
                error_msg = f"Сүлжээний алдаа: {str(e)}"
            except Exception as e:
                error_msg = f"Серверт алдаа гарлаа: {str(e)}"

    return render_template(
        "buy.html",
        user=user,
        amount=amount,
        payment_url=payment_url,
        error_msg=error_msg,
        api_response=api_response,
        qr_code_base64=qr_code_base64,
        show_bank_transfer=show_bank_transfer
    )

# ---------- Callback ----------
@app.route('/callback', methods=['POST', 'GET'])
def callback():
    try:
        if request.is_json:
            data = request.json
        else:
            data = request.form.to_dict()
        
        print(f"📩 Callback received: {data}")
        
        order_id = data.get('order_id')
        resp_code = data.get('resp_code')
        resp_msg = data.get('resp_msg')
        
        if order_id and ('http://' in order_id or 'https://' in order_id):
            order_uuid = order_id.split('/')[-1]
        else:
            order_uuid = order_id

        print(f"💳 Order: {order_uuid}, Code: {resp_code}")

        if order_uuid:
            ticket = Ticket.query.filter_by(order_id=order_uuid).first()
            
            if ticket:
                if resp_code == "000":
                    ticket.status = "paid"
                    ticket.paid_at = datetime.utcnow()
                    db.session.commit()
                    print(f"✅ Ticket {ticket.id} marked as PAID")
                    return jsonify({"success": True, "message": "Payment confirmed"}), 200
                else:
                    ticket.status = "failed"
                    db.session.commit()
                    print(f"❌ Payment failed: {resp_msg}")
                    return jsonify({"success": True, "message": "Status updated"}), 200
            else:
                print(f"⚠️ Ticket not found: {order_uuid}")
                return jsonify({"error": "Ticket not found"}), 404

        return jsonify({"success": True}), 200
        
    except Exception as e:
        print(f"❌ Callback error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# ---------- Check Payment Status ----------
@app.route('/api/check_payment_status/<order_id>')
def api_check_payment_status(order_id):
    user = logged_in_user()
    if not user:
        return jsonify({"error": "Not logged in"}), 401
    
    ticket = Ticket.query.filter_by(order_id=order_id, user_id=user.id).first()
    
    if not ticket:
        return jsonify({"error": "Ticket not found"}), 404
    
    return jsonify({
        "status": ticket.status,
        "ticket_id": ticket.id,
        "order_id": ticket.order_id
    })

# ---------- Success Page ----------
@app.route('/ticket/<int:ticket_id>')
def ticket_success(ticket_id):
    user = logged_in_user()
    if not user:
        return redirect(url_for('login'))
    
    ticket = Ticket.query.get_or_404(ticket_id)
    
    if ticket.user_id != user.id:
        return "Access denied", 403
    
    return render_template('ticket_success.html', ticket=ticket, user=user)

# ---------- Admin Routes ----------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    # If already logged in as admin, redirect to dashboard
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        admin_user = os.environ.get('ADMIN_USERNAME', 'admin')
        admin_pass = os.environ.get('ADMIN_PASSWORD', 'admin123')
        
        if username == admin_user and password == admin_pass:
            session['is_admin'] = True
            session['admin_name'] = username
            return redirect(url_for('admin_dashboard'))
        
        return render_template('admin_login.html', error="Invalid credentials")
    
    return render_template('admin_login.html')

@app.route('/admin')
@admin_required  # This decorator will redirect to login if not authenticated
def admin_dashboard():
    total_users = User.query.count()
    total_tickets = Ticket.query.count()
    paid_tickets = Ticket.query.filter_by(status='paid').count()
    pending_tickets = Ticket.query.filter_by(status='pending').count()
    
    # FIX: Only count QR payment method tickets (not bank transfers)
    qr_tickets = Ticket.query.filter_by(payment_method='qr').count()
    bank_tickets = Ticket.query.filter_by(payment_method='bank').count()
    qr_paid = Ticket.query.filter_by(payment_method='qr', status='paid').count()
    bank_paid = Ticket.query.filter_by(payment_method='bank', status='paid').count()
    
    # Calculate pending only for QR payments
    qr_pending = qr_tickets - qr_paid
    bank_pending = bank_tickets - bank_paid
    
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(10).all()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_tickets=total_tickets,
                         paid_tickets=paid_tickets,
                         pending_tickets=pending_tickets,
                         qr_tickets=qr_tickets,
                         bank_tickets=bank_tickets,
                         qr_paid=qr_paid,
                         bank_paid=bank_paid,
                         qr_pending=qr_pending,
                         bank_pending=bank_pending,
                         recent_users=recent_users,
                         recent_tickets=recent_tickets)

@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/tickets')
@admin_required
def admin_tickets():
    tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()
    return render_template('admin_tickets.html', tickets=tickets)

@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('admin_user_detail.html', user=user)

@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    session.pop('admin_name', None)
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
