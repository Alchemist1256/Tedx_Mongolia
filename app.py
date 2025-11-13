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
    invoice_id = db.Column(db.String(200), nullable=True)  # DigiPay invoice ID
    status = db.Column(db.String(50), default="pending")
    amount = db.Column(db.String(20), nullable=True)
    payment_request_id = db.Column(db.String(100), nullable=True)  # txnId
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

# ---------------- DigiPay Token ----------------
def get_digipay_client_token():
    """
    Get DigiPay client token for creating invoices
    Section 2.8 of DigiPay documentation
    """
    is_production = os.environ.get("PAYMENT_ENV", "staging") == "production"
    
    if is_production:
        token_url = "https://api.khanbank.com/v1/wallet/auth/token"
        client_id = os.environ.get("DIGIPAY_CLIENT_ID")
        client_secret = os.environ.get("DIGIPAY_CLIENT_SECRET")
    else:
        # Use test credentials
        token_url = "https://test-api.khanbank.com/v1/wallet/auth/token"
        client_id = os.environ.get("DIGIPAY_TEST_CLIENT_ID", "test_client")
        client_secret = os.environ.get("DIGIPAY_TEST_CLIENT_SECRET", "test_secret")
    
    try:
        resp = requests.post(
            token_url,
            params={"grant_type": "client_credentials"},
            auth=(client_id, client_secret),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30
        )
        data = resp.json()
        return data.get("access_token")
    except Exception as e:
        print(f"❌ Token error: {e}")
        return None

# ---------------- DB Setup ----------------
with app.app_context():
    db.create_all()
    inspector = inspect(db.engine)
    columns = [c['name'] for c in inspector.get_columns('tickets')]
    
    # Add new columns if they don't exist
    if 'order_id' not in columns:
        with db.engine.connect() as conn:
            conn.execute(text('ALTER TABLE tickets ADD COLUMN order_id VARCHAR(200);'))
            conn.commit()
    if 'status' not in columns:
        with db.engine.connect() as conn:
            conn.execute(text("ALTER TABLE tickets ADD COLUMN status VARCHAR(50) DEFAULT 'pending';"))
            conn.commit()
    if 'invoice_id' not in columns:
        with db.engine.connect() as conn:
            conn.execute(text('ALTER TABLE tickets ADD COLUMN invoice_id VARCHAR(200);'))
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

# ----- DigiPay Payment -----
@app.route('/buy', methods=['GET', 'POST'])
def buy():
    user = logged_in_user()
    if not user:
        return redirect(url_for('login'))

    # PAYMENT CONFIGURATION
    is_production = os.environ.get("PAYMENT_ENV", "staging") == "production"
    amount = "20000"  # 20,000 MNT
    
    # DigiPay configuration
    if is_production:
        invoice_url = "https://api.khanbank.com/v3/superapp/save/invoice"
        merchant_id = os.environ.get("DIGIPAY_MERCHANT_ID", "70209897")
        terminal_id = os.environ.get("DIGIPAY_TERMINAL_ID", "70209897")
        merchant_name = "TEDx Khan Uul"
    else:
        invoice_url = "https://test-api.khanbank.com/v3/superapp/save/invoice"
        merchant_id = os.environ.get("DIGIPAY_TEST_MERCHANT_ID", "TEST_MERCHANT")
        terminal_id = os.environ.get("DIGIPAY_TEST_TERMINAL_ID", "TEST_TERMINAL")
        merchant_name = "TEDx Khan Uul (Test)"
    
    webhook_url = "https://tedx-mongolia.onrender.com/digipay_webhook"
    redirect_url_after_payment = "https://tedx-mongolia.onrender.com/"

    payment_url = None
    digipay_deep_link = None
    error_msg = None
    api_response = None
    qr_code_base64 = None

    if request.method == 'POST':
        # Get DigiPay token
        access_token = get_digipay_client_token()
        
        if not access_token:
            error_msg = "Токен авахад алдаа гарлаа. Дахин оролдоно уу."
            return render_template("buy.html", user=user, amount=amount, error_msg=error_msg)
        
        # Generate unique external invoice ID
        ext_invoice_id = f"TEDX-{user.id}-{int(datetime.utcnow().timestamp())}"
        
        # Create invoice (Section 2.5)
        payload = {
            "amount": float(amount),
            "merchantId": merchant_id,
            "merchantName": merchant_name,
            "terminalId": terminal_id,
            "webHookUrl": webhook_url,
            "redirectUrl": redirect_url_after_payment,
            "extInvoiceId": ext_invoice_id
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        }

        try:
            resp = requests.post(invoice_url, json=payload, headers=headers, timeout=60)
            data = resp.json()
            api_response = data

            invoice_id = data.get("invoiceId")
            
            if invoice_id:
                # Create deep link (Section 2.7)
                digipay_deep_link = f"digipay://payment/{invoice_id}"
                payment_url = digipay_deep_link
                
                # Generate QR code for the deep link
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(digipay_deep_link)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                
                buffered = io.BytesIO()
                img.save(buffered, format="PNG")
                qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()
                
                # Save ticket to database
                ticket = Ticket(
                    user_id=user.id,
                    order_id=ext_invoice_id,
                    invoice_id=invoice_id,
                    status="pending",
                    amount=amount
                )
                db.session.add(ticket)
                db.session.commit()
                
                print(f"✅ DigiPay invoice created: {invoice_id}")
            else:
                error_msg = "Invoice ID буцаагдсангүй"

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
        digipay_deep_link=digipay_deep_link,
        error_msg=error_msg,
        api_response=api_response,
        qr_code_base64=qr_code_base64
    )

# ---------- DigiPay Webhook ----------
@app.route('/digipay_webhook', methods=['GET'])
def digipay_webhook():
    """
    DigiPay webhook endpoint (Section 2.6)
    Receives payment status updates via GET params
    
    Params: invoiceId, txnId, status, amount, extInvoiceId
    """
    try:
        invoice_id = request.args.get('invoiceId')
        txn_id = request.args.get('txnId')
        status = request.args.get('status')  # PAID or FAIL
        amount = request.args.get('amount')
        ext_invoice_id = request.args.get('extInvoiceId')
        
        print(f"📩 DigiPay Webhook: invoiceId={invoice_id}, status={status}, txnId={txn_id}")
        
        # Find ticket by invoice_id or ext_invoice_id
        ticket = Ticket.query.filter(
            (Ticket.invoice_id == invoice_id) | (Ticket.order_id == ext_invoice_id)
        ).first()
        
        if ticket:
            if status == "PAID":
                ticket.status = "paid"
                ticket.paid_at = datetime.utcnow()
                ticket.payment_request_id = txn_id
                db.session.commit()
                print(f"✅ Ticket {ticket.id} marked as PAID")
            elif status == "FAIL":
                ticket.status = "failed"
                db.session.commit()
                print(f"❌ Payment failed for ticket {ticket.id}")
            
            return "OK", 200
        else:
            print(f"⚠️ Ticket not found: invoiceId={invoice_id}, extInvoiceId={ext_invoice_id}")
            return "Ticket not found", 404
            
    except Exception as e:
        print(f"❌ Webhook error: {str(e)}")
        return str(e), 500

# ---------- Check Payment Status API ----------
@app.route('/api/check_payment_status/<invoice_id>')
def api_check_payment_status(invoice_id):
    """
    Frontend polling endpoint to check if payment is complete
    """
    user = logged_in_user()
    if not user:
        return jsonify({"error": "Not logged in"}), 401
    
    ticket = Ticket.query.filter_by(invoice_id=invoice_id, user_id=user.id).first()
    
    if not ticket:
        return jsonify({"error": "Ticket not found"}), 404
    
    return jsonify({
        "status": ticket.status,
        "ticket_id": ticket.id,
        "invoice_id": ticket.invoice_id
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
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_tickets = Ticket.query.count()
    paid_tickets = Ticket.query.filter_by(status='paid').count()
    pending_tickets = Ticket.query.filter_by(status='pending').count()
    
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(10).all()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_tickets=total_tickets,
                         paid_tickets=paid_tickets,
                         pending_tickets=pending_tickets,
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
