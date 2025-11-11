from flask import Flask, render_template, session, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
 
from functools import wraps
import os


app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'postgresql://tedx_27iq_user:jUVHT7tYZ0jzUcTNhDiVl4FGX2WLiYZQ@dpg-d3v6osbipnbc739einfg-a.oregon-postgres.render.com/tedx_27iq'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

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


def logged_in_user():
    """Return the current logged-in User object or None."""
    user_email = session.get('user_email')
    if not user_email:
        return None
    return User.query.filter_by(email=user_email).first()


def admin_required(f):
    """Decorator to protect admin-only routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


with app.app_context():
    db.create_all()


@app.route('/')
def index():
    user = logged_in_user()
    return render_template('index.html', user=user)


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
            password=password
        )
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

        return render_template('login.html', error="Gmail or password is wrong", email=email)

    return render_template('login.html')



@app.route('/logout')
def logout():
    session.pop('user_email', None)
    session.pop('is_admin', None)
    session.pop('admin_name', None)
    return redirect(url_for('index'))

@app.route('/buy', methods=['GET', 'POST'])
def buy():
    user = logged_in_user()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        ticket = Ticket(user_id=user.id)
        db.session.add(ticket)
        db.session.commit()
        return redirect(url_for('ticket_success', ticket_id=ticket.id))

    return render_template('buy.html', user=user)


@app.route('/ticket/<int:ticket_id>')
def ticket_success(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    user = ticket.user
    return render_template('ticket_success.html', ticket=ticket, user=user)

@app.route('/inquiry', methods=['POST'])
def inquiry():
    order_id = request.form.get('order_id')
    # Call your bank API here and return JSON
    return jsonify({
        "status": "paid",
        "status_text": "Төлбөр амжилттай хийгдлээ"
    })


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


@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    session.pop('admin_name', None)
    return redirect(url_for('index'))


@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.created_at.desc()).all()
    ticket_users = (User.query
                        .join(Ticket, Ticket.user_id == User.id)
                        .order_by(Ticket.created_at.desc())
                        .all())
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

if __name__ == '__main__':
    app.run(debug=True)
