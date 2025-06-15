from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os
import datetime
import random

# --- Flask App Configuration ---
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
os.makedirs(os.path.join(basedir, "instance"), exist_ok=True)

app.config['SECRET_KEY'] = 'a_very_strong_and_unique_secret_key_here_for_security_12345'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "instance", "database.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail config — Replace with actual credentials
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'chvkscanx@gmail.com'  # Replace
app.config['MAIL_PASSWORD'] = 'yoxf udmq msjy oyjm'     # Replace with App Password
app.config['MAIL_DEFAULT_SENDER'] = ('FTC Store', 'chvkscanx@gmail.com')

# --- Extensions ---
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='customer', nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200), nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    total_amount = db.Column(db.Float, nullable=False)
    items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    token = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    used = db.Column(db.Boolean, default=False)

# --- User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---
@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.role == 'customer':
            return redirect(url_for('customer_dashboard'))
        elif current_user.role == 'staff':
            return redirect(url_for('staff_dashboard'))
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'customer')

        if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
            flash('User already exists.', 'danger')
            return redirect(url_for('signup'))

        new_user = User(username=username, email=email, password=generate_password_hash(password), role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('customer_dashboard') if user.role == 'customer' else url_for('staff_dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/customer-dashboard')
@login_required
def customer_dashboard():
    return render_template('customer_dashboard.html')

@app.route('/staff-dashboard')
@login_required
def staff_dashboard():
    return render_template('staff_dashboard.html')

@app.route('/fruits_vegetables')
def fruits_vegetables():
    products = Product.query.filter_by(category='fruits_vegetables').all()
    return render_template('fruits_vegetables.html', products=products)

@app.route('/meat_milk')
def meat_milk():
    products = Product.query.filter_by(category='meat_milk').all()
    return render_template('meat_milk.html', products=products)

@app.route('/add-to-cart/<int:product_id>')
@login_required
def add_to_cart(product_id):
    cart = session.get('cart', {})
    cart[str(product_id)] = cart.get(str(product_id), 0) + 1
    session['cart'] = cart
    return redirect(request.referrer or url_for('home'))

@app.route('/cart')
@login_required
def cart():
    cart = session.get('cart', {})
    products = Product.query.filter(Product.id.in_(cart.keys())).all()
    total = 0
    cart_items = []
    for product in products:
        qty = cart[str(product.id)]
        subtotal = qty * product.price
        total += subtotal
        cart_items.append({'product': product, 'quantity': qty, 'subtotal': subtotal})
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/remove-from-cart/<int:product_id>')
@login_required
def remove_from_cart(product_id):
    cart = session.get('cart', {})
    if str(product_id) in cart:
        del cart[str(product_id)]
    session['cart'] = cart
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart = session.get('cart', {})
    if not cart:
        flash("Your cart is empty.", 'info')
        return redirect(url_for('cart'))

    products = Product.query.filter(Product.id.in_(cart.keys())).all()
    total = 0
    order = Order(customer_id=current_user.id, total_amount=0)
    db.session.add(order)
    db.session.flush()
    for product in products:
        qty = cart[str(product.id)]
        subtotal = qty * product.price
        item = OrderItem(order_id=order.id, product_id=product.id, quantity=qty, price=product.price)
        db.session.add(item)
        total += subtotal
    order.total_amount = total
    db.session.commit()
    session['cart'] = {}
    flash("Order placed successfully!", 'success')
    return redirect(url_for('customer_dashboard'))

# --- Forgot Password (OTP) ---
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with that email.", "danger")
            return redirect(url_for('forgot_password'))

        otp = str(random.randint(100000, 999999))
        token = serializer.dumps(email, salt='otp-reset')

        reset = PasswordReset(email=email, otp=otp, token=token)
        db.session.add(reset)
        db.session.commit()

        try:
            msg = Message('Your OTP Code - FTC Store', recipients=[email])
            msg.body = f"Your OTP code is: {otp}\nThis will expire in 10 minutes."
            mail.send(msg)
            flash('OTP sent to your email.', 'info')
        except Exception as e:
            print(e)
            flash('Failed to send OTP. Please check mail config.', 'danger')

        return redirect(url_for('verify_otp', email=email))
    return render_template('forgot_password.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email') or request.form.get('email')
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['new_password']
        reset = PasswordReset.query.filter_by(email=email, otp=otp, used=False).first()

        if reset and (datetime.datetime.utcnow() - reset.created_at).seconds < 600:
            user = User.query.filter_by(email=email).first()
            user.password = generate_password_hash(new_password)
            reset.used = True
            db.session.commit()
            flash("Password has been reset. Please log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("Invalid or expired OTP.", "danger")
            return redirect(url_for('verify_otp', email=email))
    return render_template('verify_otp.html', email=email)

# --- Main ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
