from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import re
import pyotp # NEW: The 2FA Library

# --- App Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-intern-key-keep-safe'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize Extensions ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- Database Model ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    # NEW: Store the unique 2FA secret for each user
    totp_secret = db.Column(db.String(16), nullable=False) 

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        
        if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username) or len(password) < 6:
            flash("Invalid username or password format.")
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash("Username already exists.")
            return render_template('register.html')
            
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # NEW: Generate a random 16-character base32 secret for this new user
        user_secret = pyotp.random_base32()
        
        new_user = User(username=username, password=hashed_password, totp_secret=user_secret)
        db.session.add(new_user)
        db.session.commit()
        
        # Pass the secret to the template so the user can save it to their phone
        flash(f"Account created! Your 2FA Secret Key is: {user_secret} (SAVE THIS!)")
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        # Step 1 of Login: Check Username and Password
        if user and bcrypt.check_password_hash(user.password, password):
            # Step 2: Don't log them in yet! Send them to the 2FA screen.
            session['pending_user_id'] = user.id 
            return redirect(url_for('verify_2fa'))
        else:
            flash("Login Unsuccessful. Please check username and password.")
            
    return render_template('login.html')

# NEW ROUTE: The 2FA Verification Screen
@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        token = request.form.get('token').strip()
        user_id = session.get('pending_user_id')
        user = User.query.get(user_id)
        
        # Check if the 6-digit code matches the user's secret
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(token):
            # Success! Now we officially log them in.
            login_user(user)
            session.pop('pending_user_id', None) # Clear the pending session
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid 2FA token. Please try again.")
            
    # We will reuse the login template for simplicity, but ask for a token instead
    return render_template('2fa.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000) 