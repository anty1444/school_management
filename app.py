from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Initialize the Flask app
app = Flask(__name__)

# Configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'instance', 'users.db')}"
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize the database
db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'student', 'teacher', 'parent'
    password = db.Column(db.String(200), nullable=False)

# Ensure the database is created
with app.app_context():
    os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)  # Create instance folder if it doesn't exist
    db.create_all()

# Home route
@app.route('/')
def home():
    return render_template('home.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        role = request.form.get('role')
        password = request.form.get('password')

        # Validation
        if not name or not email or not role or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return redirect(url_for('register'))

        # Check if the user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please login.', 'danger')
            return redirect(url_for('register'))

        # Create a new user
        new_user = User(name=name, email=email, role=role, password=generate_password_hash(password, method='sha256'))
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Validation
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return redirect(url_for('login'))

        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            # Store user details in the session
            session['user_id'] = user.id
            session['user_role'] = user.role
            session['user_name'] = user.name

            flash('Login successful!', 'success')
            # Redirect to the appropriate dashboard
            if user.role == 'student':
                return redirect(url_for('student_dashboard'))
            elif user.role == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            elif user.role == 'parent':
                return redirect(url_for('parent_dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# Student Dashboard
@app.route('/student/dashboard')
def student_dashboard():
    if 'user_role' in session and session['user_role'] == 'student':
        return render_template('student_dashboard.html', name=session['user_name'])
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Teacher Dashboard
@app.route('/teacher/dashboard')
def teacher_dashboard():
    if 'user_role' in session and session['user_role'] == 'teacher':
        return render_template('teacher_dashboard.html', name=session['user_name'])
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Parent Dashboard
@app.route('/parent/dashboard')
def parent_dashboard():
    if 'user_role' in session and session['user_role'] == 'parent':
        return render_template('parent_dashboard.html', name=session['user_name'])
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Debugging: Print all routes
with app.test_request_context():
    print(app.url_map)

# Run the app
import os

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
@app.route('/actualities')
def actualities():
    return render_template('actualities.html')

@app.route('/info')
def info():
    return render_template('info.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/support')
def support():
    return render_template('support.html')
