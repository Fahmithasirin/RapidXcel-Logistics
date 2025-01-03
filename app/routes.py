from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from app import db
from app.models import User
from flask_login import current_user, login_user, login_required, logout_user
from email_validator import validate_email, EmailNotValidError
from functools import wraps

auth_bp = Blueprint('auth', __name__)

# Role-based access control decorator
def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role != role:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# Main Page Route
@auth_bp.route('/')
def index():
    return render_template('index.html')

# Register Route
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        try: 
            valid = validate_email(username) 
            username = valid.email 
        except EmailNotValidError as e: 
            flash(str(e), 'danger') 
            return redirect(url_for('auth.register')) 
        
        existing_user = User.query.filter_by(username=username).first() 
        if existing_user: 
            flash('Username already exists', 'danger') 
            return redirect(url_for('auth.register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.register'))

        new_user = User(username=username, role=role)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        login_user(new_user)

        # Redirect based on user role
        if role == 'Inventory Manager':
            return redirect(url_for('auth.inventory'))
        elif role == 'Customer':
            return redirect(url_for('auth.customer_orders'))
        elif role == 'Supplier':
            return redirect(url_for('auth.supplier_monitor'))
        elif role == 'Courier Service':
            return redirect(url_for('auth.courier_shipments'))
        else:
            flash('Role not recognized, redirecting to the main page.', 'info')
            return redirect(url_for('auth.index'))

    return render_template('register.html')


# Login Route
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            flash('Login successful!', 'success')
            login_user(user)

            # Redirect based on user role
            if user.role == 'Inventory Manager':
                return redirect(url_for('auth.inventory'))
            elif user.role == 'Customer':
                return redirect(url_for('auth.customer_orders'))
            elif user.role == 'Supplier':
                return redirect(url_for('auth.supplier_monitor'))
            elif user.role == 'Courier Service':
                return redirect(url_for('auth.courier_shipments'))
            else:
                # Default redirection for unknown roles
                flash('Role not recognized, redirecting to the main page.', 'info')
                return redirect(url_for('auth.index'))

        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')



@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.index'))

@auth_bp.route('/customer_orders')
@role_required('Customer')
def customer_orders():
    # Your logic for handling customer orders goes here
    return render_template('customer_orders.html')

@auth_bp.route('/inventory')
@role_required('Inventory Manager')
def inventory():
    return render_template('inventory.html')

@auth_bp.route('/supplier_monitor')
@role_required('Supplier')
def supplier_monitor():
    return render_template('supplier_monitor.html')

@auth_bp.route('/courier_shipments')
@role_required('Courier Service')   
def courier_shipments():
    return render_template('courier_shipments.html')