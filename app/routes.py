from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from app import db
from app.models import Stock, User
from flask_login import current_user, login_user, login_required, logout_user
from email_validator import validate_email, EmailNotValidError
from functools import wraps
from app.extensions import format_currency

auth_bp = Blueprint('auth', __name__)
inventory_bp = Blueprint('inventory', __name__)

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
        name = request.form['name']
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
        new_user.name = name

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
    return render_template('customer_orders.html')

@auth_bp.route('/inventory')
@role_required('Inventory Manager')
def inventory():
    low_stock_threshold = 10
    stocks = Stock.query.all()
    for stock in stocks:
        if stock.quantity < low_stock_threshold:
            flash(f'Stock for {stock.stock_name} is low!', 'warning')
        stock.formatted_price = format_currency(stock.price)  # Set an instance attribute
    return render_template('inventory.html', stocks=stocks)

@auth_bp.route('/supplier_monitor')
@role_required('Supplier')
def supplier_monitor():
    return render_template('supplier_monitor.html')

@auth_bp.route('/courier_shipments')
@role_required('Courier Service')   
def courier_shipments():
    return render_template('courier_shipments.html')

@inventory_bp.route('/inventory', methods=['GET'])
@login_required
def inventory_list():
    stocks = Stock.query.all()
    return render_template('inventory.html', stocks=stocks)

# Add new stock
@inventory_bp.route('/inventory/add', methods=['GET', 'POST'])
@login_required
def add_stock():
    if request.method == 'POST':
        try:
            weight = float(request.form['weight'])
            unit = request.form['unit']

            if not all([request.form['stock_name'], request.form['price'], request.form['quantity'], weight, unit]):
                flash('All fields are required!', 'danger')
                return redirect('/inventory/add')

            new_stock = Stock(
                stock_name=request.form['stock_name'],
                price=float(request.form['price']),
                quantity=int(request.form['quantity']),
                weight=weight,
                unit=unit
            )
            db.session.add(new_stock)
            db.session.commit()
            flash('Stock added successfully!', 'success')
        except ValueError:
            flash('Please enter valid data for all fields.', 'danger')

        return redirect('/inventory')

    return render_template('inventory/add_stock.html')

# Update stock
@inventory_bp.route('/inventory/edit/<int:stock_id>', methods=['GET', 'POST'])
@login_required
def edit_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)
    if request.method == 'POST':
        try:
            weight = float(request.form['weight'])
            unit = request.form['unit']
            
            if not all([request.form['stock_name'], request.form['price'], request.form['quantity'], weight, unit]):
                flash('All fields are required!', 'danger')
                return redirect(url_for('inventory.edit_stock', stock_id=stock_id))

            stock.stock_name = request.form['stock_name']
            stock.price = float(request.form['price'])
            stock.quantity = int(request.form['quantity'])
            stock.weight = weight
            stock.unit = unit

            db.session.commit()
            flash('Stock updated successfully!', 'success')
        except ValueError:
            flash('Please enter valid data for all fields.', 'danger')

        return redirect(url_for('inventory.inventory_list'))

    return render_template('inventory/edit_stock.html', stock=stock)


# Delete stock
@inventory_bp.route('/inventory/delete/<int:stock_id>', methods=['POST'])
@login_required
def delete_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)
    db.session.delete(stock)
    db.session.commit()
    flash('Stock deleted successfully!', 'success')
    return redirect(url_for('inventory.inventory_list'))