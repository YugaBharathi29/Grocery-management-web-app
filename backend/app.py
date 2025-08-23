from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime, timedelta
import os
from functools import wraps
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grocery_store.db'  # Using SQLite for demo
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app, supports_credentials=True)

# Models
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    role = db.Column(db.Enum('customer', 'admin', name='user_roles'), default='customer')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    orders = db.relationship('Order', backref='user', lazy=True)
    cart_items = db.relationship('CartItem', backref='user', lazy=True, cascade='all, delete-orphan')

class Category(db.Model):
    __tablename__ = 'categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(500))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    products = db.relationship('Product', backref='category', lazy=True)

class Product(db.Model):
    __tablename__ = 'products'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    stock_quantity = db.Column(db.Integer, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'))
    image_url = db.Column(db.String(500))
    sku = db.Column(db.String(100), unique=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    cart_items = db.relationship('CartItem', backref='product', lazy=True)
    order_items = db.relationship('OrderItem', backref='product', lazy=True)

class Order(db.Model):
    __tablename__ = 'orders'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.Enum('pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled', name='order_status'), default='pending')
    shipping_address = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    order_items = db.relationship('OrderItem', backref='order', lazy=True, cascade='all, delete-orphan')

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Numeric(10, 2), nullable=False)

class CartItem(db.Model):
    __tablename__ = 'cart_items'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'product_id', name='unique_user_product'),)

# Helper functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Authentication Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    password_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    user = User(
        email=data['email'],
        password_hash=password_hash,
        first_name=data['first_name'],
        last_name=data['last_name'],
        phone=data.get('phone', ''),
        role=data.get('role', 'customer')
    )
    
    db.session.add(user)
    db.session.commit()
    
    session['user_id'] = user.id
    session['user_role'] = user.role
    
    return jsonify({
        'message': 'User registered successfully',
        'user': {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role
        }
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        session['user_id'] = user.id
        session['user_role'] = user.role
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.role
            }
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/auth/profile', methods=['GET'])
@login_required
def get_profile():
    user = User.query.get(session['user_id'])
    return jsonify({
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'phone': user.phone,
        'role': user.role
    })

# Product Routes
@app.route('/api/products', methods=['GET'])
def get_products():
    category_id = request.args.get('category_id')
    search_query = request.args.get('q', '')
    
    query = Product.query.filter_by(is_active=True)
    
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    if search_query:
        query = query.filter(Product.name.contains(search_query))
    
    products = query.all()
    
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'description': p.description,
        'price': float(p.price),
        'stock_quantity': p.stock_quantity,
        'category_id': p.category_id,
        'image_url': p.image_url,
        'sku': p.sku,
        'is_active': p.is_active
    } for p in products])

@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    return jsonify({
        'id': product.id,
        'name': product.name,
        'description': product.description,
        'price': float(product.price),
        'stock_quantity': product.stock_quantity,
        'category_id': product.category_id,
        'image_url': product.image_url,
        'sku': product.sku,
        'is_active': product.is_active
    })

@app.route('/api/products', methods=['POST'])
@admin_required
def create_product():
    data = request.get_json()
    
    product = Product(
        name=data['name'],
        description=data.get('description', ''),
        price=data['price'],
        stock_quantity=data.get('stock_quantity', 0),
        category_id=data.get('category_id'),
        image_url=data.get('image_url', ''),
        sku=data.get('sku', f"SKU{int(datetime.utcnow().timestamp())}")
    )
    
    db.session.add(product)
    db.session.commit()
    
    return jsonify({'message': 'Product created successfully', 'product_id': product.id}), 201

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@admin_required
def update_product(product_id):
    data = request.get_json()
    product = Product.query.get_or_404(product_id)
    
    product.name = data.get('name', product.name)
    product.description = data.get('description', product.description)
    product.price = data.get('price', product.price)
    product.stock_quantity = data.get('stock_quantity', product.stock_quantity)
    product.category_id = data.get('category_id', product.category_id)
    product.image_url = data.get('image_url', product.image_url)
    product.sku = data.get('sku', product.sku)
    product.updated_at = datetime.utcnow()
    
    db.session.commit()
    
    return jsonify({'message': 'Product updated successfully'})

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@admin_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Check if product has pending orders
    pending_orders = OrderItem.query.join(Order).filter(
        OrderItem.product_id == product_id,
        Order.status.in_(['pending', 'confirmed', 'processing'])
    ).first()
    
    if pending_orders:
        return jsonify({'error': 'Cannot delete product with pending orders'}), 400
    
    # Soft delete by marking as inactive instead of hard delete
    product.is_active = False
    db.session.commit()
    
    return jsonify({'message': 'Product deleted successfully'})

# Category Routes
@app.route('/api/categories', methods=['GET'])
def get_categories():
    categories = Category.query.filter_by(is_active=True).all()
    return jsonify([{
        'id': c.id,
        'name': c.name,
        'description': c.description,
        'image_url': c.image_url,
        'is_active': c.is_active
    } for c in categories])

@app.route('/api/categories', methods=['POST'])
@admin_required
def create_category():
    data = request.get_json()
    
    category = Category(
        name=data['name'],
        description=data.get('description', ''),
        image_url=data.get('image_url', '')
    )
    
    db.session.add(category)
    db.session.commit()
    
    return jsonify({'message': 'Category created successfully', 'category_id': category.id}), 201

@app.route('/api/categories/<int:category_id>', methods=['PUT'])
@admin_required
def update_category(category_id):
    data = request.get_json()
    category = Category.query.get_or_404(category_id)
    
    category.name = data.get('name', category.name)
    category.description = data.get('description', category.description)
    category.image_url = data.get('image_url', category.image_url)
    
    db.session.commit()
    
    return jsonify({'message': 'Category updated successfully'})

@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@admin_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    
    # Check if category has products
    products_count = Product.query.filter_by(category_id=category_id, is_active=True).count()
    if products_count > 0:
        return jsonify({'error': f'Cannot delete category with {products_count} active products'}), 400
    
    # Soft delete by marking as inactive
    category.is_active = False
    db.session.commit()
    
    return jsonify({'message': 'Category deleted successfully'})

# Cart Routes
@app.route('/api/cart', methods=['GET'])
@login_required
def get_cart():
    cart_items = CartItem.query.filter_by(user_id=session['user_id']).all()
    
    cart_data = []
    total = 0
    
    for item in cart_items:
        product = item.product
        subtotal = float(product.price) * item.quantity
        total += subtotal
        
        cart_data.append({
            'id': item.id,
            'product': {
                'id': product.id,
                'name': product.name,
                'price': float(product.price),
                'image_url': product.image_url
            },
            'quantity': item.quantity,
            'subtotal': subtotal
        })
    
    return jsonify({
        'items': cart_data,
        'total': total
    })

@app.route('/api/cart/items', methods=['POST'])
@login_required
def add_to_cart():
    data = request.get_json()
    product_id = data['product_id']
    quantity = data.get('quantity', 1)
    
    # Check if item already in cart
    cart_item = CartItem.query.filter_by(
        user_id=session['user_id'],
        product_id=product_id
    ).first()
    
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(
            user_id=session['user_id'],
            product_id=product_id,
            quantity=quantity
        )
        db.session.add(cart_item)
    
    db.session.commit()
    return jsonify({'message': 'Item added to cart successfully'})

@app.route('/api/cart/items/<int:item_id>', methods=['PUT'])
@login_required
def update_cart_item(item_id):
    data = request.get_json()
    cart_item = CartItem.query.filter_by(
        id=item_id,
        user_id=session['user_id']
    ).first_or_404()
    
    cart_item.quantity = data['quantity']
    db.session.commit()
    
    return jsonify({'message': 'Cart item updated successfully'})

@app.route('/api/cart/items/<int:item_id>', methods=['DELETE'])
@login_required
def remove_from_cart(item_id):
    cart_item = CartItem.query.filter_by(
        id=item_id,
        user_id=session['user_id']
    ).first_or_404()
    
    db.session.delete(cart_item)
    db.session.commit()
    
    return jsonify({'message': 'Item removed from cart'})

# Order Routes
@app.route('/api/orders', methods=['GET'])
@login_required
def get_orders():
    orders = Order.query.filter_by(user_id=session['user_id']).order_by(Order.created_at.desc()).all()
    
    orders_data = []
    for order in orders:
        orders_data.append({
            'id': order.id,
            'total_amount': float(order.total_amount),
            'status': order.status,
            'created_at': order.created_at.isoformat(),
            'shipping_address': order.shipping_address,
            'items': [{
                'product_name': item.product.name,
                'quantity': item.quantity,
                'unit_price': float(item.unit_price)
            } for item in order.order_items]
        })
    
    return jsonify(orders_data)

@app.route('/api/orders', methods=['POST'])
@login_required
def create_order():
    data = request.get_json()
    
    # Get cart items
    cart_items = CartItem.query.filter_by(user_id=session['user_id']).all()
    
    if not cart_items:
        return jsonify({'error': 'Cart is empty'}), 400
    
    # Calculate total
    total_amount = 0
    for item in cart_items:
        total_amount += float(item.product.price) * item.quantity
    
    # Create order
    order = Order(
        user_id=session['user_id'],
        total_amount=total_amount,
        shipping_address=data['shipping_address']
    )
    
    db.session.add(order)
    db.session.flush()  # Get order ID
    
    # Create order items
    for cart_item in cart_items:
        order_item = OrderItem(
            order_id=order.id,
            product_id=cart_item.product_id,
            quantity=cart_item.quantity,
            unit_price=cart_item.product.price
        )
        db.session.add(order_item)
    
    # Clear cart
    CartItem.query.filter_by(user_id=session['user_id']).delete()
    
    db.session.commit()
    
    return jsonify({'message': 'Order created successfully', 'order_id': order.id}), 201

# Admin Routes
@app.route('/api/admin/orders', methods=['GET'])
@admin_required
def admin_get_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    
    orders_data = []
    for order in orders:
        orders_data.append({
            'id': order.id,
            'user_name': f"{order.user.first_name} {order.user.last_name}",
            'total_amount': float(order.total_amount),
            'status': order.status,
            'created_at': order.created_at.isoformat(),
            'shipping_address': order.shipping_address
        })
    
    return jsonify(orders_data)

@app.route('/api/admin/orders/<int:order_id>/status', methods=['PUT'])
@admin_required
def update_order_status(order_id):
    data = request.get_json()
    order = Order.query.get_or_404(order_id)
    
    order.status = data['status']
    order.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'message': 'Order status updated successfully'})

# Dashboard Stats
@app.route('/api/admin/dashboard/stats', methods=['GET'])
@admin_required
def get_dashboard_stats():
    try:
        # Product stats
        total_products = Product.query.filter_by(is_active=True).count()
        low_stock_products = Product.query.filter(
            Product.is_active == True,
            Product.stock_quantity < 10
        ).count()
        
        # Order stats
        total_orders = Order.query.count()
        pending_orders = Order.query.filter_by(status='pending').count()
        
        # Revenue stats
        total_revenue = db.session.query(db.func.sum(Order.total_amount)).scalar() or 0
        monthly_revenue = db.session.query(db.func.sum(Order.total_amount)).filter(
            Order.created_at >= datetime.utcnow().replace(day=1)
        ).scalar() or 0
        
        # Customer stats
        total_customers = User.query.filter_by(role='customer').count()
        new_customers_this_month = User.query.filter(
            User.role == 'customer',
            User.created_at >= datetime.utcnow().replace(day=1)
        ).count()
        
        return jsonify({
            'products': {
                'total': total_products,
                'low_stock': low_stock_products
            },
            'orders': {
                'total': total_orders,
                'pending': pending_orders
            },
            'revenue': {
                'total': float(total_revenue),
                'monthly': float(monthly_revenue)
            },
            'customers': {
                'total': total_customers,
                'new_monthly': new_customers_this_month
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# User Management Routes
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def get_users():
    users = User.query.filter_by(role='customer').order_by(User.created_at.desc()).all()
    
    return jsonify([{
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'phone': user.phone,
        'is_active': user.is_active,
        'created_at': user.created_at.isoformat(),
        'total_orders': len(user.orders)
    } for user in users])

# Initialize database and sample data
def create_sample_data():
    """Create sample data if database is empty"""
    
    # Create sample admin user
    if not User.query.filter_by(email='admin@grocery.com').first():
        admin_user = User(
            email='admin@grocery.com',
            password_hash=bcrypt.generate_password_hash('admin123').decode('utf-8'),
            first_name='Admin',
            last_name='User',
            role='admin'
        )
        db.session.add(admin_user)
    
    # Create sample categories
    if not Category.query.first():
        categories = [
            Category(name='Fruits & Vegetables', description='Fresh produce', 
                    image_url='https://images.unsplash.com/photo-1610832958506-aa56368176cf?w=400'),
            Category(name='Dairy & Eggs', description='Milk, cheese, eggs',
                    image_url='https://images.unsplash.com/photo-1563636619-e9143da7973b?w=400'),
            Category(name='Meat & Seafood', description='Fresh meat and seafood',
                    image_url='https://images.unsplash.com/photo-1529692236671-f1f6cf9683ba?w=400'),
            Category(name='Bakery', description='Bread and baked goods',
                    image_url='https://images.unsplash.com/photo-1509440159596-0249088772ff?w=400'),
            Category(name='Beverages', description='Drinks and juices',
                    image_url='https://images.unsplash.com/photo-1544145945-f90425340c7e?w=400')
        ]
        for category in categories:
            db.session.add(category)
        
        db.session.commit()  # Commit categories first to get IDs
    
    # Create sample products
    if not Product.query.first():
        products = [
            # Fruits & Vegetables (category_id=1)
            Product(name='Fresh Apples', price=2.99, stock_quantity=100, category_id=1, sku='FRUIT001',
                   description='Crispy red apples, perfect for snacking',
                   image_url='https://images.unsplash.com/photo-1560806887-1e4cd0b6cbd6?w=400'),
            Product(name='Bananas', price=1.99, stock_quantity=150, category_id=1, sku='FRUIT002',
                   description='Fresh yellow bananas, great source of potassium',
                   image_url='https://images.unsplash.com/photo-1571771894821-ce9b6c11b08e?w=400'),
            Product(name='Organic Spinach', price=3.49, stock_quantity=75, category_id=1, sku='VEG001',
                   description='Fresh organic spinach leaves',
                   image_url='https://images.unsplash.com/photo-1576045057995-568f588f82fb?w=400'),
            
            # Dairy & Eggs (category_id=2)
            Product(name='Whole Milk', price=3.49, stock_quantity=50, category_id=2, sku='DAIRY001',
                   description='Fresh whole milk, 1 gallon',
                   image_url='https://images.unsplash.com/photo-1550583724-b2692b85b150?w=400'),
            Product(name='Free Range Eggs', price=4.79, stock_quantity=75, category_id=2, sku='DAIRY002',
                   description='Farm fresh free range eggs, dozen',
                   image_url='https://images.unsplash.com/photo-1582722872445-44dc5f7e3c8f?w=400'),
            Product(name='Greek Yogurt', price=5.99, stock_quantity=60, category_id=2, sku='DAIRY003',
                   description='Creamy Greek yogurt, 32oz container',
                   image_url='https://images.unsplash.com/photo-1488477181946-6428a0291777?w=400'),
            
            # Meat & Seafood (category_id=3)
            Product(name='Chicken Breast', price=8.99, stock_quantity=25, category_id=3, sku='MEAT001',
                   description='Fresh boneless chicken breast, per lb',
                   image_url='https://images.unsplash.com/photo-1604503468506-a8da13d82791?w=400'),
            Product(name='Atlantic Salmon', price=12.99, stock_quantity=20, category_id=3, sku='FISH001',
                   description='Fresh Atlantic salmon fillet, per lb',
                   image_url='https://images.unsplash.com/photo-1544943910-4c1dc44aab44?w=400'),
            
            # Bakery (category_id=4)
            Product(name='Whole Wheat Bread', price=2.49, stock_quantity=40, category_id=4, sku='BAKERY001',
                   description='Fresh baked whole wheat bread loaf',
                   image_url='https://images.unsplash.com/photo-1509440159596-0249088772ff?w=400'),
            Product(name='Croissants', price=4.99, stock_quantity=30, category_id=4, sku='BAKERY002',
                   description='Buttery French croissants, 6 pack',
                   image_url='https://images.unsplash.com/photo-1555507036-ab794f4ade90?w=400'),
            
            # Beverages (category_id=5)
            Product(name='Orange Juice', price=4.99, stock_quantity=30, category_id=5, sku='BEV001',
                   description='Fresh squeezed orange juice, 64oz',
                   image_url='https://images.unsplash.com/photo-1621506289937-a8e4df240d0b?w=400'),
            Product(name='Sparkling Water', price=3.99, stock_quantity=80, category_id=5, sku='BEV002',
                   description='Natural sparkling water, 12 pack',
                   image_url='https://images.unsplash.com/photo-1541014741259-de529411b96a?w=400')
        ]
        for product in products:
            db.session.add(product)
    
    db.session.commit()

# Initialize the app
@app.before_first_request
def create_tables():
    db.create_all()
    create_sample_data()

# Alternative initialization for newer Flask versions
def init_app():
    with app.app_context():
        db.create_all()
        create_sample_data()

if __name__ == '__main__':
    init_app()  # Initialize database and sample data
    app.run(debug=True, port=5000)
