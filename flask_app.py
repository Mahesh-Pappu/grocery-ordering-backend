import os
import datetime
import decimal
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import traceback  # For detailed error logging
import os
import datetime
import decimal 
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import traceback
import psycopg2 # For PostgreSQL
from psycopg2.extras import RealDictCursor # For dictionary-like rows

# Use the PostgreSQL connection functions
from connection import get_db_connection_for_request, close_db_connection_for_request
from product import get_all_products

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY', 'a_very_strong_fallback_secret_key_!@#$_CHANGE_THIS_IN_ENV_FILE')
# Adjust origins if your frontend URL is different or add multiple
CORS(app, resources={r"/*": {"origins": os.getenv("FRONTEND_URL", "http://localhost:5173")}})

@app.teardown_appcontext
def teardown_db(exception=None):
    close_db_connection_for_request(exception)

def get_db():
    return get_db_connection_for_request()

# --- JWT Token Required Decorator ---
def token_required(f):
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id'] # This holds the customer_id
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            print(f"Token decoding error: {e}\n{traceback.format_exc()}")
            return jsonify({'message': 'Error processing token.'}), 401
        return f(current_user_id, *args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# --- User Auth API Endpoints ---
@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    if not data: return jsonify({'error': 'Request body must be JSON'}), 400
    
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    address = data.get('address')
    phone = data.get('phone')
    
    if not all([name, email, password, address, phone]):
        return jsonify({'error': 'All fields (Name, Email, Password, Address, Phone) are required for signup'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters long'}), 400
    if '@' not in email or '.' not in email:
        return jsonify({'error': 'Invalid email format'}), 400
    phone_str = str(phone).strip()
    if not (phone_str.isdigit() and len(phone_str) >= 7 and len(phone_str) <= 15): # Example phone validation
        return jsonify({'error': 'Invalid phone number format.'}), 400

    conn = get_db()
    if not conn: return jsonify({'error': 'Database connection failed'}), 500
    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT customer_id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({'error': 'Email already registered'}), 409
        
        hashed_password = generate_password_hash(password)
        query = """
            INSERT INTO users (name, email, password, address, phone) 
            VALUES (%s, %s, %s, %s, %s) RETURNING customer_id
        """
        cursor.execute(query, (name, email, hashed_password, address, phone))
        user_row = cursor.fetchone()
        if not user_row or 'customer_id' not in user_row:
            conn.rollback()
            return jsonify({'error': 'Failed to create user account.'}), 500
        user_customer_id = user_row['customer_id']
        conn.commit()

        token_payload = {'user_id': user_customer_id, 'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({
            'message': 'Signup successful! Welcome.',
            'user': {'customer_id': user_customer_id, 'name': name, 'email': email, 'address': address, 'phone': phone},
            'token': token
        }), 201
    except psycopg2.Error as db_err:
        if conn: conn.rollback()
        print(f"PostgreSQL Signup Error: {db_err}\n{traceback.format_exc()}")
        error_message = db_err.diag.message_detail if hasattr(db_err, 'diag') and db_err.diag else str(db_err)
        return jsonify({'error': f'Database error during signup: {error_message}'}), 500
    except Exception as e:
        if conn: conn.rollback()
        print(f"Generic Signup Error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'An error occurred during signup.'}), 500
    finally:
        if cursor: cursor.close()

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data: return jsonify({'error': 'Request body must be JSON'}), 400
    email, password = data.get('email'), data.get('password')
    if not all([email, password]):
        return jsonify({'error': 'Email and password are required'}), 400

    conn = get_db()
    if not conn: return jsonify({'error': 'Database connection failed'}), 500
    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT customer_id, name, email, password, address, phone FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password): 
            token_payload = {'user_id': user['customer_id'], 'email': user['email'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}
            token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")
            return jsonify({
                'message': 'Login successful!',
                'user': {
                    'customer_id': user['customer_id'], 'name': user['name'], 'email': user['email'],
                    'address': user.get('address'), 'phone': user.get('phone')
                },
                'token': token
            }), 200
        else:
            return jsonify({'error': 'Invalid email or password'}), 401
    except psycopg2.Error as db_err:
        print(f"PostgreSQL Login Error: {db_err}\n{traceback.format_exc()}")
        error_message = db_err.diag.message_detail if hasattr(db_err, 'diag') and db_err.diag else str(db_err)
        return jsonify({'error': f'Database error during login: {error_message}'}), 500
    except Exception as e:
        print(f"Generic Login Error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'An error occurred during login.'}), 500
    finally:
        if cursor: cursor.close()

@app.route('/api/profile', methods=['GET'])
@token_required
def api_profile(current_user_id):
    conn = get_db()
    if not conn: return jsonify({'error': 'Database connection failed'}), 500
    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT customer_id, name, email, address, phone FROM users WHERE customer_id = %s", (current_user_id,))
        user_data = cursor.fetchone()
        if not user_data: return jsonify({'error': 'User not found'}), 404
        return jsonify({'user': user_data}), 200
    except psycopg2.Error as db_err:
        print(f"PostgreSQL Profile Error: {db_err}\n{traceback.format_exc()}")
        error_message = db_err.diag.message_detail if hasattr(db_err, 'diag') and db_err.diag else str(db_err)
        return jsonify({'error': f'Database error fetching profile: {error_message}'}), 500
    except Exception as e:
        print(f"Generic Profile fetch error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'An error occurred while fetching profile.'}), 500
    finally:
        if cursor: cursor.close()

@app.route('/api/products', methods=['GET'])
def api_products():
    conn = get_db()
    if not conn: return jsonify({'error': 'Database connection failed'}), 500
    try:
        products_data = get_all_products(conn) 
        return jsonify(products_data), 200
    except Exception as e: # get_all_products should handle its own psycopg2.Error
        print(f"Error fetching products (controller): {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to fetch products'}), 500

@app.route('/api/orders/create', methods=['POST'])
@token_required
def api_create_order(current_user_id):
    data = request.get_json()
    if not data: return jsonify({'error': 'Request body must be JSON'}), 400

    items = data.get('items') 
    total_amount_frontend = data.get('total_amount')
    shipping_details_data = data.get('shipping_details', {})
    payment_details_data = data.get('payment_details', {'method': 'Cash on Delivery', 'status': 'pending'})

    if not items or not isinstance(items, list) or total_amount_frontend is None:
        return jsonify({'error': 'Order items (as a list) and total amount are required'}), 400
    if not all(isinstance(item, dict) for item in items):
         return jsonify({'error': 'Each item in items must be an object'}), 400

    conn = get_db()
    if not conn or not conn.is_connected():
        return jsonify({'error': 'Database connection problem for creating order'}), 500
    
    calculated_total = 0.0
    product_info_map = {}
    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        # psycopg2 connections start a transaction implicitly if autocommit is False (default)
        
        for item in items:
            product_id = item.get('product_id')
            quantity = item.get('quantity')
            if not (isinstance(product_id, int) and isinstance(quantity, (int, float)) and float(quantity) > 0):
                conn.rollback(); return jsonify({'error': f"Invalid data for item: {item}"}), 400
            
            item_quantity = float(quantity)
            # Use SELECT ... FOR UPDATE for row locking in PostgreSQL if needed, depends on isolation level
            cursor.execute("SELECT product_name, price, inventory FROM products WHERE product_id = %s", (product_id,)) # FOR UPDATE
            product_db = cursor.fetchone()

            if not product_db:
                conn.rollback(); return jsonify({'error': f"Product ID {product_id} not found."}), 404
            if item_quantity > product_db['inventory']:
                conn.rollback(); return jsonify({'error': f"Not enough stock for {product_db['product_name']}. Available: {product_db['inventory']}"}), 400
            
            current_price = float(product_db['price']) if isinstance(product_db['price'], decimal.Decimal) else float(product_db['price'])
            product_info_map[product_id] = {'price': current_price}
            calculated_total += current_price * item_quantity

        if abs(calculated_total - float(total_amount_frontend)) > 0.01:
            print(f"Warning: Total amount mismatch. Frontend: {total_amount_frontend}, Backend: {calculated_total}.")
           
        order_query = """INSERT INTO orders 
                         (order_date, total, customer_id, status, 
                          shipping_name, shipping_email, shipping_address, shipping_phone, 
                          payment_method, payment_status) 
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING order_id"""
        cursor.execute(order_query, (
            datetime.datetime.now(), calculated_total, current_user_id, 'Pending',
            shipping_details_data.get('name'), shipping_details_data.get('email'),
            shipping_details_data.get('address'), shipping_details_data.get('phone'),
            payment_details_data.get('method', 'Cash on Delivery'), 
            payment_details_data.get('status', 'pending')
        ))
        order_id_row = cursor.fetchone()
        if not order_id_row or 'order_id' not in order_id_row:
            conn.rollback()
            return jsonify({'error': 'Failed to retrieve order ID after creation.'}), 500
        order_id = order_id_row['order_id']

        order_item_query = "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (%s, %s, %s, %s)"
        update_inventory_query = "UPDATE products SET inventory = inventory - %s WHERE product_id = %s"

        for item in items:
            product_id = item.get('product_id')
            item_quantity = float(item.get('quantity'))
            price_for_item = product_info_map[product_id]['price']
            cursor.execute(order_item_query, (order_id, product_id, item_quantity, price_for_item))
            cursor.execute(update_inventory_query, (item_quantity, product_id))
        
        conn.commit()
        return jsonify({
            'message': 'Order created successfully!', 'order_id': order_id, 'total_charged': calculated_total 
        }), 201
    except psycopg2.Error as db_err:
        if conn: conn.rollback()
        print(f"PostgreSQL Create Order Error: {db_err}\n{traceback.format_exc()}")
        error_message = db_err.diag.message_detail if hasattr(db_err, 'diag') and db_err.diag else str(db_err)
        return jsonify({'error': f'Database error creating order: {error_message}'}), 500
    except Exception as e:
        if conn: conn.rollback()
        print(f"Generic Create Order Error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Could not create order due to a server error.'}), 500
    finally:
        if cursor: cursor.close()

@app.route('/api/my-orders', methods=['GET'])
@token_required
def get_my_orders(current_user_id):
    conn = get_db()
    if not conn or not conn.is_connected():
        return jsonify({'error': 'Database connection problem'}), 500

    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        query_orders = """
            SELECT o.order_id, o.order_date, o.total, o.status,
                   o.shipping_name, o.shipping_address, o.shipping_phone, o.shipping_email,
                   o.payment_method, o.payment_status
            FROM orders o
            WHERE o.customer_id = %s
            ORDER BY o.order_date DESC
        """
        cursor.execute(query_orders, (current_user_id,))
        orders_data = cursor.fetchall()
        
        orders_with_items = []
        for order_dict in orders_data:
            order_copy = order_dict.copy()
            query_items = """
                SELECT oi.product_id, oi.quantity, oi.price AS price_at_purchase, 
                       p.product_name, p.image_url
                FROM order_items oi
                JOIN products p ON oi.product_id = p.product_id
                WHERE oi.order_id = %s
            """
            cursor.execute(query_items, (order_dict['order_id'],))
            items_data = cursor.fetchall()
            
            formatted_items = []
            for item_row in items_data:
                item_row_copy = item_row.copy()
                if isinstance(item_row_copy.get('price_at_purchase'), decimal.Decimal):
                    item_row_copy['price_at_purchase'] = float(item_row_copy['price_at_purchase'])
                formatted_items.append(item_row_copy)
            
            order_copy['items'] = formatted_items
            if isinstance(order_copy.get('total'), decimal.Decimal):
                order_copy['total'] = float(order_copy['total'])
            orders_with_items.append(order_copy)
            
        return jsonify(orders_with_items), 200
    except psycopg2.Error as db_err:
        print(f"PostgreSQL My Orders Error: {db_err}\n{traceback.format_exc()}")
        error_message = db_err.diag.message_detail if hasattr(db_err, 'diag') and db_err.diag else str(db_err)
        return jsonify({'error': f'Database error fetching orders: {error_message}'}), 500
    except Exception as e:
        print(f"Generic Error fetching user orders: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Could not retrieve your orders.'}), 500
    finally:
        if cursor: cursor.close()

@app.route('/api/orders/<int:order_id>/cancel', methods=['PUT'])
@token_required
def cancel_order_api(current_user_id, order_id):
    conn = get_db()
    if not conn or not conn.is_connected():
        return jsonify({'error': 'Database connection problem for cancel order.'}), 500

    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        # Implicit transaction starts with first execute with psycopg2 if autocommit is False

        cursor.execute("SELECT status, customer_id, order_date FROM orders WHERE order_id = %s", (order_id,)) # FOR UPDATE
        order_details = cursor.fetchone()

        if not order_details:
            conn.rollback(); return jsonify({'error': 'Order not found'}), 404
        if order_details['customer_id'] != current_user_id:
            conn.rollback(); return jsonify({'error': 'You are not authorized to cancel this order'}), 403

        current_order_status = order_details.get('status', 'Pending').lower()
        allowed_cancel_statuses = ['pending', 'processing'] 
        if current_order_status not in allowed_cancel_statuses:
            conn.rollback()
            return jsonify({'error': f'Order cannot be canceled. Current status: {current_order_status.capitalize()}'}), 400
        
        cursor.execute("SELECT product_id, quantity FROM order_items WHERE order_id = %s", (order_id,))
        order_items = cursor.fetchall()

        if order_items:
            update_inventory_query = "UPDATE products SET inventory = inventory + %s WHERE product_id = %s"
            for item in order_items:
                item_quantity = float(item['quantity'])
                cursor.execute(update_inventory_query, (item_quantity, item['product_id']))
        
        cursor.execute("UPDATE orders SET status = 'Canceled' WHERE order_id = %s", (order_id,))
        conn.commit()
        return jsonify({'message': f'Order ID {order_id} has been successfully canceled.'}), 200
    except psycopg2.Error as db_err:
        if conn: conn.rollback()
        print(f"PostgreSQL Cancel Order Error: {db_err}\n{traceback.format_exc()}")
        error_message = db_err.diag.message_detail if hasattr(db_err, 'diag') and db_err.diag else str(db_err)
        return jsonify({'error': f'Database error canceling order: {error_message}'}), 500
    except Exception as e:
        if conn: conn.rollback()
        print(f"Generic Error canceling order {order_id}: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Could not cancel the order due to a server error.'}), 500
    finally:
        if cursor: cursor.close()

@app.route('/api/test_db', methods=['GET'])
def test_db_connection():
    conn = get_db()
    if conn and not conn.closed: # Check if not closed for psycopg2
        # Optionally try a simple query
        # cursor = conn.cursor()
        # cursor.execute("SELECT 1")
        # cursor.fetchone()
        # cursor.close()
        return jsonify({"message": "Database connection (per-request) successful!"}), 200
    else:
        return jsonify({"error": "Database connection (per-request) failed or closed."}), 500

if __name__ == '__main__':
    port = int(os.getenv('FLASK_RUN_PORT', 5000))
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    print(f"--- Flask Grocery App (PostgreSQL Version) ---")
    print(f"Attempting to start on http://0.0.0.0:{port}")
    print(f"Debug mode: {debug_mode}")
    print(f"Frontend expected at: {os.getenv('FRONTEND_URL')}")
    secret_key_status = 'Yes' if app.config['SECRET_KEY'] != 'fallback_secret_key_CHANGE_THIS_IN_ENV_FILE' else 'NO - USING FALLBACK (INSECURE!)'
    print(f"App Secret Key Loaded from .env: {secret_key_status}")
    app.run(debug=debug_mode, port=port, host='0.0.0.0')
from connection import get_sql_connection
from product import get_all_products

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY', 'fallback_secret_key_CHANGE_THIS')
CORS(
    app,
    resources={r"/api/*": {"origins": "https://grocery-mart.onrender.com"}}, # Removed trailing slash, usually fine
    allow_headers=["Content-Type", "Authorization"], # Explicitly allow common headers
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], # Explicitly allow methods
    supports_credentials=True, # If you ever use cookies/session-based auth with credentials
    expose_headers=["Content-Length", "X-My-Custom-Header"] # If frontend needs to read specific headers
)


def get_db():
    return get_sql_connection()


def token_required(f):
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id']  # This holds the customer_id
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            print(f"Token decoding error: {e}")
            return jsonify({'message': 'Error processing token.'}), 401
        return f(current_user_id, *args, **kwargs)

    decorated.__name__ = f.__name__
    return decorated


@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body must be JSON'}), 400

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    address = data.get('address')  # <-- NEW: Get address
    phone = data.get('phone')  # <-- NEW: Get phone

    # Updated validation to include new fields (make them optional or required as you see fit)
    # For this example, let's make them required for signup.
    if not all([name, email, password, address, phone]):
        return jsonify({'error': 'All fields (Name, Email, Password, Address, Phone) are required for signup'}), 400

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters long'}), 400
    if '@' not in email or '.' not in email:
        return jsonify({'error': 'Invalid email format'}), 400
    # Add any validation for address and phone if needed (e.g., phone number format)

    conn = get_db()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT customer_id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({'error': 'Email already registered'}), 409

        hashed_password = generate_password_hash(password)

        # Updated query to include address and phone
        # Make sure your 'users' table has these exact column names
        query = "INSERT INTO users (name, email, password, address, phone) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(query, (name, email, hashed_password, address, phone))
        conn.commit()
        user_customer_id = cursor.lastrowid

        token_payload = {
            'user_id': user_customer_id,
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({
            'message': 'Signup successful! Welcome.',
            'user': {  # Optionally include address and phone in the returned user object
                'customer_id': user_customer_id,
                'name': name,
                'email': email,
                'address': address,  # <-- NEW
                'phone': phone  # <-- NEW
            },
            'token': token
        }), 201

    except Exception as e:
        if conn: conn.rollback()
        print(f"Signup Error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'An error occurred during signup. Please try again.'}), 500
    finally:
        if cursor: cursor.close()
        conn.close()


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data: return jsonify({'error': 'Request body must be JSON'}), 400
    email, password = data.get('email'), data.get('password')
    if not all([email, password]):
        return jsonify({'error': 'Email and password are required'}), 400

    conn = get_db()
    if not conn: return jsonify({'error': 'Database connection failed'}), 500
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT customer_id, name, email, password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user or check_password_hash(user['password'], password):
            token_payload = {'user_id': user['customer_id'], 'email': user['email'],
                             'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}
            token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")
            return jsonify({
                'message': 'Login successful!',
                'user': {'customer_id': user['customer_id'], 'name': user['name'], 'email': user['email']},
                'token': token
            }), 200
        else:
            return jsonify({'error': 'Invalid email or password'}), 401
    except Exception as e:
        print(f"Login Error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'An error occurred during login.'}), 500
    finally:
        if cursor: cursor.close()
        conn.close()





@app.route('/api/my-orders', methods=['GET'])
@token_required
def get_my_orders(current_user_id):  # current_user_id is customer_id
    print(f"--- Fetching orders for customer_id: {current_user_id} ---")
    conn = get_db()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    if not conn.is_connected():
        print("!!! DB Connection not active in get_my_orders !!!")
        return jsonify({'error': 'Database connection lost'}), 500

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        # Query to get orders for the current user
        # Ensure your orders table has status, payment_method, payment_status, shipping_address etc.
        # if you want to display them.
        query_orders = """
            SELECT 
                o.order_id, o.order_date, o.total, o.status
            FROM orders o
            WHERE o.customer_id = %s
            ORDER BY o.order_date DESC
        """
        cursor.execute(query_orders, (current_user_id,))
        orders_data = cursor.fetchall()
        print(f"Fetched {len(orders_data)} base orders.")

        orders_with_items = []
        for order in orders_data:
            order_copy = order.copy()  # Work on a copy

            # Fetch items for this order
            query_items = """
                SELECT 
                    oi.product_id, oi.quantity, 
                    oi.price AS price_at_purchase, 
                    p.product_name, p.image_url
                FROM order_items oi
                JOIN products p ON oi.product_id = p.product_id
                WHERE oi.order_id = %s
            """
            cursor.execute(query_items, (order['order_id'],))
            items_data = cursor.fetchall()

            formatted_items = []
            for item_row in items_data:
                item_row_copy = item_row.copy()
                if 'price_at_purchase' in item_row_copy and isinstance(item_row_copy['price_at_purchase'],
                                                                       decimal.Decimal):
                    item_row_copy['price_at_purchase'] = float(item_row_copy['price_at_purchase'])
                formatted_items.append(item_row_copy)

            order_copy['items'] = formatted_items

            if 'total' in order_copy and isinstance(order_copy['total'], decimal.Decimal):
                order_copy['total'] = float(order_copy['total'])

            orders_with_items.append(order_copy)

        return jsonify(orders_with_items), 200

    except Exception as e:
        print(f"Error fetching user orders: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Could not retrieve your orders.'}), 500
    finally:
        if cursor: cursor.close()
        conn.close()


@app.route('/api/orders/<int:order_id>/cancel', methods=['PUT'])
@token_required
def cancel_order_api(current_user_id, order_id):
    print(f"--- Attempting to cancel order_id: {order_id} for customer_id: {current_user_id} ---")
    conn = get_db()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    if not conn.is_connected():
        print("!!! DB Connection not active in cancel_order_api !!!")
        return jsonify({'error': 'Database connection lost'}), 500

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        #conn.start_transaction()

        cursor.execute("SELECT status, customer_id, order_date FROM orders WHERE order_id = %s FOR UPDATE",
                       (order_id,))  # Lock order row
        order = cursor.fetchone()

        if not order:
            conn.rollback()
            return jsonify({'error': 'Order not found'}), 404

        if order['customer_id'] != current_user_id:
            conn.rollback()
            return jsonify({'error': 'You are not authorized to cancel this order'}), 403

        current_order_status = order.get('status', 'Pending').lower()
        allowed_cancel_statuses = ['pending', 'processing']  # Define which statuses allow cancellation

        # Example: Time-based check - only cancel within 1 hour
        # order_placed_time = order['order_date']
        # if datetime.datetime.now() > order_placed_time + datetime.timedelta(hours=1):
        #     conn.rollback()
        #     return jsonify({'error': 'Order cannot be canceled after 1 hour.'}), 400

        if current_order_status not in allowed_cancel_statuses:
            conn.rollback()
            return jsonify(
                {'error': f'Order cannot be canceled. Current status: {current_order_status.capitalize()}'}), 400

        # Fetch items to restore inventory
        cursor.execute("SELECT product_id, quantity FROM order_items WHERE order_id = %s", (order_id,))
        order_items = cursor.fetchall()

        if order_items:
            update_inventory_query = "UPDATE products SET inventory = inventory + %s WHERE product_id = %s"
            for item in order_items:
                item_quantity = float(item['quantity'])  # If quantity in order_items is DOUBLE
                cursor.execute(update_inventory_query, (item_quantity, item['product_id']))
        else:
            print(f"Warning: Order {order_id} has no items to restore to inventory.")

        # Update order status
        cursor.execute("UPDATE orders SET status = 'Canceled' WHERE order_id = %s", (order_id,))

        conn.commit()
        print(f"Order {order_id} successfully canceled.")
        return jsonify({'message': f'Order ID {order_id} has been successfully canceled.'}), 200

    except Exception as e:
        if conn: conn.rollback()
        print(f"Error canceling order {order_id}: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Could not cancel the order due to a server error.'}), 500
    finally:
        if cursor: cursor.close()
        conn.close()


@app.route('/api/profile', methods=['GET'])
@token_required
def api_profile(current_user_id):
    conn = get_db()
    if not conn: return jsonify({'error': 'Database connection failed'}), 500
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT customer_id, name, email FROM users WHERE customer_id = %s", (current_user_id,))
        user_data = cursor.fetchone()
        if not user_data: return jsonify({'error': 'User not found'}), 404
        return jsonify({'user': user_data}), 200
    except Exception as e:
        print(f"Profile fetch error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'An error occurred while fetching profile.'}), 500
    finally:
        if cursor: cursor.close()
        conn.close()


@app.route('/api/products', methods=['GET'])
def api_products():
    conn = get_db()
    if not conn: return jsonify({'error': 'Database connection failed'}), 500
    try:
        products_data = get_all_products(conn)
        return jsonify(products_data), 200
    except Exception as e:
        print(f"Error fetching products: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to fetch products'}), 500
    finally:
        conn.close()


# ... (all other imports and flask app setup from previous full flask_app.py)
# ... (token_required decorator, api_signup, api_login, api_profile, api_products)

@app.route('/api/orders/create', methods=['POST'])
@token_required
def api_create_order(current_user_id):  # current_user_id is customer_id from token
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body must be JSON'}), 400

    items = data.get('items')  # Expected: [{product_id, quantity}, ...]
    # Frontend sends price, but we'll use backend price for security
    total_amount_frontend = data.get('total_amount')  # For validation against backend calculation

    # We don't use shipping_details or payment_details if not in your 'orders' table schema
    # shipping_details_data = data.get('shipping_details', {})
    # payment_details_data = data.get('payment_details', {'method': 'Cash on Delivery', 'status': 'pending'})

    if not items or total_amount_frontend is None:
        return jsonify({'error': 'Order items and total amount are required'}), 400

    conn = get_db()
    if not conn: return jsonify({'error': 'Database connection failed'}), 500

    calculated_total = 0.0
    product_info_map = {}
    cursor = None

    try:
        cursor = conn.cursor(dictionary=True)
        conn.start_transaction()

        # Validate items, calculate total from backend prices, check inventory
        for item in items:
            if not isinstance(item.get('product_id'), int) or not isinstance(item.get('quantity'), (
            int, float)):  # Allow float for quantity if schema is DOUBLE
                conn.rollback()
                return jsonify({'error': 'Invalid item data format (product_id or quantity).'}), 400

            item_quantity = float(item['quantity'])  # Convert to float if schema is DOUBLE
            if item_quantity <= 0:
                conn.rollback()
                return jsonify({'error': f"Invalid quantity for product ID {item['product_id']}"}), 400

            # Lock product row for update to prevent race conditions on inventory
            cursor.execute("SELECT product_name, price, inventory FROM products WHERE product_id = %s FOR UPDATE",
                           (item['product_id'],))
            product_db = cursor.fetchone()

            if not product_db:
                conn.rollback()
                return jsonify({'error': f"Product ID {item['product_id']} not found."}), 404
            if item_quantity > product_db['inventory']:
                conn.rollback()
                return jsonify({
                                   'error': f"Not enough stock for {product_db['product_name']}. Available: {product_db['inventory']}"}), 400

            current_price = float(product_db['price']) if isinstance(product_db['price'], decimal.Decimal) else float(
                product_db['price'])
            product_info_map[item['product_id']] = {
                'price': current_price,
                'inventory': product_db['inventory']
            }
            calculated_total += current_price * item_quantity

        # Optional: Compare calculated_total with frontend's total_amount
        if abs(calculated_total - float(total_amount_frontend)) > 0.01:  # 1 cent tolerance
            print(
                f"Warning: Total amount mismatch. Frontend: {total_amount_frontend}, Backend calculated: {calculated_total}. Using backend total for order record.")

        # 1. Insert into 'orders' table (using ONLY columns from your schema)
        order_query = """INSERT INTO orders 
                         (order_date, total, customer_id, status) 
                         VALUES (%s, %s, %s, %s)"""
        cursor.execute(order_query, (
            datetime.datetime.now(),
            calculated_total,  # Use backend calculated total
            current_user_id,
            'Pending'
        ))
        order_id = cursor.lastrowid

        # 2. Insert into 'order_items' table
        order_item_query = ("INSERT INTO order_items (order_id, product_id, quantity, price) "
                            "VALUES (%s, %s, %s, %s)")
        # 3. Update inventory in 'products' table
        update_inventory_query = "UPDATE products SET inventory = inventory - %s WHERE product_id = %s"

        for item in items:
            price_for_item = product_info_map[item['product_id']]['price']
            item_quantity = float(item['quantity'])  # Ensure it's float if schema is DOUBLE
            cursor.execute(order_item_query, (order_id, item['product_id'], item_quantity, price_for_item))
            cursor.execute(update_inventory_query, (item_quantity, item['product_id']))

        conn.commit()  # Commit all changes if everything is successful
        conn.close()

        return jsonify({
            'message': 'Order created successfully!',
            'order_id': order_id,
            'total_charged': calculated_total
        }), 201

    except Exception as e:
        if conn: conn.rollback()
        print(f"Error creating order: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Could not create order due to a server error.'}), 500
    finally:
        if cursor: cursor.close()


# ... (test_db and if __name__ == '__main__': block, and other API routes as before) ...
# Ensure you have the full api_signup, api_login, api_profile, api_products, and test_db routes
# from the previous "full code" response.


@app.route('/api/test_db', methods=['GET'])
def test_db_connection():
    conn = get_db()
    if conn and conn.is_connected():
        return jsonify({"message": "Database connection successful!"}), 200
    else:
        return jsonify({"error": "Database connection failed."}), 500


if __name__ == '__main__':
    port = int(os.getenv('FLASK_RUN_PORT', 5000))
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    print(f"Starting Flask app on port {port} with debug mode: {debug_mode}")
    app.run(debug=debug_mode, port=port, host='0.0.0.0')