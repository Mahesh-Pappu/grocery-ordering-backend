import os
import datetime
import decimal 
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import traceback
import psycopg2
from psycopg2.extras import RealDictCursor

from connection import get_db_connection_for_request, close_db_connection_for_request # Ensure this is your PG version
from product import get_all_products # Ensure this is your PG version

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY', 'a_very_strong_fallback_secret_key_!@#$_CHANGE_THIS_IN_ENV_FILE')

# Using your provided frontend URL directly here for now,
# but using os.getenv("FRONTEND_URL") and setting it on Render is more flexible.
CORS(
    app,
    resources={r"/api/*": {
        "origins": "https://grocery-mart.onrender.com",  # Ensure no trailing slash
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }},
    supports_credentials=True,
    expose_headers=["Content-Length"]
)

@app.teardown_appcontext
def teardown_db(exception=None):
    close_db_connection_for_request(exception)

def get_db():
    return get_db_connection_for_request()

def token_required(f):
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]
        if not token: return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id'] 
        except jwt.ExpiredSignatureError: return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError: return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            print(f"Token decoding error: {e}\n{traceback.format_exc()}")
            return jsonify({'message': 'Error processing token.'}), 401
        return f(current_user_id, *args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    if not data: return jsonify({'error': 'Request body must be JSON'}), 400
    name, email, password, address, phone = (data.get('name'), data.get('email'), 
                                             data.get('password'), data.get('address'), 
                                             data.get('phone'))
    if not all([name, email, password, address, phone]):
        return jsonify({'error': 'All fields are required for signup'}), 400
    if len(password) < 6: return jsonify({'error': 'Password too short'}), 400
    if '@' not in email or '.' not in email: return jsonify({'error': 'Invalid email'}), 400
    phone_str = str(phone).strip()
    if not (phone_str.isdigit() and 7 <= len(phone_str) <= 15): return jsonify({'error': 'Invalid phone'}), 400

    conn = get_db()
    if not conn: return jsonify({'error': 'Database connection failed'}), 500
    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT customer_id FROM users WHERE email = %s", (email,))
        if cursor.fetchone(): return jsonify({'error': 'Email already registered'}), 409
        
        hashed_password = generate_password_hash(password)
        query = "INSERT INTO users (name, email, password, address, phone) VALUES (%s, %s, %s, %s, %s) RETURNING customer_id"
        cursor.execute(query, (name, email, hashed_password, address, phone))
        user_row = cursor.fetchone()
        if not user_row: conn.rollback(); return jsonify({'error': 'Signup failed.'}), 500
        user_customer_id = user_row['customer_id']
        conn.commit()

        token_payload = {'user_id': user_customer_id, 'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({
            'message': 'Signup successful! Welcome.',
            'user': {'customer_id': user_customer_id, 'name': name, 'email': email, 'address': address, 'phone': phone},
            'token': token
        }), 201
    except psycopg2.Error as db_err: # Catch specific DB errors
        if conn: conn.rollback()
        print(f"PG Signup Error: {db_err}\n{traceback.format_exc()}")
        return jsonify({'error': f'Database error: {db_err.diag.message_detail if hasattr(db_err, "diag") else str(db_err)}'}), 500
    except Exception as e:
        if conn: conn.rollback()
        print(f"Signup Error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'An error occurred during signup.'}), 500
    finally:
        if cursor: cursor.close()

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data: return jsonify({'error': 'Request body must be JSON'}), 400
    email, password = data.get('email'), data.get('password')
    if not all([email, password]): return jsonify({'error': 'Email and password are required'}), 400

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
                'user': {'customer_id': user['customer_id'], 'name': user['name'], 'email': user['email'], 'address': user.get('address'), 'phone': user.get('phone')},
                'token': token
            }), 200
        else:
            return jsonify({'error': 'Invalid email or password'}), 401
    except psycopg2.Error as db_err:
        print(f"PG Login Error: {db_err}\n{traceback.format_exc()}")
        return jsonify({'error': f'Database error: {db_err.diag.message_detail if hasattr(db_err, "diag") else str(db_err)}'}), 500
    except Exception as e:
        print(f"Login Error: {e}\n{traceback.format_exc()}")
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
    except psycopg2.Error as db_err: # ...
        print(f"PG Profile Error: {db_err}\n{traceback.format_exc()}")
        return jsonify({'error': f'Database error: {db_err.diag.message_detail if hasattr(db_err, "diag") else str(db_err)}'}), 500
    except Exception as e: # ...
        print(f"Generic Profile Error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'An error fetching profile.'}), 500
    finally:
        if cursor: cursor.close()

@app.route('/api/products', methods=['GET'])
def api_products():
    conn = get_db()
    if not conn: return jsonify({'error': 'Database connection failed'}), 500
    try:
        products_data = get_all_products(conn) 
        return jsonify(products_data), 200
    except Exception as e:
        print(f"Error fetching products (controller): {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to fetch products.'}), 500

@app.route('/api/orders/create', methods=['POST'])
@token_required
def api_create_order(current_user_id):
    data = request.get_json()
    if not data: return jsonify({'error': 'Request body must be JSON'}), 400
    items = data.get('items') 
    total_amount_frontend = data.get('total_amount')
    # Shipping and payment details are not part of the simple orders table as per your schema
    # We will ignore shipping_details and payment_details from frontend payload for DB insert

    if not items or not isinstance(items, list) or total_amount_frontend is None:
        return jsonify({'error': 'Order items (list) and total amount are required'}), 400
    if not all(isinstance(item, dict) and 'product_id' in item and 'quantity' in item for item in items):
         return jsonify({'error': 'Each item must be an object with product_id and quantity'}), 400

    conn = get_db()
    if not conn or not conn.is_connected():
        return jsonify({'error': 'Database connection problem'}), 500
    
    calculated_total = 0.0
    product_info_map = {}
    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        # psycopg2 starts transaction implicitly if autocommit is False (default)
        
        for item in items:
            product_id = item['product_id'] # Assume these keys exist due to above check
            quantity = item['quantity']
            if not (isinstance(product_id, int) and isinstance(quantity, (int, float)) and float(quantity) > 0):
                if conn: conn.rollback(); 
                return jsonify({'error': f"Invalid data for item with product_id {product_id}"}), 400
            
            item_quantity = float(quantity)
            cursor.execute("SELECT product_name, price, inventory FROM products WHERE product_id = %s FOR UPDATE", (product_id,))
            product_db = cursor.fetchone()

            if not product_db:
                if conn: conn.rollback(); 
                return jsonify({'error': f"Product ID {product_id} not found."}), 404
            if item_quantity > product_db['inventory']:
                if conn: conn.rollback(); 
                return jsonify({'error': f"Not enough stock for {product_db['product_name']}. Available: {product_db['inventory']}"}), 400
            
            current_price = float(product_db['price']) if isinstance(product_db['price'], decimal.Decimal) else float(product_db['price'])
            product_info_map[product_id] = {'price': current_price}
            calculated_total += current_price * item_quantity

        if abs(calculated_total - float(total_amount_frontend)) > 0.01:
            print(f"Warning: Total amount mismatch. Frontend: {total_amount_frontend}, Backend: {calculated_total}.")
           
        # INSERT into 'orders' table using ONLY columns from your schema: order_date, total, customer_id, status
        order_query = """INSERT INTO orders (order_date, total, customer_id, status) 
                         VALUES (%s, %s, %s, %s) RETURNING order_id"""
        cursor.execute(order_query, (
            datetime.datetime.now(), 
            calculated_total, 
            current_user_id, 
            'Pending' # Default initial status
        ))
        order_id_row = cursor.fetchone()
        if not order_id_row or 'order_id' not in order_id_row:
            if conn: conn.rollback(); 
            return jsonify({'error': 'Failed to retrieve order ID after creation.'}), 500
        order_id = order_id_row['order_id']

        order_item_query = "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (%s, %s, %s, %s)"
        update_inventory_query = "UPDATE products SET inventory = inventory - %s WHERE product_id = %s"
        for item in items:
            product_id = item['product_id']
            item_quantity = float(item['quantity'])
            price_for_item = product_info_map[product_id]['price']
            cursor.execute(order_item_query, (order_id, product_id, item_quantity, price_for_item))
            cursor.execute(update_inventory_query, (item_quantity, product_id))
        
        conn.commit()
        return jsonify({'message': 'Order created successfully!', 'order_id': order_id, 'total_charged': calculated_total}), 201
    except psycopg2.Error as db_err:
        if conn: conn.rollback()
        print(f"PG Create Order Error: {db_err}\n{traceback.format_exc()}")
        return jsonify({'error': f'Database error: {db_err.diag.message_detail if hasattr(db_err, "diag") else str(db_err)}'}), 500
    except Exception as e:
        if conn: conn.rollback()
        print(f"Generic Create Order Error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Could not create order.'}), 500
    finally:
        if cursor: cursor.close()

@app.route('/api/my-orders', methods=['GET'])
@token_required
def get_my_orders(current_user_id):
    conn = get_db()
    if not conn or not conn.is_connected(): return jsonify({'error': 'Database problem'}), 500
    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        # Select ONLY columns present in your 'orders' schema
        query_orders = """
            SELECT o.order_id, o.order_date, o.total, o.status
            FROM orders o WHERE o.customer_id = %s ORDER BY o.order_date DESC
        """
        cursor.execute(query_orders, (current_user_id,))
        orders_data = cursor.fetchall()
        
        orders_with_items = []
        for order_dict in orders_data:
            order_copy = order_dict.copy()
            query_items = """
                SELECT oi.product_id, oi.quantity, oi.price AS price_at_purchase, 
                       p.product_name, p.image_url
                FROM order_items oi JOIN products p ON oi.product_id = p.product_id
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
    except psycopg2.Error as db_err: # ... (error handling)
        print(f"PG My Orders Error: {db_err}\n{traceback.format_exc()}")
        return jsonify({'error': f'Database error: {db_err.diag.message_detail if hasattr(db_err, "diag") else str(db_err)}'}), 500
    except Exception as e:
        print(f"Generic My Orders Error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Could not get orders'}), 500
    finally:
        if cursor: cursor.close()

@app.route('/api/orders/<int:order_id>/cancel', methods=['PUT'])
@token_required
def cancel_order_api(current_user_id, order_id):
    conn = get_db()
    if not conn or not conn.is_connected(): return jsonify({'error': 'Database problem'}), 500
    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT status, customer_id, order_date FROM orders WHERE order_id = %s FOR UPDATE", (order_id,))
        order_details = cursor.fetchone()

        if not order_details: conn.rollback(); return jsonify({'error': 'Order not found'}), 404
        if order_details['customer_id'] != current_user_id: conn.rollback(); return jsonify({'error': 'Unauthorized'}), 403

        current_order_status = order_details.get('status', 'Pending').lower()
        allowed_cancel_statuses = ['pending', 'processing'] 
        if current_order_status not in allowed_cancel_statuses:
            conn.rollback(); return jsonify({'error': f'Order status: {current_order_status.capitalize()}, cannot cancel'}), 400
        
        cursor.execute("SELECT product_id, quantity FROM order_items WHERE order_id = %s", (order_id,))
        order_items = cursor.fetchall()
        if order_items:
            update_inventory_query = "UPDATE products SET inventory = inventory + %s WHERE product_id = %s"
            for item in order_items:
                cursor.execute(update_inventory_query, (float(item['quantity']), item['product_id']))
        
        cursor.execute("UPDATE orders SET status = 'Canceled' WHERE order_id = %s", (order_id,))
        conn.commit()
        return jsonify({'message': f'Order ID {order_id} canceled.'}), 200
    except psycopg2.Error as db_err: # ... (error handling)
        if conn: conn.rollback()
        print(f"PG Cancel Order Error: {db_err}\n{traceback.format_exc()}")
        return jsonify({'error': f'Database error: {db_err.diag.message_detail if hasattr(db_err, "diag") else str(db_err)}'}), 500
    except Exception as e: # ... (error handling)
        if conn: conn.rollback()
        print(f"Generic Cancel Order Error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Could not cancel order'}), 500
    finally:
        if cursor: cursor.close()

@app.route('/api/test_db', methods=['GET'])
def test_db_connection():
    conn = get_db()
    if conn and not conn.closed:
        return jsonify({"message": "Database connection (per-request) successful!"}), 200
    else:
        return jsonify({"error": "Database connection (per-request) failed or closed."}), 500

if __name__ == '__main__':
    port = int(os.getenv('FLASK_RUN_PORT', 5000))
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    print(f"--- Flask Grocery App (PostgreSQL Per-Request Connection Version) ---")
    print(f"Attempting to start on http://0.0.0.0:{port}")
    print(f"Debug mode: {debug_mode}")
    print(f"Frontend expected at: {os.getenv('FRONTEND_URL')}") # Check this output
    print(f"CORS Origins: {app.extensions['cors'].resources}") # Check actual CORS config
    secret_key_status = 'Yes' if app.config['SECRET_KEY'] != 'fallback_secret_key_CHANGE_THIS_IN_ENV_FILE' else 'NO - USING FALLBACK (INSECURE!)'
    print(f"App Secret Key Loaded from .env: {secret_key_status}")
    app.run(debug=debug_mode, port=port, host='0.0.0.0')