# backend/product.py
import decimal
from psycopg2.extras import RealDictCursor 

def get_all_products(connection): # Connection object is passed in
    if connection is None or connection.closed:
        print("No database connection available or connection closed in get_all_products.")
        return []

    cursor = None
    try:
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        # ... (your SQL query for products) ...
        query = """
            SELECT p.product_id, p.product_name, p.price, p.inventory, p.image_url, m.measure_name
            FROM products p
            LEFT JOIN measurement m ON p.measurement = m.measure_id
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        
        products_data = []
        for row in rows:
            price = float(row['price']) if isinstance(row['price'], decimal.Decimal) else (float(row['price']) if row['price'] is not None else 0.0)
            products_data.append({
                'id': row['product_id'],
                'name': row['product_name'],
                'price': price,
                'inventory': row['inventory'] if row['inventory'] is not None else 0,
                'image': row.get('image_url'), 
                'description': row.get('description', f"High quality {row['product_name']}"),
                'unit': row.get('measure_name', 'unit')
            })
        return products_data
    except psycopg2.Error as db_err: # Catch psycopg2 specific errors
        print(f"PostgreSQL Error in get_all_products: {db_err}")
        print(f"Query attempted: {cursor.query if cursor else 'Cursor not initialized'}") # Log the query if possible
        print(f"Traceback: {traceback.format_exc()}")
        return [] # Return empty on error
    except Exception as e:
        print(f"Generic error fetching products in product.py: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return []
    finally:
        if cursor: 
            cursor.close()