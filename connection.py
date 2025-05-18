# backend/connection.py
import psycopg2
from psycopg2.extras import RealDictCursor 
import os
from dotenv import load_dotenv
from flask import g 
import traceback # For better error logging

load_dotenv()

def get_db_connection_for_request():
    """
    Connects to the PostgreSQL database.
    Prioritizes DATABASE_URL (common for Render managed DBs).
    Falls back to individual PG* variables if DATABASE_URL is not set.
    Connection is stored in Flask's `g` object, unique per request.
    """
    if not hasattr(g, 'db_conn') or g.db_conn is None or g.db_conn.closed:
        print("--- DB (PostgreSQL): Opening new connection for this request ---")
        database_url = os.getenv('DATABASE_URL')
        
        try:
            if database_url:
                print(f"--- DB (PostgreSQL): Attempting connection using DATABASE_URL ---")
                # For Render's internal PostgreSQL, often includes ?sslmode=require
                # Check if your DATABASE_URL from Render already includes SSL params
                # If not, and SSL is required (usually is), you might need to append:
                # if 'sslmode' not in database_url:
                #     database_url += "?sslmode=require" # Example for requiring SSL
                g.db_conn = psycopg2.connect(database_url)
            else:
                # Fallback to individual components if DATABASE_URL is not set
                print(f"--- DB (PostgreSQL): DATABASE_URL not found. Attempting connection using individual PG* params ---")
                pg_host = os.getenv('PGHOST')
                pg_user = os.getenv('PGUSER')
                pg_password = os.getenv('PGPASSWORD')
                pg_database = os.getenv('PGDATABASE')
                pg_port = os.getenv('PGPORT', '5432') # Default PostgreSQL port

                if not all([pg_host, pg_user, pg_password, pg_database]):
                    print("!!! DB (PostgreSQL): Missing one or more PG* connection parameters (PGHOST, PGUSER, PGPASSWORD, PGDATABASE) !!!")
                    g.db_conn = None
                    return None

                conn_str = (
                    f"dbname='{pg_database}' "
                    f"user='{pg_user}' "
                    f"password='{pg_password}' "
                    f"host='{pg_host}' "
                    f"port='{pg_port}'"
                )
                g.db_conn = psycopg2.connect(conn_str)
            
            # Optional: Set client encoding if needed, though usually UTF8 is default
            # g.db_conn.set_client_encoding('UTF8')
            print("--- DB (PostgreSQL): Connection established successfully for this request ---")

        except psycopg2.OperationalError as op_err: # More specific error for connection issues
            print(f"!!! DB (PostgreSQL): OperationalError connecting: {op_err} !!!")
            print(f"Traceback: {traceback.format_exc()}")
            if hasattr(g, 'db_conn') and g.db_conn is not None:
                 if not g.db_conn.closed: g.db_conn.close()
            g.db_conn = None
            return None
        except psycopg2.Error as db_err: # Catch other psycopg2 specific errors
            print(f"!!! DB (PostgreSQL): Error connecting: {db_err} !!!")
            print(f"Traceback: {traceback.format_exc()}")
            if hasattr(g, 'db_conn') and g.db_conn is not None:
                 if not g.db_conn.closed: g.db_conn.close()
            g.db_conn = None
            return None
        except Exception as e: # Catch any other potential errors during connect
            print(f"!!! DB (PostgreSQL): Unexpected generic error in get_db_connection_for_request: {e} !!!")
            print(f"Traceback: {traceback.format_exc()}")
            if hasattr(g, 'db_conn') and g.db_conn is not None:
                 if not g.db_conn.closed: g.db_conn.close()
            g.db_conn = None
            return None
    # else:
    #     print("--- DB (PostgreSQL): Using existing valid connection for this request ---")
    return g.db_conn

def close_db_connection_for_request(e=None):
    db_conn = g.pop('db_conn', None)
    if db_conn is not None and not db_conn.closed:
        try:
            # If there was an unhandled exception during the request and a transaction is active,
            # it's good practice to roll it back before closing.
            # However, if the connection is already in an error state, rollback might also fail.
            if e is not None and db_conn.status == psycopg2.extensions.STATUS_IN_TRANSACTION: # Check if in transaction
                print("--- DB (PostgreSQL): Rolling back active transaction due to exception during request teardown ---")
                db_conn.rollback()
        except psycopg2.Error as db_err:
            print(f"!!! DB (PostgreSQL): Error during rollback on teardown: {db_err} !!!")
        finally:
            print("--- DB (PostgreSQL): Closing connection for this request ---")
            db_conn.close()
    # elif db_conn is not None and db_conn.closed:
        # print("--- DB (PostgreSQL): Connection was already closed at teardown ---")