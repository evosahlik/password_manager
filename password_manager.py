from flask import Flask, request, render_template, redirect, url_for, flash, session
from supabase import create_client, Client
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import httpx
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', str(uuid.uuid4()))

# Supabase setup
supabase_url = os.getenv('SUPABASE_URL')
supabase_key = os.getenv('SUPABASE_KEY')
logging.debug(f"Supabase URL: {supabase_url}")

# Create HTTP client with default CA store
http_client = httpx.Client(verify=True)

# Initialize Supabase client
supabase: Client = create_client(supabase_url, supabase_key)
try:
    supabase.postgrest._session = http_client  # For REST API calls
    supabase.auth._http_client = http_client  # For Auth API calls
    logging.debug("Supabase client HTTP clients set successfully")
except AttributeError as e:
    logging.error(f"Error setting HTTP clients: {str(e)}")
    raise

logging.debug("Supabase client initialized successfully")

# Database schema creation
def init_db():
    logging.debug("Checking credentials table")
    try:
        response = supabase.table('credentials').select('*').limit(1).execute()
        logging.debug(f"Table check response: {response}")
    except Exception as e:
        logging.error(f"Error in init_db: {str(e)}")
        raise

init_db()

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            # Authenticate with Supabase
            response = supabase.auth.sign_in_with_password({
                'email': email,
                'password': password
            })
            session['user'] = response.user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            logging.error(f"Login error: {str(e)}")
            flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            # Register with Supabase
            response = supabase.auth.sign_up({
                'email': email,
                'password': password
            })
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(f"Registration error: {str(e)}")
            flash('Registration failed', 'error')
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    try:
        # Fetch credentials for the user
        response = supabase.table('credentials').select('*').eq('user_id', session['user']).execute()
        credentials = response.data
        return render_template('dashboard.html', credentials=credentials)
    except Exception as e:
        logging.error(f"Dashboard error: {str(e)}")
        flash('Error fetching credentials', 'error')
        return redirect(url_for('login'))

@app.route('/add_credential', methods=['POST'])
def add_credential():
    if 'user' not in session:
        return redirect(url_for('login'))
    site_name = request.form['site_name']
    site_url = request.form['site_url']
    username = request.form['username']
    password = request.form['password']
    try:
        supabase.table('credentials').insert({
            'user_id': session['user'],
            'site_name': site_name,
            'site_url': site_url,
            'username': username,
            'password': password
        }).execute()
        flash('Credential added successfully!', 'success')
    except Exception as e:
        logging.error(f"Add credential error: {str(e)}")
        flash('Error adding credential', 'error')
    return redirect(url_for('dashboard'))

@app.route('/delete_credential/<credential_id>')
def delete_credential(credential_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    try:
        supabase.table('credentials').delete().eq('id', credential_id).eq('user_id', session['user']).execute()
        flash('Credential deleted successfully!', 'success')
    except Exception as e:
        logging.error(f"Delete credential error: {str(e)}")
        flash('Error deleting credential', 'error')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    supabase.auth.sign_out()
    session.pop('user', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)