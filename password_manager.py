from flask import Flask, request, render_template, redirect, url_for, flash, session
from supabase import create_client, Client
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', str(uuid.uuid4()))
app.config['SESSION_COOKIE_SECURE'] = True # Only send over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

# Supabase setup
supabase_url = os.getenv('SUPABASE_URL')
supabase_key = os.getenv('SUPABASE_KEY')
supabase: Client = create_client(supabase_url, supabase_key)

# Database schema creation
def init_db():
    # Create credentials table if not exists
    supabase.table('credentials').select('*').limit(1).execute()  # Check if table exists
    # If table doesn't exist, Supabase will handle schema via migrations or manual creation
    # Suggested schema:
    # credentials: id (uuid), user_id (uuid), site_name (text), site_url (text), username (text), password (text)

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

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
            
            if response.user:
                session['user'] = response.user.id
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
        except Exception as e:
            flash('Invalid credentials', 'error')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            # Register user with Supabase
            response = supabase.auth.sign_up({
                'email': email,
                'password': password
            })
            
            if response.user:
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
        except Exception as e:
            flash('Registration failed. Email might be taken.', 'error')
            
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Fetch credentials for the user
    try:
        credentials = supabase.table('credentials').select('*').eq('user_id', session['user']).execute()
        return render_template('dashboard.html', credentials=credentials.data)
    except Exception as e:
        flash('Error fetching credentials', 'error')
        return render_template('dashboard.html', credentials=[])

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
        flash('Error deleting credential', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    supabase.auth.sign_out()
    session.pop('user', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)