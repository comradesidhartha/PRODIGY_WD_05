# PRODIGY_WD_05
from flask import Flask, request, redirect, url_for, session, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this in production!

# In-memory mock database
users_db = {}

# HTML templates
form_template = '''
    <h2>{{ title }}</h2>
    <form method="post">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        {% if show_role %}
        Role: <input name="role" value="user"><br>
        {% endif %}
        <input type="submit" value="{{ title }}">
    </form>
    <a href="/">Home</a>
'''

# Home route
@app.route('/')
def home():
    if 'username' in session:
        return f"Logged in as {session['username']} ({session['role']})<br>" \
               f"<a href='/dashboard'>Dashboard</a><br>" \
               f"<a href='/admin'>Admin Panel</a><br>" \
               f"<a href='/logout'>Logout</a>"
    return "Welcome! <a href='/register'>Register</a> | <a href='/login'>Login</a>"

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')

        if username in users_db:
            return "User already exists. <a href='/register'>Try again</a>"

        users_db[username] = {
            'password': generate_password_hash(password),
            'role': role
        }
        return redirect(url_for('login'))

    return render_template_string(form_template, title="Register", show_role=True)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users_db.get(username)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        return "Invalid credentials. <a href='/login'>Try again</a>"

    return render_template_string(form_template, title="Login", show_role=False)

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Dashboard route (requires login)
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return f"Welcome to your dashboard, {session['username']}!<br><a href='/'>Home</a>"

# Admin-only route
@app.route('/admin')
def admin():
    if session.get('role') != 'admin':
        return "Access denied. Admins only. <a href='/'>Home</a>"
    return "Welcome to the admin panel. <a href='/'>Home</a>"

if __name__ == '__main__':
    app.run(debug=True)
