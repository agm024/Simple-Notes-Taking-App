from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3

app = Flask(__name__)
app.secret_key = '85d6658ed2f7019021f1c5b2f9e2770630b73059441718b96cde3849b14aa3ff'  # Replace with your actual secret key

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

DATABASE = 'app.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Allows dictionary-like access to rows
    return conn

def load_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, password FROM users')
    users = {row['id']: row['password'] for row in cursor.fetchall()}
    conn.close()
    return users

def save_user(username, password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (id, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()

@login_manager.user_loader
def load_user(user_id):
    users = load_users()
    if user_id in users:
        return User(user_id, users[user_id])
    return None

def load_notes():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, title, content, password FROM notes')
    notes = cursor.fetchall()
    conn.close()
    return [{'id': n['id'], 'title': n['title'], 'content': n['content'], 'password': n['password']} for n in notes]

def save_note(title, content, password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO notes (title, content, password) VALUES (?, ?, ?)', (title, content, password))
    conn.commit()
    conn.close()

def update_note(note_id, title, content, password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE notes SET title = ?, content = ?, password = ? WHERE id = ?', (title, content, password, note_id))
    conn.commit()
    conn.close()

def delete_note_from_db(note_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM notes WHERE id = ?', (note_id,))
    conn.commit()
    conn.close()

class User(UserMixin):
    def __init__(self, username, password=None):
        self.id = username
        self.password = password

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            users = load_users()
            if username not in users:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                save_user(username, hashed_password)
                flash('Registration successful! You can now log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Username already exists!', 'danger')
        else:
            flash('Please fill out both fields.', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        users = load_users()
        user = users.get(username)
        if user and bcrypt.check_password_hash(user, password):
            user_obj = User(username, user)
            login_user(user_obj)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    notes = load_notes()
    if request.method == 'POST':
        note_title = request.form.get('title')
        note_content = request.form.get('note')
        note_password = request.form.get('password')
        
        if note_title and note_content:
            if note_password:
                hashed_password = bcrypt.generate_password_hash(note_password).decode('utf-8')
            else:
                hashed_password = None
            save_note(note_title, note_content, hashed_password)
            flash('Note added successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Note title and content are required.', 'danger')
    
    return render_template('index.html', notes=notes)

@app.route('/notes')
@login_required
def notes():
    notes = load_notes()
    return render_template('notes.html', notes=notes)

@app.route('/view/<int:note_id>', methods=['GET', 'POST'])
@login_required
def view_note(note_id):
    notes = load_notes()
    
    if 0 <= note_id < len(notes):
        note = notes[note_id]
        if note['password'] is None:
            return render_template('view_note.html', note=note, note_id=note_id)
        
        if request.method == 'POST':
            note_password = request.form.get('password')
            if bcrypt.check_password_hash(note['password'], note_password):
                return render_template('view_note.html', note=note, note_id=note_id)
            else:
                flash('Incorrect password.', 'danger')
        
        return render_template('enter_password.html', note_id=note_id)
    else:
        flash('Note not found.', 'danger')
        return redirect(url_for('index'))

@app.route('/edit/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    notes = load_notes()
    
    if 0 <= note_id < len(notes):
        if request.method == 'POST':
            new_title = request.form.get('title')
            new_content = request.form.get('note')
            new_password = request.form.get('password')
            
            if new_title and new_content:
                if new_password:
                    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                else:
                    hashed_password = None
                
                update_note(note_id, new_title, new_content, hashed_password)
                flash('Note updated successfully.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Note title and content are required.', 'danger')
        
        return render_template('edit_note.html', title=notes[note_id]['title'], note=notes[note_id]['content'], password=notes[note_id]['password'])
    else:
        flash('Note not found.', 'danger')
        return redirect(url_for('index'))

@app.route('/delete/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    delete_note_from_db(note_id)
    flash('Note deleted successfully.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
