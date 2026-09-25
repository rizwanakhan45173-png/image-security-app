import os
import hashlib
import traceback
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
import pymysql.cursors
from cryptography.fernet import Fernet
import base64
import secrets
from datetime import datetime, timedelta
from flask_mail import Mail, Message

app = Flask(__name__)

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'rizwanakhan45173@gmail.com'      # Replace with your email
app.config['MAIL_PASSWORD'] = 'ykuh eamo yztl rove'          # Replace with App Password
mail = Mail(app)
app.secret_key = 'super_secret_image_vault_key'

# MySQL Configuration (reads from Render environment variables)
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_USER = os.environ.get('DB_USERNAME', 'root')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'root')
DB_NAME = os.environ.get('DB_DATABASE', 'test')

# Directory to save encrypted and decrypted files
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_db_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

def generate_fernet_key(passphrase: str) -> bytes:
    # Derives a deterministic 32-byte key from the user passphrase
    key = hashlib.sha256(passphrase.encode()).digest()
    return base64.urlsafe_b64encode(key)

def log_action(user_id, action, filename, status):
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO audit_logs (user_id, action, filename, status) VALUES (%s, %s, %s, %s)",
                (user_id, action, filename, status)
            )
        conn.close()
    except Exception as e:
        print(f"Audit log error: {e}")

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()

        try:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, password)
                )
            conn.close()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except pymysql.MySQLError as e:
            if e.args[0] == 1062:
                flash('Email already registered. Please log in or use another email.', 'warning')
            else:
                flash(f'Database error: {e}', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()

        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE email = %s AND password = %s",
                (email, password)
            )
            user = cursor.fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    # Fetch history records for current user
    cursor.execute("SELECT * FROM audit_logs WHERE user_id = %s ORDER BY timestamp DESC", (session['user_id'],))
    history_logs = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('dashboard.html', username=session.get('username'), history=history_logs)

@app.route('/encrypt_image', methods=['POST'])
def encrypt_image():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = request.files.get('image')
    passphrase = request.form.get('passphrase')

    if not file or not passphrase:
        flash('Please select an image and provide a secret passphrase.', 'warning')
        return redirect(url_for('dashboard'))

    filename = file.filename
    encrypted_filename = f"enc_{session['user_id']}_{os.urandom(4).hex()}_{filename}"
    file_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)

    try:
        raw_data = file.read()
        fernet = Fernet(generate_fernet_key(passphrase))
        encrypted_data = fernet.encrypt(raw_data)

        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        passphrase_hash = hashlib.sha256(passphrase.encode()).hexdigest()

        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO encrypted_images (user_id, original_filename, encrypted_filename, passphrase_hash) VALUES (%s, %s, %s, %s)",
                (session['user_id'], filename, encrypted_filename, passphrase_hash)
            )
        conn.close()

        log_action(session['user_id'], 'ENCRYPT', encrypted_filename, 'SUCCESS')
        flash('Image encrypted and vault updated successfully!', 'success')
    except Exception as e:
        log_action(session['user_id'], 'ENCRYPT', filename, 'FAILED')
        flash(f'Encryption failed: {e}', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/decrypt_image', methods=['POST'])
def decrypt_image():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = request.files.get('image')
    passphrase = request.form.get('passphrase')

    if not file or not passphrase:
        flash('Please select an encrypted image file and enter the passphrase.', 'warning')
        return redirect(url_for('dashboard'))

    filename = file.filename
    decrypted_filename = f"dec_{session['user_id']}_{os.urandom(4).hex()}_{filename.replace('enc_', '')}"
    decrypted_path = os.path.join(UPLOAD_FOLDER, decrypted_filename)

    try:
        encrypted_data = file.read()
        fernet = Fernet(generate_fernet_key(passphrase))
        decrypted_data = fernet.decrypt(encrypted_data)

        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)

        log_action(session['user_id'], 'DECRYPT', decrypted_filename, 'SUCCESS')
        flash('Image decrypted and saved to vault successfully!', 'success')

    except Exception:
        log_action(session['user_id'], 'DECRYPT', filename, 'FAILED')
        flash('Decryption failed! Invalid passphrase or corrupted file.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/audit_history')
def audit_history():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM audit_logs WHERE user_id = %s ORDER BY timestamp DESC",
            (session['user_id'],)
        )
        logs = cursor.fetchall()
    conn.close()

    return render_template('audit_history.html', logs=logs)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        try:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()

                if user:
                    token = secrets.token_urlsafe(32)
                    expires_at = datetime.now() + timedelta(hours=1)
                    
                    cursor.execute(
                        "INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)",
                        (user['id'], token, expires_at)
                    )

                    reset_url = url_for('reset_password', token=token, _external=True)
                    
                    # Always print the reset link to the server logs so you can copy it
                    print(f"\n==============================================")
                    print(f"🔑 PASSWORD RESET LINK FOR: {email}")
                    print(f"{reset_url}")
                    print(f"==============================================\n")
                    
                    # Safely attempt to send mail, wrapping everything so network blocks won't crash the server
                    try:
                        msg = Message("Password Reset Request", sender=app.config['MAIL_USERNAME'], recipients=[email])
                        msg.body = f"Click the link to reset your password: {reset_url}\n\nLink expires in 1 hour."
                        mail.send(msg)
                    except Exception as mail_err:
                        print(f"SMTP connection blocked/failed (Normal on Render free tier): {mail_err}")

            conn.close()
            flash('If that email exists in our system, a reset link has been processed.', 'info')
        except Exception as e:
            print("--- FORGOT PASSWORD ERROR ---")
            traceback.print_exc()
            print("-----------------------------")
            flash(f'ERROR FOUND: {str(e)}', 'danger')

        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT user_id, expires_at FROM reset_tokens WHERE token = %s", (token,))
        record = cursor.fetchone()

        if not record or record['expires_at'] < datetime.now():
            conn.close()
            flash('Invalid or expired reset link.', 'danger')
            return redirect(url_for('forgot_password'))

        if request.method == 'POST':
            new_password = request.form.get('password')
            hashed_pw = hashlib.sha256(new_password.encode()).hexdigest()

            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_pw, record['user_id']))
            cursor.execute("DELETE FROM reset_tokens WHERE token = %s", (token,))
            conn.commit()
            conn.close()

            flash('Your password has been updated! Please log in.', 'success')
            return redirect(url_for('login'))

    conn.close()
    return render_template('reset_password.html', token=token)

@app.route('/delete_audit_log/<int:log_id>', methods=['POST'])
def delete_audit_log(log_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM audit_logs WHERE id = %s AND user_id = %s", (log_id, session['user_id']))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Audit log entry deleted successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/clear_audit_logs', methods=['POST'])
def clear_audit_logs():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM audit_logs WHERE user_id = %s", (session['user_id'],))
    conn.commit()
    cursor.close()
    conn.close()

    flash("All audit logs cleared!", "success")
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(file_path):
        flash("The requested file is no longer available on the server storage.", "danger")
        return redirect(url_for('dashboard'))
        
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
      
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
