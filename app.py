import random
# Test update - checking GitHub sync
import os
import logging
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
import json
import threading
import time
import schedule
from config import Config
import socket
import hashlib
from math import sin, cos, sqrt, atan2, radians
from functools import wraps
import re
import subprocess
import bcrypt

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# הגדרת תיקיית ה-QR
QR_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'qr_codes')
if not os.path.exists(QR_FOLDER):
    os.makedirs(QR_FOLDER)

# הגדרת logging מפורט יותר
if not os.path.exists('logs'):
    os.makedirs('logs')

file_handler = logging.FileHandler('logs/app.log')
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Tracker startup')

# Setup logging
# file_handler = logging.FileHandler('app.log')
# file_handler.setLevel(logging.WARNING)
# app.logger.addHandler(file_handler)

# הגדרת משתנים גלובליים
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds
login_attempts = {}

def check_login_attempts(f):
    """דקורטור לבדיקת ניסיונות התחברות"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        if ip in login_attempts:
            if login_attempts[ip]['attempts'] >= MAX_ATTEMPTS:
                if datetime.now() < login_attempts[ip]['lockout_until']:
                    remaining_time = (login_attempts[ip]['lockout_until'] - datetime.now()).seconds
                    flash(f'החשבון נעול. נסה שוב בעוד {remaining_time} שניות', 'error')
                    return redirect(url_for('login'))
                else:
                    login_attempts.pop(ip)
        return f(*args, **kwargs)
    return decorated_function

def clean_qr_files():
    """מנקה את כל קבצי ה-QR מהתיקייה"""
    try:
        if not os.path.exists(QR_FOLDER):
            os.makedirs(QR_FOLDER)
            return

        for filename in os.listdir(QR_FOLDER):
            if filename.endswith('.png'):
                file_path = os.path.join(QR_FOLDER, filename)
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e:
                    app.logger.error(f"Error deleting QR file {file_path}: {str(e)}")
        
        app.logger.info(f"QR files cleanup completed at {datetime.now()}")
    except Exception as e:
        app.logger.error(f"Error during QR cleanup: {str(e)}")

def run_schedule():
    """מריץ את תזמון המשימות"""
    while True:
        try:
            schedule.run_pending()
            time.sleep(60)
        except Exception as e:
            app.logger.error(f"Error in scheduler: {str(e)}")
            time.sleep(60)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    children = db.relationship('Child', backref='user', lazy=True)

class Child(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    device_id = db.Column(db.String(32), unique=True, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    last_latitude = db.Column(db.Float, nullable=True)
    last_longitude = db.Column(db.Float, nullable=True)
    last_update = db.Column(db.DateTime, nullable=True)
    safe_zones = db.relationship('SafeZone', backref='child_ref', lazy=True)
    locations = db.relationship('Location', backref='child', lazy=True)

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    child_id = db.Column(db.Integer, db.ForeignKey('child.id'))

class SafeZone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    radius = db.Column(db.Float, nullable=False)  # במטרים
    child_id = db.Column(db.Integer, db.ForeignKey('child.id'), nullable=False)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey('child.id'), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('הסיסמאות אינן תואמות', 'error')
            return redirect(url_for('register'))

        # בדיקת חוזק סיסמה
        if len(password) < 8:
            flash('הסיסמה חייבת להכיל לפחות 8 תווים', 'error')
            return redirect(url_for('register'))
        
        if not re.search(r"[A-Z]", password):
            flash('הסיסמה חייבת להכיל לפחות אות גדולה אחת באנגלית', 'error')
            return redirect(url_for('register'))
        
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            flash('הסיסמה חייבת להכיל לפחות תו מיוחד אחד', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('שם משתמש כבר קיים', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('נרשמת בהצלחה!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@check_login_attempts
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            captcha_response = request.form.get('captcha_response')

            if not username or not password:
                flash('נא למלא את כל השדות', 'error')
                return redirect(url_for('login'))

            ip = request.remote_addr
            
            # בדיקת CAPTCHA רק אם יש ניסיונות כושלים
            if ip in login_attempts and login_attempts[ip]['attempts'] > 0:
                expected_captcha = session.get('captcha_answer')
                if not captcha_response or int(captcha_response) != expected_captcha:
                    if ip not in login_attempts:
                        login_attempts[ip] = {'attempts': 1, 'lockout_until': None}
                    else:
                        login_attempts[ip]['attempts'] += 1

                    if login_attempts[ip]['attempts'] >= MAX_ATTEMPTS:
                        login_attempts[ip]['lockout_until'] = datetime.now() + timedelta(seconds=LOCKOUT_TIME)
                        flash('יותר מדי ניסיונות כושלים. החשבון ננעל ל-5 דקות', 'error')
                        return redirect(url_for('login'))

                    flash('קוד האימות שגוי', 'error')
                    return redirect(url_for('login'))

            user = User.query.filter_by(username=username).first()
            
            if user and check_password_hash(user.password, password):
                login_user(user)
                if ip in login_attempts:
                    del login_attempts[ip]
                flash('התחברת בהצלחה!', 'success')
                return redirect(url_for('dashboard'))

            # ניסיון התחברות כושל
            if ip not in login_attempts:
                login_attempts[ip] = {'attempts': 1, 'lockout_until': None}
            else:
                login_attempts[ip]['attempts'] += 1

            if login_attempts[ip]['attempts'] >= MAX_ATTEMPTS:
                login_attempts[ip]['lockout_until'] = datetime.now() + timedelta(seconds=LOCKOUT_TIME)
                flash('יותר מדי ניסיונות כושלים. החשבון ננעל ל-5 דקות', 'error')
            else:
                flash('שם משתמש או סיסמה שגויים', 'error')
            
            return redirect(url_for('login'))

        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('אירעה שגיאה בתהליך ההתחברות. נסה שוב', 'error')
            return redirect(url_for('login'))

    # יצירת CAPTCHA רק אם יש ניסיונות כושלים
    ip = request.remote_addr
    captcha_text = None
    if ip in login_attempts and login_attempts[ip]['attempts'] > 0:
        num1 = random.randint(1, 10)
        num2 = random.randint(1, 10)
        session['captcha_answer'] = num1 + num2
        captcha_text = f"{num1} + {num2}"

    return render_template('login.html', captcha_text=captcha_text)

@app.route('/dashboard')
@login_required
def dashboard():
    user_children = Child.query.filter_by(parent_id=current_user.id).all()
    return render_template('dashboard.html', children=user_children)

@app.route('/generate_qr', methods=['POST'])
@login_required
def generate_qr():
    try:
        child_id = request.form.get('child_id')
        if not child_id:
            return jsonify({'error': 'No child ID provided'}), 400

        # וודא שהתיקייה קיימת
        if not os.path.exists(QR_FOLDER):
            os.makedirs(QR_FOLDER)

        # יצירת ה-QR
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        # הוספת המידע ל-QR
        qr_data = {
            'child_id': child_id,
            'timestamp': str(datetime.now())
        }
        qr.add_data(str(qr_data))
        qr.make(fit=True)

        # יצירת התמונה
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # שמירת הקובץ עם שם ייחודי
        filename = f"qr_{child_id}_{int(time.time())}.png"
        file_path = os.path.join(QR_FOLDER, filename)
        qr_image.save(file_path)

        return jsonify({
            'success': True,
            'qr_code_url': url_for('static', filename=f'qr_codes/{filename}')
        })

    except Exception as e:
        app.logger.error(f"Error generating QR code: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/update_location', methods=['POST'])
def update_location():
    data = request.get_json()
    device_id = data.get('device_id')
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    
    if not all([device_id, latitude, longitude]):
        return jsonify({'status': 'error', 'message': 'חסרים פרטים'}), 400
    
    try:
        child = Child.query.filter_by(device_id=device_id).first()
        if child:
            # בדיקה אם המיקום החדש נמצא באזור בטוח
            safe_zones = SafeZone.query.filter_by(child_id=child.id).all()
            for zone in safe_zones:
                if is_within_safe_zone(float(latitude), float(longitude), zone):
                    # בדיקה אם כבר יש התראה לא נקראה עבור אותו אזור בטוח
                    existing_notification = Notification.query\
                        .filter_by(child_id=child.id, is_read=False)\
                        .filter(Notification.message.like(f"%{zone.name}%"))\
                        .first()
                    
                    if not existing_notification:
                        # יצירת התראה חדשה רק אם אין התראה קיימת לא נקראה
                        notification = Notification(
                            child_id=child.id,
                            message=f"{child.name} הגיע/ה לאזור בטוח: {zone.name}",
                            timestamp=datetime.now()
                        )
                        db.session.add(notification)
            
            # עדכון מיקום הילד
            child.last_latitude = float(latitude)
            child.last_longitude = float(longitude)
            child.last_update = datetime.now()
            
            # שמירת המיקום בהיסטוריה
            location = Location(
                latitude=float(latitude),
                longitude=float(longitude),
                child_id=child.id
            )
            db.session.add(location)
            db.session.commit()
            
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': 'מכשיר לא נמצא'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/add_safe_zone', methods=['POST'])
@login_required
def add_safe_zone():
    try:
        data = request.get_json()
        child = Child.query.get(data['child_id'])
        
        if not child or child.parent_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'לא נמצא ילד או אין הרשאה'}), 404
        
        safe_zone = SafeZone(
            name=data['name'],
            address=data['address'],
            latitude=data['latitude'],
            longitude=data['longitude'],
            radius=data['radius'],
            child_id=child.id
        )
        
        db.session.add(safe_zone)
        db.session.commit()
        
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get_location/<child_id>')
def get_location(child_id):
    try:
        child = Child.query.get(child_id)
        if child and child.last_latitude and child.last_longitude:
            return jsonify({
                'status': 'success',
                'latitude': child.last_latitude,
                'longitude': child.last_longitude,
                'timestamp': child.last_update.isoformat() if child.last_update else None
            })
        return jsonify({
            'status': 'not_found',
            'message': 'אין מיקום זמין'
        }), 404
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/device/<device_id>')
def device_page(device_id):
    child = Child.query.filter_by(device_id=device_id).first()
    if child:
        return render_template('device.html', child=child)
    return "מכשיר לא נמצא", 404

@app.route('/get_children')
@login_required
def get_children():
    try:
        children = []
        for child in current_user.children:
            children.append({
                'id': child.id,
                'name': child.name,
                'device_id': child.device_id
            })
        return jsonify(children)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/delete_child/<child_id>', methods=['POST'])
@login_required
def delete_child(child_id):
    try:
        child = Child.query.get(child_id)
        if child and child.parent_id == current_user.id:
            # מחיקת קובץ ה-QR אם קיים
            qr_file = os.path.join(app.static_folder, 'qr', f'qr_{child.device_id}.png')
            if os.path.exists(qr_file):
                os.remove(qr_file)
            
            # מחיקת האזורים הבטוחים של הילד
            SafeZone.query.filter_by(child_id=child.id).delete()
            
            # מחיקת הילד
            db.session.delete(child)
            db.session.commit()
            
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': 'לא נמצא ילד או אין הרשאה'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get_safe_zones/<child_id>')
@login_required
def get_safe_zones(child_id):
    try:
        child = Child.query.get(child_id)
        if child and child.parent_id == current_user.id:
            safe_zones = []
            for zone in child.safe_zones:
                safe_zones.append({
                    'id': zone.id,
                    'name': zone.name,
                    'address': zone.address,
                    'latitude': zone.latitude,
                    'longitude': zone.longitude,
                    'radius': zone.radius
                })
            return jsonify({'status': 'success', 'safe_zones': safe_zones})
        return jsonify({'status': 'error', 'message': 'לא נמצא ילד או אין הרשאה'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get_notifications')
@login_required
def get_notifications():
    try:
        # מקבל את כל הילדים של ההורה הנוכחי
        children_ids = [child.id for child in current_user.children]
        
        # מקבל את ההתראות הלא נקראות של הילדים
        notifications = Notification.query\
            .filter(Notification.child_id.in_(children_ids))\
            .filter_by(is_read=False)\
            .order_by(Notification.timestamp.desc())\
            .all()
        
        return jsonify([{
            'id': n.id,
            'message': n.message,
            'timestamp': n.timestamp.isoformat()
        } for n in notifications])
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    try:
        notification = Notification.query.get(notification_id)
        if notification:
            notification.is_read = True
            db.session.commit()
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': 'התראה לא נמצאה'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/mark_all_notifications_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    try:
        # מציאת כל ההתראות הלא נקראות של המשתמש הנוכחי
        user_children = Child.query.filter_by(parent_id=current_user.id).all()
        child_ids = [child.id for child in user_children]
        
        unread_notifications = Notification.query\
            .filter(Notification.child_id.in_(child_ids))\
            .filter_by(is_read=False)\
            .all()
        
        # סימון כל ההתראות כנקראות
        for notification in unread_notifications:
            notification.is_read = True
        
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get_locations')
@login_required
def get_locations():
    try:
        # קבלת כל הילדים של המשתמש הנוכחי
        children = Child.query.filter_by(parent_id=current_user.id).all()
        locations = []
        
        for child in children:
            if child.last_latitude and child.last_longitude:
                locations.append({
                    'child_id': child.id,
                    'child_name': child.name,
                    'latitude': child.last_latitude,
                    'longitude': child.last_longitude,
                    'last_update': child.last_update.isoformat() if child.last_update else None
                })
        
        return jsonify(locations)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.context_processor
def inject_config():
    return dict(config=app.config)

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {error}')
    db.session.rollback()
    return render_template('error.html', error=error), 500

@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f'Page not found: {error}')
    return render_template('error.html', error=error), 404

def is_within_safe_zone(latitude, longitude, safe_zone):
    """Check if a location is within a safe zone using the Haversine formula"""
    R = 6371000  # Earth's radius in meters
    
    lat1, lon1 = radians(latitude), radians(longitude)
    lat2, lon2 = radians(safe_zone.latitude), radians(safe_zone.longitude)
    
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    
    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    distance = R * c
    
    return distance <= safe_zone.radius

if __name__ == '__main__':
    # הגדרת המשימה לרוץ בחצות
    schedule.every().day.at("00:00").do(clean_qr_files)
    
    # התחלת thread נפרד לתזמון
    scheduler_thread = threading.Thread(target=run_schedule, daemon=True)
    scheduler_thread.start()
    
    # יצירת טבלאות בבסיס הנתונים
    with app.app_context():
        db.create_all()
        app.logger.info('Database tables created')

    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 3000)))
