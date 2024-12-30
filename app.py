from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_login import UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os
import qrcode
import json
import hashlib
import time
from datetime import datetime, timedelta
import logging
import threading
import schedule
import socket
import bcrypt
from math import sin, cos, sqrt, atan2, radians
from functools import wraps
import re
from config import Config
from extensions import db, login_manager
from models import User, Child, SafeZone, Notification
from io import BytesIO
import requests

app = Flask(__name__)
app.config.from_object(Config)

# Database configuration
if os.environ.get('VERCEL_ENV') == 'production':
    db_path = os.path.join(os.getcwd(), 'app.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

db.init_app(app)
migrate = Migrate(app, db)
login_manager.init_app(app)

# Create tables if needed
with app.app_context():
    try:
        # Ensure the directory exists
        db_dir = os.path.dirname(app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', ''))
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
        
        db.create_all()
        print("Tables created successfully!")
        print(f"Database path: {app.config['SQLALCHEMY_DATABASE_URI']}")
    except Exception as e:
        print(f"Error creating tables: {str(e)}")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

# הגדרת תיקיית QR
QR_FOLDER = os.path.join(app.static_folder, 'qr_codes')
if not os.path.exists(QR_FOLDER):
    os.makedirs(QR_FOLDER)

# הגדרת logging
logging.basicConfig(level=logging.DEBUG)

# הגדרות אבטחה
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds
login_attempts = {}

def check_login_attempts(f):
    """דקורטור לבדיקת ניסיונות התחברות"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        if ip in login_attempts:
            if login_attempts[ip]['attempts'] >= MAX_LOGIN_ATTEMPTS:
                if time.time() - login_attempts[ip]['last_attempt'] < LOCKOUT_TIME:
                    return jsonify({'error': 'חשבונך נחסם זמנית. נסה שוב מאוחר יותר.'}), 429
                login_attempts[ip]['attempts'] = 0
        return f(*args, **kwargs)
    return decorated_function

def start_scheduler():
    """הפעלת תזמון משימות"""
    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(60)

    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def calculate_distance(lat1, lon1, lat2, lon2):
    """חישוב מרחק בין שתי נקודות על פני כדור הארץ"""
    R = 6371.0  # רדיוס כדור הארץ בק"מ

    lat1 = radians(lat1)
    lon1 = radians(lon1)
    lat2 = radians(lat2)
    lon2 = radians(lon2)

    dlon = lon2 - lon1
    dlat = lat2 - lat1

    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    distance = R * c * 1000  # המרה למטרים
    return distance

def check_safe_zones(child):
    """בדיקת מיקום הילד ביחס לאזורים הבטוחים"""
    try:
        safe_zones = SafeZone.query.filter_by(child_id=child.id).all()
        in_safe_zone = False
        
        for zone in safe_zones:
            distance = calculate_distance(
                child.last_latitude, child.last_longitude,
                zone.latitude, zone.longitude
            )
            
            if distance <= zone.radius:
                in_safe_zone = True
                break
        
        if not in_safe_zone:
            notification = Notification(
                child_id=child.id,
                parent_id=child.parent_id,
                message=f"{child.name} נמצא מחוץ לאזור הבטוח",
                timestamp=datetime.utcnow()
            )
            db.session.add(notification)
            db.session.commit()
    except Exception as e:
        app.logger.error(f"Error checking safe zones: {str(e)}")

def check_safe_zones_all():
    """בדיקת מיקום כל הילדים ביחס לאזורים הבטוחים"""
    try:
        children = Child.query.all()
        for child in children:
            if child.last_latitude and child.last_longitude:
                check_safe_zones(child)
    except Exception as e:
        app.logger.error(f"Error checking all safe zones: {str(e)}")

# הגדרת בדיקת אזורים בטוחים כל 5 דקות
schedule.every(5).minutes.do(check_safe_zones_all)

# התחלת thread לתזמון משימות
start_scheduler()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@check_login_attempts
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password, password):
            ip = request.remote_addr
            if ip not in login_attempts:
                login_attempts[ip] = {'attempts': 0, 'last_attempt': time.time()}
            login_attempts[ip]['attempts'] += 1
            login_attempts[ip]['last_attempt'] = time.time()
            
            flash('שם משתמש או סיסמה לא נכונים')
            return redirect(url_for('login'))

        login_user(user, remember=remember)
        return redirect(url_for('dashboard'))
        
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')
        
        # בדיקה שכל השדות מלאים
        if not username or not password or not confirm_password or not email:
            flash('כל השדות הם חובה')
            return redirect(url_for('register'))
        
        # בדיקת תקינות שם משתמש
        if not re.match("^[a-zA-Z0-9_-]{3,20}$", username):
            flash('שם משתמש חייב להכיל בין 3 ל-20 תווים ויכול להכיל רק אותיות, מספרים, מקף ותחתון')
            return redirect(url_for('register'))
        
        # בדיקת תקינות סיסמה
        if len(password) < 8:
            flash('הסיסמה חייבת להכיל לפחות 8 תווים')
            return redirect(url_for('register'))
        
        # בדיקת התאמת סיסמאות
        if password != confirm_password:
            flash('הסיסמאות אינן תואמות')
            return redirect(url_for('register'))
        
        # בדיקת תקינות אימייל
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('כתובת אימייל לא תקינה')
            return redirect(url_for('register'))
        
        # בדיקה אם המשתמש כבר קיים
        user = User.query.filter_by(username=username).first()
        if user:
            flash('שם משתמש כבר קיים')
            return redirect(url_for('register'))
        
        # בדיקה אם האימייל כבר קיים
        user = User.query.filter_by(email=email).first()
        if user:
            flash('כתובת האימייל כבר קיימת במערכת')
            return redirect(url_for('register'))
        
        # יצירת משתמש חדש
        new_user = User(username=username, email=email)
        new_user.password = generate_password_hash(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('נרשמת בהצלחה! אנא התחבר', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('אירעה שגיאה בעת ההרשמה. אנא נסה שוב')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/generate_qr', methods=['POST'])
@login_required
def generate_qr_new():
    try:
        app.logger.debug("Starting QR code generation")
        name = request.form.get('name')
        if not name:
            return jsonify({'success': False, 'error': 'שם הילד חסר'}), 400

        # יצירת מזהה מכשיר חדש
        device_id = hashlib.md5(f"{name}_{time.time()}".encode()).hexdigest()

        # יצירת ילד חדש
        child = Child(
            name=name,
            device_id=device_id,
            parent_id=current_user.id
        )
        db.session.add(child)
        db.session.commit()

        app.logger.debug(f"Created new child with ID {child.id}")

        # יצירת ה-URL המלא לדף המעקב
        track_url = url_for('track_location', child_id=child.id, device_id=device_id, _external=True)
        
        # יצירת ה-QR
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        qr.add_data(track_url)
        qr.make(fit=True)

        # יצירת התמונה
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # וודא שתיקיית QR קיימת
        if not os.path.exists('static/qr_codes'):
            os.makedirs('static/qr_codes')
        
        # שמירת הקובץ
        filename = f"qr_{device_id}.png"
        file_path = os.path.join('static/qr_codes', filename)
        
        app.logger.debug(f"Saving QR code to {file_path}")
        qr_image.save(file_path)

        return jsonify({
            'success': True,
            'qr_code_url': url_for('static', filename=f'qr_codes/{filename}')
        })

    except Exception as e:
        app.logger.error(f"Error generating QR code: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_children')
@login_required
def get_children():
    try:
        children = Child.query.filter_by(parent_id=current_user.id).all()
        return jsonify([{
            'id': child.id,
            'name': child.name,
            'device_id': child.device_id,
            'last_latitude': child.last_latitude,
            'last_longitude': child.last_longitude,
            'last_address': child.last_address,
            'last_update': child.last_update.isoformat() if child.last_update else None
        } for child in children])
    except Exception as e:
        app.logger.error(f"Error getting children: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_locations')
@login_required
def get_locations():
    try:
        children = Child.query.filter_by(parent_id=current_user.id).all()
        locations = []
        for child in children:
            if child.last_latitude and child.last_longitude:
                locations.append({
                    'child_id': child.id,
                    'child_name': child.name,
                    'latitude': child.last_latitude,
                    'longitude': child.last_longitude,
                    'address': child.last_address,
                    'last_update': child.last_update.isoformat() if child.last_update else None
                })
        return jsonify(locations)
    except Exception as e:
        app.logger.error(f"Error getting locations: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_notifications')
@login_required
def get_notifications():
    try:
        notifications = Notification.query.filter_by(parent_id=current_user.id).order_by(Notification.timestamp.desc()).all()
        return jsonify([{
            'id': notification.id,
            'child_name': notification.child.name,
            'message': notification.message,
            'timestamp': notification.timestamp.isoformat()
        } for notification in notifications])
    except Exception as e:
        app.logger.error(f"Error getting notifications: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/delete_notification/<int:notification_id>', methods=['DELETE'])
@login_required
def delete_notification(notification_id):
    try:
        notification = Notification.query.get_or_404(notification_id)
        if notification.parent_id != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        db.session.delete(notification)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error deleting notification: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/delete_child/<int:child_id>', methods=['DELETE'])
@login_required
def delete_child(child_id):
    try:
        child = Child.query.get_or_404(child_id)
        if child.parent_id != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        # מחיקת כל ההתראות של הילד
        Notification.query.filter_by(child_id=child.id).delete()
        
        # מחיקת כל האזורים הבטוחים של הילד
        SafeZone.query.filter_by(child_id=child.id).delete()
        
        # מחיקת הילד
        db.session.delete(child)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error deleting child: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_safe_zones/<int:child_id>')
@login_required
def get_safe_zones(child_id):
    try:
        child = Child.query.get_or_404(child_id)
        if child.parent_id != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
        safe_zones = SafeZone.query.filter_by(child_id=child_id).all()
        return jsonify([{
            'id': zone.id,
            'name': zone.name,
            'address': zone.address,
            'latitude': zone.latitude,
            'longitude': zone.longitude,
            'radius': zone.radius
        } for zone in safe_zones])
    except Exception as e:
        app.logger.error(f"Error getting safe zones: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/add_safe_zone', methods=['POST'])
@login_required
def add_safe_zone():
    try:
        data = request.get_json()
        child_id = data.get('child_id')
        name = data.get('name', 'אזור בטוח חדש')
        address = data.get('address')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        radius = data.get('radius')

        if not all([child_id, latitude, longitude, radius]):
            return jsonify({'success': False, 'error': 'חסרים פרטים'}), 400

        child = Child.query.get_or_404(child_id)
        if child.parent_id != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        safe_zone = SafeZone(
            name=name,
            address=address,
            latitude=latitude,
            longitude=longitude,
            radius=radius,
            child_id=child_id
        )
        
        db.session.add(safe_zone)
        db.session.commit()

        return jsonify({
            'success': True,
            'safe_zone': {
                'id': safe_zone.id,
                'name': safe_zone.name,
                'address': safe_zone.address,
                'latitude': safe_zone.latitude,
                'longitude': safe_zone.longitude,
                'radius': safe_zone.radius
            }
        })
    except Exception as e:
        app.logger.error(f"Error adding safe zone: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/update_location', methods=['POST'])
def update_location():
    try:
        data = request.get_json()
        device_id = data.get('device_id')
        latitude = data.get('latitude')
        longitude = data.get('longitude')

        if not all([device_id, latitude, longitude]):
            return jsonify({'status': 'error', 'message': 'Missing required data'}), 400

        child = Child.query.filter_by(device_id=device_id).first()
        if not child:
            return jsonify({'status': 'error', 'message': 'Child not found'}), 404

        # Get address using Google Geocoding API
        try:
            geocoding_url = f"https://maps.googleapis.com/maps/api/geocode/json?latlng={latitude},{longitude}&key={app.config['GOOGLE_MAPS_API_KEY']}&language=iw"
            response = requests.get(geocoding_url)
            if response.status_code == 200:
                result = response.json()
                if result['results']:
                    address = result['results'][0]['formatted_address']
                else:
                    address = "כתובת לא זמינה"
            else:
                address = "כתובת לא זמינה"
        except Exception as e:
            app.logger.error(f"Error getting address: {str(e)}")
            address = "כתובת לא זמינה"

        # Update child's location and address
        child.last_latitude = latitude
        child.last_longitude = longitude
        child.last_address = address
        child.last_update = datetime.utcnow()
        
        db.session.commit()

        # Check safe zones after location update
        check_safe_zones(child)

        return jsonify({'status': 'success'})

    except Exception as e:
        app.logger.error(f"Error updating location: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('התנתקת בהצלחה', 'success')
    return redirect(url_for('index'))

@app.route('/track/<int:child_id>/<device_id>')
def track_location(child_id, device_id):
    return render_template('track_location.html', child_id=child_id, device_id=device_id)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
