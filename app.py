from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import secrets
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///licenses.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Модели базы данных
class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    hwid = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    activation_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_validation = db.Column(db.DateTime, nullable=True)

class ActivationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), nullable=False)
    hwid = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    user_agent = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected

# Админ пользователи
class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

# Создаем таблицы
with app.app_context():
    db.create_all()
    
    # Создаем админа по умолчанию
    if not AdminUser.query.first():
        admin = AdminUser(
            username='admin',
            password_hash=hashlib.sha256('admin123'.encode()).hexdigest()
        )
        db.session.add(admin)
        db.session.commit()

# API endpoints
@app.route('/license', methods=['POST'])
def license_api():
    data = request.get_json()
    action = data.get('action')
    key = data.get('key')
    hwid = data.get('hwid')
    
    if not key:
        return jsonify({'success': False, 'error': 'No key provided'})
    
    if action == 'activate':
        return activate_license(key, hwid, request)
    elif action == 'validate':
        return validate_license(key, hwid)
    else:
        return jsonify({'success': False, 'error': 'Invalid action'})

def activate_license(key, hwid, request):
    license_obj = License.query.filter_by(key=key).first()
    
    if not license_obj:
        return jsonify({'success': False, 'error': 'Invalid license key'})
    
    if not license_obj.is_active:
        return jsonify({'success': False, 'error': 'License is deactivated'})
    
    # Если у ключа уже есть привязанный HWID
    if license_obj.hwid:
        if license_obj.hwid == hwid:
            # Устройство уже активировано
            return jsonify({
                'success': True, 
                'message': 'License already activated on this device',
                'license_data': {'status': 'active'}
            })
        else:
            # HWID не совпадает - записываем запрос активации
            activation_req = ActivationRequest(
                key=key,
                hwid=hwid,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(activation_req)
            db.session.commit()
            
            return jsonify({
                'success': False, 
                'error': 'License already activated on another device. Activation request sent to admin.'
            })
    
    # Если HWID не привязан - привязываем
    license_obj.hwid = hwid
    license_obj.activation_date = datetime.utcnow()
    license_obj.last_validation = datetime.utcnow()
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'License activated successfully',
        'license_data': {'status': 'active'}
    })

def validate_license(key, hwid):
    license_obj = License.query.filter_by(key=key).first()
    
    if not license_obj:
        return jsonify({'valid': False, 'error': 'Invalid license key'})
    
    if not license_obj.is_active:
        return jsonify({'valid': False, 'error': 'License is deactivated'})
    
    if not license_obj.hwid:
        return jsonify({'valid': False, 'error': 'License not activated'})
    
    if license_obj.hwid != hwid:
        return jsonify({'valid': False, 'error': 'License not valid for this device'})
    
    # Обновляем время последней проверки
    license_obj.last_validation = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'valid': True, 'message': 'License is valid'})

# Админ панель
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        admin = AdminUser.query.filter_by(username=username).first()
        if admin and admin.password_hash == hashlib.sha256(password.encode()).hexdigest():
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        
        return render_template('admin_login.html', error='Invalid credentials')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    licenses = License.query.all()
    activation_requests = ActivationRequest.query.filter_by(status='pending').all()
    stats = {
        'total_licenses': License.query.count(),
        'activated_licenses': License.query.filter(License.hwid.isnot(None)).count(),
        'pending_requests': ActivationRequest.query.filter_by(status='pending').count()
    }
    
    return render_template('admin_dashboard.html', 
                         licenses=licenses, 
                         activation_requests=activation_requests,
                         stats=stats)

@app.route('/admin/add_license', methods=['POST'])
def add_license():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'error': 'Not authorized'})
    
    key = request.form.get('key')
    if not key:
        return jsonify({'success': False, 'error': 'No key provided'})
    
    # Проверяем формат ключа
    if not (len(key) == 24 and key.startswith('GUFY-')):
        return jsonify({'success': False, 'error': 'Invalid key format'})
    
    # Проверяем существование
    if License.query.filter_by(key=key).first():
        return jsonify({'success': False, 'error': 'Key already exists'})
    
    license_obj = License(key=key)
    db.session.add(license_obj)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'License added successfully'})

@app.route('/admin/bulk_add_licenses', methods=['POST'])
def bulk_add_licenses():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'error': 'Not authorized'})
    
    keys_text = request.form.get('keys')
    if not keys_text:
        return jsonify({'success': False, 'error': 'No keys provided'})
    
    keys = [k.strip() for k in keys_text.split('\n') if k.strip()]
    added = 0
    errors = []
    
    for key in keys:
        if len(key) == 24 and key.startswith('GUFY-'):
            if not License.query.filter_by(key=key).first():
                license_obj = License(key=key)
                db.session.add(license_obj)
                added += 1
            else:
                errors.append(f"Key {key} already exists")
        else:
            errors.append(f"Invalid key format: {key}")
    
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'Added {added} licenses',
        'errors': errors
    })

@app.route('/admin/process_request/<int:request_id>', methods=['POST'])
def process_request(request_id):
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'error': 'Not authorized'})
    
    action = request.form.get('action')  # approve or reject
    activation_req = ActivationRequest.query.get_or_404(request_id)
    
    if action == 'approve':
        # Находим лицензию и меняем HWID
        license_obj = License.query.filter_by(key=activation_req.key).first()
        if license_obj:
            license_obj.hwid = activation_req.hwid
            license_obj.activation_date = datetime.utcnow()
            activation_req.status = 'approved'
            db.session.commit()
            return jsonify({'success': True, 'message': 'Request approved'})
        else:
            return jsonify({'success': False, 'error': 'License not found'})
    
    elif action == 'reject':
        activation_req.status = 'rejected'
        db.session.commit()
        return jsonify({'success': True, 'message': 'Request rejected'})
    
    return jsonify({'success': False, 'error': 'Invalid action'})

@app.route('/admin/toggle_license/<int:license_id>', methods=['POST'])
def toggle_license(license_id):
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'error': 'Not authorized'})
    
    license_obj = License.query.get_or_404(license_id)
    license_obj.is_active = not license_obj.is_active
    db.session.commit()
    
    status = "activated" if license_obj.is_active else "deactivated"
    return jsonify({'success': True, 'message': f'License {status}'})

@app.route('/admin/delete_license/<int:license_id>', methods=['POST'])
def delete_license(license_id):
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'error': 'Not authorized'})
    
    license_obj = License.query.get_or_404(license_id)
    db.session.delete(license_obj)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'License deleted'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)