import os
import uuid
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from geopy.geocoders import Nominatim
import jwt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-only-for-local')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Enable CORS
CORS(app)

# In-memory storage (replace with database in production)
users = [
    {
        'id': 1,
        'name': 'Administrator',
        'email': 'admin@city.gov',
        'password_hash': generate_password_hash('secure2024'),
        'role': 'admin',
        'created_at': datetime.utcnow()
    }
]

issues = []
next_id = 1

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def save_image(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'images', unique_filename)
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Simple save without image processing
        file.save(filepath)
        return unique_filename
    return None

def get_address_from_coords(lat, lng):
    try:
        geolocator = Nominatim(user_agent="citywatch_app")
        location = geolocator.reverse((lat, lng), exactly_one=True)
        return location.address if location else "Address not found"
    except:
        return "Address not available"

# Auth decorators
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = next((u for u in users if u['id'] == data['user_id']), None)
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 401
        except:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Routes
@app.route('/')
def index():
    return jsonify({"message": "CityWatch API"})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('name') or not data.get('email') or not data.get('password'):
        return jsonify({"error": "Missing required fields"}), 400
    
    if any(user['email'] == data['email'] for user in users):
        return jsonify({"error": "Email already registered"}), 409
    
    hashed_password = generate_password_hash(data['password'])
    user_id = len(users) + 1
    
    user = {
        'id': user_id,
        'name': data['name'],
        'email': data['email'],
        'password_hash': hashed_password,
        'role': 'citizen',
        'created_at': datetime.utcnow()
    }
    
    users.append(user)
    
    return jsonify({
        "message": "User created successfully",
        "user": {
            "id": user['id'],
            "name": user['name'],
            "email": user['email'],
            "role": user['role']
        }
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"error": 'Email and password required'}), 400
    
    user = next((u for u in users if u['email'] == data['email']), None)
    
    if not user or not check_password_hash(user['password_hash'], data['password']):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': user['id'],
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    }, app.config['SECRET_KEY'])
    
    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user['id'],
            "name": user['name'],
            "email": user['email'],
            "role": user['role']
        }
    })

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    
    if not data or not data.get('admin_id') or not data.get('department') or not data.get('code'):
        return jsonify({"error": "Admin credentials required"}), 400
    
    if data['admin_id'] == 'admin123' and data['code'] == 'secure2024':
        admin_user = next((u for u in users if u['role'] == 'admin'), None)
        
        if admin_user:
            token = jwt.encode({
                'user_id': admin_user['id'],
                'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
            }, app.config['SECRET_KEY'])
            
            return jsonify({
                "message": "Admin login successful",
                "token": token,
                "user": {
                    "id": admin_user['id'],
                    "name": admin_user['name'],
                    "email": admin_user['email'],
                    "role": admin_user['role'],
                    "department": data['department']
                }
            })
    
    return jsonify({"error": "Invalid admin credentials"}), 401

@app.route('/api/issues', methods=['GET', 'POST'])
def handle_issues():
    global next_id
    
    if request.method == 'GET':
        user_id = request.args.get('user_id')
        status = request.args.get('status')
        search = request.args.get('search')
        
        filtered_issues = issues
        
        if user_id:
            filtered_issues = [i for i in filtered_issues if i['reported_by'] == int(user_id)]
        if status:
            filtered_issues = [i for i in filtered_issues if i['status'] == status]
        if search:
            search_lower = search.lower()
            filtered_issues = [
                i for i in filtered_issues 
                if search_lower in i['title'].lower() or 
                   search_lower in i['description'].lower()
            ]
        
        return jsonify({
            "issues": filtered_issues,
            "total": len(filtered_issues)
        })
    
    elif request.method == 'POST':
        try:
            title = request.form.get('title')
            description = request.form.get('description')
            issue_type = request.form.get('issue_type')
            latitude = float(request.form.get('latitude'))
            longitude = float(request.form.get('longitude'))
            user_id = int(request.form.get('user_id'))
            
            if not all([title, issue_type, latitude, longitude, user_id]):
                return jsonify({"error": "Missing required fields"}), 400
            
            address = get_address_from_coords(latitude, longitude)
            
            image_url = None
            if 'image' in request.files:
                image_filename = save_image(request.files['image'])
                if image_filename:
                    image_url = f"/uploads/images/{image_filename}"
            
            issue = {
                'id': next_id,
                'title': title,
                'description': description,
                'issue_type': issue_type,
                'latitude': latitude,
                'longitude': longitude,
                'address': address,
                'image_url': image_url,
                'status': 'reported',
                'reported_by': user_id,
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }
            
            issues.append(issue)
            next_id += 1
            
            return jsonify({
                "message": "Issue created successfully",
                "issue": issue
            }), 201
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route('/api/issues/<int:issue_id>', methods=['GET', 'PUT', 'DELETE'])
def issue_detail(issue_id):
    issue = next((i for i in issues if i['id'] == issue_id), None)
    
    if not issue:
        return jsonify({"error": "Issue not found"}), 404
    
    if request.method == 'GET':
        return jsonify({"issue": issue})
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        if 'status' in data:
            issue['status'] = data['status']
        
        issue['updated_at'] = datetime.utcnow().isoformat()
        
        return jsonify({
            "message": "Issue updated successfully",
            "issue": issue
        })
    
    elif request.method == 'DELETE':
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authorization required"}), 401
        
        try:
            user_id = int(auth_header[7:])
            user = next((u for u in users if u['id'] == user_id and u['role'] == 'admin'), None)
            
            if not user:
                return jsonify({"error": "Admin access required"}), 403
        except:
            return jsonify({"error": "Invalid authorization"}), 401
        
        issues.remove(issue)
        return jsonify({"message": "Issue deleted successfully"})

@app.route('/uploads/images/<filename>')
def uploaded_file(filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], 'images'), filename)

@app.route('/api/admin/stats')
def admin_stats():
    total_issues = len(issues)
    resolved_issues = len([i for i in issues if i['status'] == 'resolved'])
    pending_issues = len([i for i in issues if i['status'] == 'reported'])
    
    return jsonify({
        'total_issues': total_issues,
        'resolved_issues': resolved_issues,
        'pending_issues': pending_issues
    })

if __name__ == '__main__':
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'images'), exist_ok=True)
    
    if app.config['SECRET_KEY'] == 'dev-key-only-for-local':
        print("⚠️  WARNING: Using default SECRET_KEY. Set a secure SECRET_KEY environment variable for production!")
    
    app.run(debug=os.environ.get('FLASK_ENV') != 'production', host='0.0.0.0', port=5000)
