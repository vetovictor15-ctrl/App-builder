from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db, login_manager
from app.models import User
from werkzeug.security import generate_password_hash
import json

bp = Blueprint('auth', __name__, url_prefix='/auth')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@bp.route('/register', methods=['GET', 'POST'])
def register():
    """Register new user"""
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not all([username, email, password]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 400
        
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict()
        }), 201
    
    return render_template('auth/register.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login user"""
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not all([username, password]):
            return jsonify({'error': 'Missing credentials'}), 400
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        login_user(user, remember=data.get('remember', False))
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict()
        }), 200
    
    return render_template('auth/login.html')

@bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logout user"""
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@bp.route('/profile', methods=['GET'])
@login_required
def profile():
    """Get current user profile"""
    return jsonify({
        'user': current_user.to_dict()
    }), 200

@bp.route('/update-profile', methods=['PUT'])
@login_required
def update_profile():
    """Update user profile"""
    data = request.get_json()
    
    if 'email' in data:
        if User.query.filter_by(email=data['email']).filter(User.id != current_user.id).first():
            return jsonify({'error': 'Email already in use'}), 400
        current_user.email = data['email']
    
    if 'password' in data:
        current_user.set_password(data['password'])
    
    db.session.commit()
    
    return jsonify({
        'message': 'Profile updated',
        'user': current_user.to_dict()
    }), 200