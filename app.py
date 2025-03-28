from datetime import time, datetime
import flask
from flask import request, render_template, session, jsonify, redirect, url_for, send_from_directory
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from blockchain import Blockchain
import qrcode
import base64
from io import BytesIO
from bson import SON, ObjectId
import secrets
from flask_mail import Mail, Message
import csv
import os
from PIL import Image as PILImage, ImageDraw, ImageFont
import json
import uuid
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import Image as ReportLabImage
import hashlib
secret_key = secrets.token_urlsafe(32)
app = flask.Flask(__name__)
app.secret_key = secret_key
app.static_folder = 'static'

blockchain = Blockchain()

# MongoDB connection with error handling
try:
    client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
    client.server_info()  # Will throw an exception if unable to connect
    db = client['user_database']
    users_collection = db['users']
    events_collection = db['events']
    auth_users_collection = db['auth_users']  # For user authentication
    registrations_collection = db['registrations']  # For event registrations
except Exception as e:
    print(f"Failed to connect to MongoDB. Error: {str(e)}")
    exit(1)

def create_default_image():
    # Create directory if it doesn't exist
    static_dir = os.path.join(app.root_path, 'static', 'event')
    os.makedirs(static_dir, exist_ok=True)
    
    default_img_path = os.path.join(static_dir, 'default.jpg')
    
    if not os.path.exists(default_img_path):
        # Create a simple default image
        img = PILImage.new('RGB', (800, 600), color='#1a237e')
        d = ImageDraw.Draw(img)
        d.text((400, 300), "No Image Available", fill="white", anchor="mm", font=None)
        img.save(default_img_path, 'JPEG')

# Call this function during app initialization
create_default_image()

# Import CSV data to MongoDB
def import_events_from_csv():
    with open('event_details.csv', 'r') as file:
        csv_data = csv.DictReader(file)
        for row in csv_data:
            event_name = row['Event Name'].lower().replace(' ', '_')
            image_path = os.path.join(app.static_folder, 'event', f"{event_name}.jpg")
            
            # Use default image path if event image doesn't exist
            if not os.path.exists(image_path):
                row['image_path'] = "/static/event/default.jpg"
            else:
                row['image_path'] = f"/static/event/{event_name}.jpg"
            
            if not events_collection.find_one({'Event Name': row['Event Name']}):
                events_collection.insert_one(row)

# Update existing events with image paths if they don't have one
def update_event_images():
    events = events_collection.find({'image_path': {'$exists': False}})
    for event in events:
        event_name = event['Event Name'].lower().replace(' ', '_')
        events_collection.update_one(
            {'_id': event['_id']},
            {'$set': {'image_path': f"/static/event/{event_name}.jpg"}}
        )

# Call these functions when the app starts
import_events_from_csv()
update_event_images()

# Add admin credentials to MongoDB on startup
def setup_admin():
    admin_credentials = {
        'username': 'admin',
        'password': '12345678'
    }
    if not db.admin.find_one({'username': 'admin'}):
        db.admin.insert_one(admin_credentials)

setup_admin()

# Initialize Flask-Mail with updated settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'dhairyagudadhe14@gmail.com'
app.config['MAIL_PASSWORD'] = 'sqac szxq lhyq blhf'  # App password
app.config['MAIL_DEFAULT_SENDER'] = ('EventChain', 'dhairyagudadhe14@gmail.com')
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_ASCII_ATTACHMENTS'] = False

mail = Mail(app)

def generate_registration_qr(registration_data):
    try:
        # Create QR code with better error correction and size
        qr = qrcode.QRCode(
            version=4,  # Increased version for more data capacity
            error_correction=qrcode.constants.ERROR_CORRECT_Q,  # Higher error correction
            box_size=12,  # Larger box size
            border=5,  # Slightly larger border
        )
        
        # Simplified data structure for better scanning
        qr_data = {
            'rid': registration_data['registration_id'],  # shortened key names
            'n': registration_data['name'],
            'e': registration_data['event_name'],
            'm': registration_data['email']
        }
        
        qr.add_data(json.dumps(qr_data))
        qr.make(fit=True)
        
        # Create image with higher contrast
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Resize image to be larger
        img = img.resize((400, 400))
        
        buffer = BytesIO()
        img.save(buffer, format='PNG', optimize=True, quality=95)
        buffer.seek(0)
        
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        return qr_base64
    except Exception as e:
        print(f"Error generating QR code: {str(e)}")
        return None

def generate_registration_pdf(registration_data, event, qr_code):
    buffer = BytesIO()
    # Create PDF
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Add header
    c.setFillColor(colors.HexColor('#1a237e'))
    c.rect(0, height-100, width, 100, fill=True)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 24)
    c.drawString(50, height-60, "Event Registration Confirmation")
    
    # Add QR Code
    qr_image = PILImage.open(BytesIO(base64.b64decode(qr_code)))
    qr_image.save('temp_qr.png')
    c.drawImage('temp_qr.png', 200, height-400, width=200, height=200)
    os.remove('temp_qr.png')
    
    # Add registration details
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 16)
    y = height-450
    c.drawString(50, y, "Registration Details")
    
    c.setFont("Helvetica", 12)
    details = [
        f"Registration ID: {registration_data['registration_id']}",
        f"Name: {registration_data['name']}",
        f"Email: {registration_data['email']}",
        f"Event: {event['Event Name']}",
        f"Date: {event['Date']}",
        f"Venue: {event['Venue']}"
    ]
    
    for detail in details:
        y -= 25
        c.drawString(50, y, detail)
    
    # Add footer
    c.setFillColor(colors.grey)
    c.setFont("Helvetica", 10)
    c.drawString(50, 50, "Please bring this ticket to the event for entry.")
    
    c.save()
    buffer.seek(0)
    return buffer

def send_confirmation_email(registration, event, qr_code):
    try:
        msg = Message(
            subject='EventChain - Registration Confirmation',
            sender=('EventChain', 'dhairyagudadhe14@gmail.com'),
            recipients=[registration['email']]
        )
        
        msg.html = f"""
        <html>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
            <div style="max-width: 600px; margin: 0 auto; background: #ffffff; padding: 20px;">
                <!-- Header -->
                <div style="background: #1a237e; color: white; padding: 20px; text-align: center; border-radius: 5px;">
                    <h1 style="margin: 0;">Registration Confirmed! 🎉</h1>
                </div>
                
                <!-- Content -->
                <div style="padding: 20px; color: #333;">
                    <p style="font-size: 16px;">Dear <strong>{registration['name']}</strong>,</p>
                    <p style="font-size: 16px;">Your registration for <strong>{event['Event Name']}</strong> has been successfully confirmed.</p>
                    
                    <!-- Event Details Box -->
                    <div style="background: #f8f9fa; border-left: 4px solid #1a237e; padding: 15px; margin: 20px 0;">
                        <h2 style="color: #1a237e; margin-top: 0; font-size: 20px;">Event Details</h2>
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 8px 0;"><strong>Event:</strong></td>
                                <td>{event['Event Name']}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0;"><strong>Date:</strong></td>
                                <td>{event['Date']}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0;"><strong>Venue:</strong></td>
                                <td>{event['Venue']}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0;"><strong>Registration ID:</strong></td>
                                <td>{registration['registration_id']}</td>
                            </tr>
                        </table>
                    </div>

                    <!-- Important Notes -->
                    <div style="background: #fff3cd; border-radius: 5px; padding: 15px; margin: 20px 0;">
                        <h3 style="color: #856404; margin-top: 0; font-size: 18px;">Important Notes:</h3>
                        <ul style="list-style-type: none; padding-left: 0; margin: 0;">
                            <li style="margin-bottom: 10px;">✓ Please show your registration QR code at the entrance</li>
                            <li style="margin-bottom: 10px;">✓ Arrive 15 minutes before the event starts</li>
                            <li style="margin-bottom: 10px;">✓ Keep your ID proof handy for verification</li>
                        </ul>
                    </div>

                    <!-- QR Code will be generated at dashboard -->
                    <p style="text-align: center; background: #e8eaf6; padding: 15px; border-radius: 5px;">
                        <strong>Access your QR code from your dashboard when you arrive at the event.</strong>
                    </p>

                    <!-- Footer -->
                    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center;">
                        <p style="color: #666; font-size: 14px;">
                            Best regards,<br>
                            <strong style="color: #1a237e;">The EventChain Team</strong>
                        </p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        with app.app_context():
            mail.send(msg)
        return True
        
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        traceback.print_exc()
        return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if 'logged_in' in session and session['logged_in']:
            # User is already logged in
            return render_template('dashboard.html')
        else:
            return render_template('login.html')
    else:
        email = request.form.get('email')
        roll_no = request.form.get('roll_no')

        # Check if the email and roll_no match in your database
        user = blockchain.transactionsCollection.find_one({'email': email, 'roll_no': roll_no})
        if user:
            # Check if the user is already logged in
            if 'logged_in' in session and session['logged_in']:
                return jsonify({'success': False, 'message': 'You are already logged in.'})

            # Login successful
            session['logged_in'] = True
            session['email'] = email
            session['roll_no'] = roll_no

            # Generate QR code
            transaction_id = user['_id']
            qr_code = generate_qr_code(transaction_id)

            return jsonify({'success': True, 'qr_code': qr_code})
        else:
            # Login failed
            return jsonify({'success': False, 'message': 'Invalid email or roll number'})

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    
    if request.method == 'POST':
        user_data = {
            'name': request.form['name'],
            'email': request.form['email'],
            'roll_no': request.form['roll_no'],
            'college': request.form['college'],
            'password': generate_password_hash(request.form['password']),
            'created_at': datetime.now()
        }
        
        # Check if user already exists
        if auth_users_collection.find_one({'email': user_data['email']}):
            return render_template('signup.html', error='Email already registered')
            
        auth_users_collection.insert_one(user_data)
        return redirect(url_for('user_login'))

@app.route('/user-login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'GET':
        return render_template('user_login.html')
    
    email = request.form.get('email')
    password = request.form.get('password')

    user = auth_users_collection.find_one({'email': email})
    
    if user and check_password_hash(user['password'], password):
        session['logged_in'] = True
        session['email'] = email
        session['user_id'] = str(user['_id'])
        return redirect(url_for('user_dashboard'))
    else:
        return render_template('user_login.html', error='Invalid credentials')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/get_qr_code', methods=['GET'])
def get_qr_code():
    if 'logged_in' in session and session['logged_in']:
        # Check if the QR code has expired
        if 'qr_code_expiration' in session and time.time() < session['qr_code_expiration']:
            return jsonify({'qr_code': session['qr_code']})
        else:
            return jsonify({'error': 'QR code has expired'}), 403
    else:
        return jsonify({'error': 'Unauthorized'}), 401


def user_verified(name, email, roll_no):
    query = SON([
        ("Name", name),
        ("College Mail ID", email),
        ("PRN", int(roll_no))
    ])
    verified_user = blockchain.db.verification.find_one(query)
    return bool(verified_user)


def user_already_exists(name, email, roll_no):
    existing_user = blockchain.transactionsCollection.find_one({
        '$or': [
            {'name': name},
            {'email': email},
            {'roll_no': roll_no}
        ]
    })
    return bool(existing_user)


def generate_qr_code(transaction_id):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(transaction_id)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    qr_code_base64 = base64.b64encode(img_io.getvalue()).decode('utf-8')
    return f'data:image/png;base64,{qr_code_base64}'


@app.route('/register/<event_name>', methods=['GET', 'POST'])
def register(event_name):
    if not session.get('logged_in'):
        return redirect(url_for('user_login'))
    
    event = events_collection.find_one({'Event Name': event_name})
    if not event:
        return jsonify({'error': 'Event not found'}), 404

    if request.method == 'GET':
        return render_template('register.html', event=event)
    
    if request.method == 'POST':
        try:
            data = request.form
            registration_id = str(uuid.uuid4())  # Generate unique ID
            
            # Create registration document with QR hash
            registration = {
                'registration_id': registration_id,
                'qr_hash': hashlib.sha256(registration_id.encode()).hexdigest(),  # Create hash
                'event_name': event_name,
                'name': data['name'],
                'email': session.get('email'),
                'date_of_birth': data['dob'],
                'college_name': data['college'],
                'phone': data['phone'],
                'registration_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'user_id': session.get('user_id'),
                'verified': False  # Track if QR has been verified
            }
            
            # Save to MongoDB
            users_collection.insert_one(registration)
            
            # Send confirmation email
            msg = Message('Event Registration Confirmation',
                        sender='dhairyagudadhe14@gmail.com',
                        recipients=[registration['email']])
            
            msg.html = f"""
            <html>
            <body style="font-family: Arial, sans-serif;">
                <h2>Registration Confirmed!</h2>
                <p>Dear {registration['name']},</p>
                <p>Your registration for {event['Event Name']} has been confirmed.</p>
                <p><strong>Event Details:</strong></p>
                <ul>
                    <li>Event: {event['Event Name']}</li>
                    <li>Date: {event['Date']}</li>
                    <li>Venue: {event['Venue']}</li>
                </ul>
                <p>Please visit your dashboard to view your QR code for entry.</p>
                <br>
                <p>Best regards,<br>The Fiesta Team</p>
            </body>
            </html>
            """
            
            mail.send(msg)
            return redirect(url_for('user_dashboard'))
            
        except Exception as e:
            print(f"Error in registration: {str(e)}")
            return jsonify({'error': 'Registration failed'}), 500
    
    return render_template('register.html', event=event)

@app.route('/generate-qr/<registration_id>')
def generate_entry_qr(registration_id):
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    registration = users_collection.find_one({
        'registration_id': registration_id,
        'email': session.get('email')
    })
    
    if not registration:
        return jsonify({'error': 'Registration not found'}), 404

    try:
        # Get the QR hash from registration
        qr_hash = registration['qr_hash']
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=30,
            border=8
        )
        qr.add_data(qr_hash)
        qr.make(fit=True)
        
        # Create QR code image
        qr_image = qr.make_image(fill_color="black", back_color="white")
        qr_image = qr_image.resize((800, 800))
        
        # Create padding with PILImage
        padded_image = PILImage.new('RGB', (1000, 1000), 'white')
        # Calculate position to center the QR code
        paste_x = (1000 - qr_image.size[0]) // 2
        paste_y = (1000 - qr_image.size[1]) // 2
        padded_image.paste(qr_image, (paste_x, paste_y))
        
        # Convert to base64
        buffer = BytesIO()
        padded_image.save(buffer, format='PNG', optimize=False, quality=95)
        buffer.seek(0)
        
        img_str = base64.b64encode(buffer.getvalue()).decode()
        return jsonify({'qr_code': f"data:image/png;base64,{img_str}"})
        
    except Exception as e:
        print(f"QR Generation Error: {str(e)}")
        return jsonify({'error': 'Failed to generate QR code'}), 500

@app.route('/validate/', methods=['GET', 'POST'])
def validate():
    if 'admin_logged_in' not in session or not session['admin_logged_in']:
        return redirect('/admin-login')

    if request.method == 'GET':
        return render_template('validate.html')
    
    try:
        data = request.get_json()
        scanned_data = data.get('qr_data', '').strip()
        
        # Try to decode hash directly first
        registration = users_collection.find_one({'qr_hash': scanned_data})
        
        if not registration:
            try:
                # If not a hash, try parsing as JSON
                qr_json = json.loads(scanned_data)
                if isinstance(qr_json, dict) and 'rid' in qr_json:
                    # This is the new format with shortened keys
                    registration = users_collection.find_one({
                        'registration_id': qr_json['rid'],
                        'name': qr_json['n'],
                        'event_name': qr_json['e'],
                        'email': qr_json['m']
                    })
                else:
                    # Try old format or direct registration_id
                    registration = users_collection.find_one({
                        'registration_id': scanned_data
                    })
            except json.JSONDecodeError:
                # If not JSON, try as direct registration_id
                registration = users_collection.find_one({
                    'registration_id': scanned_data
                })
        
        if not registration:
            return jsonify({
                'status': 'error',
                'message': 'Invalid or unrecognized QR code'
            }), 404

        # Get event details
        event = events_collection.find_one({'Event Name': registration['event_name']})
        
        # Check if already verified
        if registration.get('verified'):
            return jsonify({
                'status': 'warning',
                'message': 'This registration has already been verified',
                'data': {
                    'name': registration['name'],
                    'email': registration['email'],
                    'event': registration['event_name'],
                    'registration_id': registration['registration_id'],
                    'verification_time': registration.get('verification_time', 'Unknown')
                }
            })
        
        # Update verification status
        users_collection.update_one(
            {'_id': registration['_id']},
            {'$set': {
                'verified': True,
                'verification_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }}
        )
        
        return jsonify({
            'status': 'success',
            'data': {
                'name': registration['name'],
                'email': registration['email'],
                'event': registration['event_name'],
                'registration_id': registration['registration_id'],
                'event_date': event['Date'] if event else 'Unknown',
                'event_venue': event['Venue'] if event else 'Unknown',
                'phone': registration.get('phone', 'Not provided'),
                'college': registration.get('college_name', 'Not provided'),
                'registration_date': registration.get('registration_date', 'Unknown')
            }
        })
        
    except Exception as e:
        print(f"Validation error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'QR code scanning failed. Please try again.'
        }), 500

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')
    
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Check for exact match with "Admin" and "12345"
    if username == "Admin" and password == "12345":
        session['admin_logged_in'] = True
        return redirect(url_for('admin_dashboard'))
    else:
        return render_template('admin_login.html', error='Invalid Admin ID or password')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')

@app.route('/admin/reminders')
def admin_reminders():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    # Get all upcoming events
    events = list(events_collection.find({'Date': {'$gte': datetime.now().strftime('%Y-%m-%d')}}))
    for event in events:
        # Get registrations for each event
        event['registrations'] = list(users_collection.find({'event_name': event['Event Name']}))
    
    return render_template('admin_reminders.html', events=events)

@app.route('/admin/send-reminder', methods=['POST'])
def send_event_reminder():
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    event_name = request.form.get('event_name')
    event = events_collection.find_one({'Event Name': event_name})
    if not event:
        return jsonify({'error': 'Event not found'}), 404
    
    registrations = users_collection.find({'event_name': event_name})
    success_count = 0
    
    for reg in registrations:
        try:
            msg = Message(
                'EventChain - Event Reminder',
                sender=('EventChain', 'dhairyagudadhe14@gmail.com'),
                recipients=[reg['email']]
            )
            
            msg.html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <div style="background-color: #1a237e; color: white; padding: 20px; text-align: center; border-radius: 5px;">
                    <h2 style="margin: 0;">Event Reminder</h2>
                </div>
                <div style="padding: 20px;">
                    <p>Dear {reg['name']},</p>
                    <p>This is a reminder that you are registered for <strong>{event['Event Name']}</strong>.</p>
                    <div style="background: #f8f9fa; padding: 15px; margin: 20px 0; border-radius: 5px;">
                        <p><strong>Event Details:</strong></p>
                        <ul>
                            <li>Date: {event['Date']}</li>
                            <li>Time: Check your registration email</li>
                            <li>Venue: {event['Venue']}</li>
                        </ul>
                    </div>
                    <p>Don't forget to bring your registration QR code for entry!</p>
                    <p>Best regards,<br>The EventChain Team</p>
                </div>
            </body>
            </html>
            """
            
            mail.send(msg)
            success_count += 1
        except Exception as e:
            print(f"Error sending reminder to {reg['email']}: {str(e)}")
    
    return jsonify({
        'message': f'Successfully sent {success_count} reminders',
        'total': users_collection.count_documents({'event_name': event_name})
    })

@app.route('/admin/verify')
def admin_verify():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('admin_verify.html')

@app.route('/admin/add-event', methods=['GET', 'POST'])
def add_event():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        event = {
            'Event Name': request.form['name'],
            'Description': request.form['description'],
            'Date': request.form['date'],
            'Venue': request.form['venue']
        }
        events_collection.insert_one(event)
        return redirect(url_for('admin_dashboard'))
    
    return render_template('add_event.html')

@app.route('/admin/send-reminders')
def send_reminders():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    users = users_collection.find({})
    for user in users:
        send_reminder_email(user['email'], user['name'], user['event_name'])
    
    return redirect(url_for('admin_dashboard'))

def send_reminder_email(email, name, event_name):
    msg = Message(
        'EventChain - Event Reminder',
        sender=('EventChain', 'dhairyagudadhe14@gmail.com'),
        recipients=[email]
    )
    msg.body = f"""Dear {name},
This is a reminder for your upcoming event: {event_name}
We look forward to seeing you!

Best regards,
The Fiesta Team"""
    mail.send(msg)

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

@app.route('/', methods=['GET'])
def index():
    # Fetch all events from MongoDB
    events = list(events_collection.find({}, {'_id': 0}))
    return render_template('index.html', events=events)

@app.route('/dashboard')
def user_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('user_login'))
    
    # Get user's registrations
    user_email = session.get('email')
    registrations = list(users_collection.find({'email': user_email}))
    
    # Get available events
    events = list(events_collection.find({}, {'_id': 0}))
    
    # Filter out events user has already registered for
    registered_event_names = [reg['event_name'] for reg in registrations]
    available_events = [event for event in events if event['Event Name'] not in registered_event_names]
    
    return render_template('user_dashboard.html', 
                         registrations=registrations, 
                         events=available_events)

if __name__ == '__main__':
    try:
        # Create required directories
        os.makedirs(os.path.join(app.root_path, 'static', 'event'), exist_ok=True)
        
        # Initialize database and create default image
        create_default_image()
        import_events_from_csv()
        update_event_images()
        setup_admin()
        
        # Run the app
        print("Server starting at http://localhost:5000")
        app.run(host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        print(f"Failed to start server. Error: {str(e)}")
