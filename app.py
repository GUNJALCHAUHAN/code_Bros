from datetime import time, datetime

import flask
from flask import request, render_template, session, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash

from blockchain import Blockchain
import qrcode
import base64
from io import BytesIO
from bson import SON
import secrets
from flask_mail import Mail, Message
import csv

# Initialize Flask app
secret_key = secrets.token_urlsafe(32)
app = flask.Flask(__name__)
app.secret_key = secret_key

blockchain = Blockchain()

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['user_database']
users_collection = db['users']
events_collection = db['events']

# Import CSV data to MongoDB
def import_events_from_csv():
    with open('event_details.csv', 'r') as file:
        csv_data = csv.DictReader(file)
        for row in csv_data:
            # Check if event already exists
            if not events_collection.find_one({'Event Name': row['Event Name']}):
                events_collection.insert_one(row)

# Call this function when the app starts
import_events_from_csv()

# Initialize Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'dhairyagudadhe14@gmail.com'
app.config['MAIL_PASSWORD'] = 'sqac szxq lhyq blhf'  # App password
mail = Mail(app)

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


@app.route('/register/<event_name>', methods=['GET', 'POST'])
def register(event_name):
    if request.method == 'GET':
        event = events_collection.find_one({'Event Name': event_name})
        if not event:
            return jsonify({'error': 'Event not found'}), 404
        return render_template('register.html', event=event)
    
    if request.method == 'POST':
        data = request.form
        
        # Get event details from MongoDB
        event = events_collection.find_one({'Event Name': event_name})
        if not event:
            return jsonify({'error': 'Event not found'}), 404
        
        # Create user registration document
        registration = {
            'event_name': event_name,
            'name': data['name'],
            'email': data['email'],
            'date_of_birth': data['dob'],
            'college_name': data['college'],
            'phone': data['phone'],
            'registration_date': datetime.now()
        }
        
        # Insert into database
        users_collection.insert_one(registration)
        
        # Send confirmation email
        send_confirmation_email(data['email'], data['name'], event)
        
        return jsonify({'message': 'Registration successful'}), 201


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


def send_confirmation_email(email, name, event):
    msg = Message('EventChain - Registration Confirmation',
                  sender='dhairyagudadhe14@gmail.com',
                  recipients=[email])
    
    msg.body = f"""Dear {name},

Thank you for registering for {event['Event Name']}.

Event Details:
- Event: {event['Event Name']}
- Date: {event['Date']}
- Venue: {event['Venue']}
- Description: {event['Description']}

Your registration has been successfully completed.

Best regards,
The EventChain Team
"""
    mail.send(msg)


@app.route('/validate/', methods=['GET', 'POST'])
def validate():
    if 'admin_logged_in' not in flask.session or not flask.session['admin_logged_in']:
        return flask.redirect('/admin-login')

    if flask.request.method == 'GET':
        return flask.render_template('validate.html')
    else:
        data = flask.request.get_json()
        transaction_id = data.get('registration_number')  # Use .get() to avoid KeyError
        if not transaction_id:
            message = {
                'status': 'error',
                'message': 'Registration number is missing in the request'
            }
            return flask.jsonify(message), 400

        transaction = blockchain.get_transaction_by_id(transaction_id)
        if not transaction:
            message = {
                'status': 'error',
                'message': 'Invalid registration number'
            }
            return flask.jsonify(message), 404

        # Constructing a transaction object to return
        transaction_data = {
            'name': transaction['name'],
            'email': transaction['email'],
            'college': transaction['college'],
            'course': transaction['course'],
            'roll_no': transaction['roll_no']
        }

        message = {
            'status': 'success',
            'message': transaction_data
        }
        return flask.jsonify(message), 200


@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if flask.request.method == 'GET':
        return flask.render_template('admin_login.html')
    else:
        # Implement admin login logic here
        admin_id = flask.request.form.get('admin_id')
        password = flask.request.form.get('password')

        # Query the database for admin credentials
        admin_user = blockchain.db.admin.find_one({'admin_id': admin_id, 'password': password})

        if admin_user:
            # Admin login successful
            flask.session['admin_logged_in'] = True
            return flask.redirect('/validate')
        else:
            # Admin login failed
            error_message = 'Invalid admin ID or password'
            return flask.render_template('admin_login.html', error=error_message)


@app.route('/', methods=['GET'])
def index():
    # Fetch all events from MongoDB
    events = list(events_collection.find({}, {'_id': 0}))
    return render_template('index.html', events=events)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
