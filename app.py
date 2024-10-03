from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
db = SQLAlchemy(app)
socketio = SocketIO(app)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)  # Store user's private key

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)

db.create_all()

# Helper functions
def encrypt_message(message, public_key):
    recipient_key = RSA.import_key(public_key)
    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
    encrypted_session_key = recipient_key.encrypt(session_key, None)[0]
    return {
        'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
        'nonce': base64.b64encode(cipher_aes.nonce).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt_message(encrypted_data, private_key):
    private_key = RSA.import_key(private_key)
    session_key = private_key.decrypt(base64.b64decode(encrypted_data['encrypted_session_key']))
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=base64.b64decode(encrypted_data['nonce']))
    plaintext = cipher_aes.decrypt_and_verify(
        base64.b64decode(encrypted_data['ciphertext']), 
        base64.b64decode(encrypted_data['tag'])
    )
    return plaintext.decode('utf-8')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['private_key'] = user.private_key  # Store private key in session for decryption
            return redirect(url_for('chat'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        key = RSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password, public_key=public_key, private_key=private_key)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html')

@socketio.on('message')
def handle_message(data):
    sender = User.query.get(session['user_id'])
    receiver = User.query.filter_by(username=data['receiver']).first()
    if receiver:
        encrypted_message = encrypt_message(data['message'], receiver.public_key)
        new_message = Message(
            sender_id=sender.id,
            receiver_id=receiver.id,
            content=str(encrypted_message)  # Store encrypted message as a string
        )
        db.session.add(new_message)
        db.session.commit()

        emit('message', {'message': encrypted_message, 'sender': sender.username}, room=receiver.id)

@socketio.on('request_messages')
def handle_request_messages():
    user_id = session['user_id']
    private_key = session['private_key']
    messages = Message.query.filter((Message.sender_id == user_id) | (Message.receiver_id == user_id)).all()
    
    for message in messages:
        decrypted_message = decrypt_message(eval(message.content), private_key)  # Convert string back to dictionary
        emit('message', {
            'sender': message.sender_id,
            'content': decrypted_message
        })

@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        join_room(session['user_id'])  # Each user joins a room based on their user ID

if __name__ == '__main__':
    socketio.run(app, debug=True)
