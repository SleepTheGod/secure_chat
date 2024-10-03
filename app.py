from flask import Flask, render_template, redirect, url_for, request
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from hashlib import sha256
import base64
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
db = SQLAlchemy(app)
socketio = SocketIO(app)

login_manager = LoginManager()
login_manager.init_app(app)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message_encrypted = db.Column(db.Text, nullable=False)
    iv = db.Column(db.Text, nullable=False)

# Setup user loader for login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions for encryption
def encrypt_message(message, pub_key):
    recipient_key = RSA.import_key(pub_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())

    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return base64.b64encode(encrypted_aes_key).decode(), base64.b64encode(ciphertext).decode(), base64.b64encode(cipher_aes.nonce).decode()

def decrypt_message(encrypted_key, ciphertext, nonce, priv_key):
    private_key = RSA.import_key(priv_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)

    aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_key))
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=base64.b64decode(nonce))
    
    decrypted_message = cipher_aes.decrypt(base64.b64decode(ciphertext)).decode()

    return decrypted_message

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user and user.password_hash == sha256(request.form['password'].encode()).hexdigest():
            login_user(user)
            return redirect(url_for('chat'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST']:
        username = request.form['username']
        password = sha256(request.form['password'].encode()).hexdigest()

        # Generate RSA key pair
        key = RSA.generate(2048)
        private_key = key.export_key().decode()
        public_key = key.publickey().export_key().decode()

        user = User(username=username, password_hash=password, private_key=private_key, public_key=public_key)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('chat'))
    return render_template('register.html')

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

@socketio.on('send_message')
@login_required
def handle_send_message(data):
    receiver_username = data['receiver']
    message = data['message']

    receiver = User.query.filter_by(username=receiver_username).first()
    if receiver:
        # Encrypt the message with the receiver's public key
        enc_key, enc_message, nonce = encrypt_message(message, receiver.public_key)

        # Save encrypted message in the database
        new_message = Message(sender_id=current_user.id, receiver_id=receiver.id, message_encrypted=enc_message, iv=nonce)
        db.session.add(new_message)
        db.session.commit()

        emit('receive_message', {'sender': current_user.username, 'message': enc_message}, room=receiver.id)

@socketio.on('join')
@login_required
def join():
    join_room(current_user.id)

if __name__ == '__main__':
    db.create_all()
    socketio.run(app, debug=True)
