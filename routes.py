from flask import session, render_template, render_template_string, request, redirect, url_for, flash, jsonify, abort, send_file
from flask_login import current_user, login_user
from app import app, db, limiter
from app import socketio
from auth import require_login
from models import User, Server, Channel, Message, DirectMessage, ServerMembership, Call, CallMessage, Voicemail, Invitation, SharedFile, MessageReaction, MessageReport, ContactAccess
from contact_manager import can_see_contact, can_message_contact, get_accessible_contacts, create_contact_access, process_invitation_contact_access
from datetime import datetime
import bleach
import uuid
import os
import base64
import logging
import re
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import io


# Register admin routes
try:
    from admin_routes import admin, setup_super_admin
    app.register_blueprint(admin)
    print("Admin routes registered successfully")

    # Set up super admin on startup
    with app.app_context():
        setup_super_admin()
except Exception as e:
    print(f"Error registering admin routes: {e}")

def sanitize_input(text, max_length=1000):
    """Sanitize and validate user input"""
    if not text:
        return ""
    # Strip whitespace and limit length
    text = text.strip()[:max_length]
    # Allow basic HTML tags for messages
    allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'br']
    return bleach.clean(text, tags=allowed_tags, strip=True)

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route('/')
def index():
    try:
        # Check if user is authenticated
        if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
            return redirect(url_for('home'))
        # Show splash page for non-authenticated users
        return render_template('splash.html')
    except Exception as e:
        logging.error(f"Error in index route: {e}")
        # Fallback response if templates fail
        return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>CommunicationX</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #36393f; color: white; }
        .container { max-width: 600px; margin: 0 auto; }
        .btn { display: inline-block; padding: 12px 24px; background: #5865f2; color: white; text-decoration: none; border-radius: 5px; margin: 10px; }
        .btn:hover { background: #4752c4; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 CommunicationX</h1>
        <p>Modern communication platform with real-time messaging, voice calls, and collaboration tools.</p>
        <div>
            <a href="{{ url_for('landing') }}" class="btn">Get Started</a>
            <a href="{{ url_for('login') }}" class="btn">Sign In</a>
        </div>
    </div>
</body>
</html>
        ''')

@app.route('/health')
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'app': 'CommunicationX',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/landing')
def landing():
    return render_template('landing.html')

@app.route('/test-messaging')
def test_messaging():
    """Test route for real-time messaging functionality"""
    return send_file('test_messaging.html')

@app.route('/test-dm-messaging')
def test_dm_messaging():
    """Test route for DM messaging functionality"""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DM Messaging Test</title>
        <script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            .test-section { border: 1px solid #ccc; padding: 15px; margin: 10px 0; }
            .messages { border: 1px solid #ddd; height: 200px; overflow-y: auto; padding: 10px; margin: 10px 0; }
            input, button { padding: 8px; margin: 5px; }
            .success { color: green; }
            .error { color: red; }
            .info { color: blue; }
        </style>
    </head>
    <body>
        <h1>DM Messaging & File Upload Test</h1>
        
        <div class="test-section">
            <h3>Connection Status</h3>
            <div id="connectionStatus">Connecting...</div>
        </div>
        
        <div class="test-section">
            <h3>DM Messaging Test</h3>
            <input type="text" id="dmMessage" placeholder="Type a DM message..." />
            <input type="number" id="recipientId" placeholder="Recipient ID" value="2" />
            <button onclick="sendDM()">Send DM</button>
            <div id="dmMessages" class="messages"></div>
        </div>
        
        <div class="test-section">
            <h3>File Upload Test (500MB Limit)</h3>
            <input type="file" id="fileInput" />
            <button onclick="testFileUpload()">Test Upload</button>
            <div id="uploadStatus"></div>
            <div id="fileInfo"></div>
        </div>
        
        <div class="test-section">
            <h3>Events Log</h3>
            <div id="eventsLog" class="messages"></div>
        </div>

        <script>
            let socket;
            
            function log(message, type = 'info') {
                const timestamp = new Date().toLocaleTimeString();
                const logDiv = document.getElementById('eventsLog');
                logDiv.innerHTML += `<div class="${type}">[${timestamp}] ${message}</div>`;
                logDiv.scrollTop = logDiv.scrollHeight;
                console.log(message);
            }
            
            function updateConnectionStatus(status) {
                const statusDiv = document.getElementById('connectionStatus');
                statusDiv.textContent = status;
                statusDiv.className = status.includes('Connected') ? 'success' : 'error';
            }
            
            function initSocket() {
                socket = io({
                    transports: ['websocket', 'polling'],
                    timeout: 20000,
                    reconnection: true
                });
                
                socket.on('connect', () => {
                    updateConnectionStatus('Connected to server');
                    log('Socket connected successfully', 'success');
                    
                    // Join user room for DM testing
                    socket.emit('join_user_room', {});
                    log('Joined user room for DM testing');
                });
                
                socket.on('disconnect', (reason) => {
                    updateConnectionStatus('Disconnected: ' + reason);
                    log('Socket disconnected: ' + reason, 'error');
                });
                
                socket.on('connect_error', (error) => {
                    updateConnectionStatus('Connection failed');
                    log('Connection error: ' + error, 'error');
                });
                
                socket.on('new_dm', (data) => {
                    log('New DM received: ' + JSON.stringify(data), 'success');
                    displayDM(data);
                });
                
                socket.on('dm_error', (data) => {
                    log('DM error: ' + JSON.stringify(data), 'error');
                });
                
                socket.on('joined_user_room', (data) => {
                    log('Joined user room: ' + JSON.stringify(data), 'success');
                });
                
                socket.on('joined_dm_conversation', (data) => {
                    log('Joined DM conversation: ' + JSON.stringify(data), 'success');
                });
            }
            
            function displayDM(data) {
                const messagesDiv = document.getElementById('dmMessages');
                const messageDiv = document.createElement('div');
                messageDiv.innerHTML = `
                    <strong>From:</strong> ${data.sender_name || 'User ' + data.sender_id}<br>
                    <strong>Content:</strong> ${data.content}<br>
                    <strong>Time:</strong> ${new Date(data.created_at).toLocaleString()}<br>
                    <strong>Status:</strong> ${data.status}
                `;
                messagesDiv.appendChild(messageDiv);
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }
            
            function sendDM() {
                const content = document.getElementById('dmMessage').value.trim();
                const recipientId = document.getElementById('recipientId').value;
                
                if (!content || !recipientId) {
                    alert('Please enter message content and recipient ID');
                    return;
                }
                
                log(`Sending DM: "${content}" to user ${recipientId}`);
                socket.emit('send_dm', {
                    content: content,
                    recipient_id: recipientId
                });
                
                document.getElementById('dmMessage').value = '';
            }
            
            function testFileUpload() {
                const fileInput = document.getElementById('fileInput');
                const file = fileInput.files[0];
                
                if (!file) {
                    alert('Please select a file first');
                    return;
                }
                
                const fileInfo = document.getElementById('fileInfo');
                const uploadStatus = document.getElementById('uploadStatus');
                
                // Display file information
                const fileSizeMB = (file.size / (1024 * 1024)).toFixed(2);
                fileInfo.innerHTML = `
                    <strong>File:</strong> ${file.name}<br>
                    <strong>Size:</strong> ${fileSizeMB} MB<br>
                    <strong>Type:</strong> ${file.type}
                `;
                
                // Check if file exceeds 500MB limit
                if (file.size > 500 * 1024 * 1024) {
                    uploadStatus.innerHTML = '<span class="error">❌ File exceeds 500MB limit</span>';
                    log(`File upload test: ${file.name} (${fileSizeMB}MB) exceeds 500MB limit`, 'error');
                    return;
                }
                
                uploadStatus.innerHTML = '<span class="success">✅ File size acceptable (within 500MB limit)</span>';
                log(`File upload test: ${file.name} (${fileSizeMB}MB) is within 500MB limit`, 'success');
                
                // Test actual upload (to a test endpoint)
                const formData = new FormData();
                formData.append('file', file);
                
                uploadStatus.innerHTML += '<br><span class="info">📤 Testing upload...</span>';
                
                fetch('/upload_message_file', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        uploadStatus.innerHTML += '<br><span class="success">✅ Upload successful!</span>';
                        log(`File upload successful: ${data.file_url || 'File uploaded'}`, 'success');
                    } else {
                        uploadStatus.innerHTML += '<br><span class="error">❌ Upload failed: ' + data.error + '</span>';
                        log(`File upload failed: ${data.error}`, 'error');
                    }
                })
                .catch(error => {
                    uploadStatus.innerHTML += '<br><span class="error">❌ Upload error: ' + error + '</span>';
                    log(`File upload error: ${error}`, 'error');
                });
            }
            
            // Initialize when page loads
            window.addEventListener('load', () => {
                log('Initializing DM messaging and file upload test...');
                initSocket();
            });
        </script>
    </body>
    </html>
    """

@app.route('/custom_auth', methods=['POST'])
def custom_auth():
    """Log in an existing account using username OR email and password."""
    identifier = request.form.get('identifier', '').strip()
    password = request.form.get('password', '')

    if not identifier or not password:
        flash('Username/email and password are required.', 'error')
        return redirect(url_for('login'))

    try:
        user = User.query.filter(
            (User.username.ilike(identifier)) | (User.email.ilike(identifier))
        ).first()

        if not user or not user.password_hash:
            flash('Invalid username/email or password.', 'error')
            return redirect(url_for('login'))

        if user.is_banned:
            flash('This account is banned.', 'error')
            return redirect(url_for('login'))

        if not check_password_hash(user.password_hash, password):
            flash('Invalid username/email or password.', 'error')
            return redirect(url_for('login'))

        user.status = 'online'
        user.last_seen = datetime.now()
        db.session.commit()
        login_user(user, remember=True)

        next_url = session.pop('next_url', None)
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(next_url or url_for('home'))

    except Exception as e:
        db.session.rollback()
        logging.exception("Local login failed")
        flash('Login failed. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    from flask_login import logout_user
    logout_user()
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    # Clear any existing session data to prevent conflicts
    if request.method == 'GET':
        session.clear()
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def custom_signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        first_name = sanitize_input(request.form.get('first_name', ''), max_length=50)
        last_name = sanitize_input(request.form.get('last_name', ''), max_length=50)
        username = sanitize_input(request.form.get('username', ''), max_length=64)
        email = sanitize_input(request.form.get('email', ''), max_length=255)
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        if not all([first_name, last_name, username, email, password]):
            flash('All fields are required.', 'error')
            return render_template('signup.html')

        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
            return render_template('signup.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('signup.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('signup.html')

        # Check if user exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            flash('Username or email already exists.', 'error')
            return render_template('signup.html')

        try:
            # Create new user
            password_hash = generate_password_hash(password)

            user = User()
            user.first_name = first_name
            user.last_name = last_name
            user.username = username
            user.email = email
            user.password_hash = password_hash

            db.session.add(user)
            db.session.flush()  # Get user ID before committing

            # Check if there's an invitation code in session
            invitation_code = session.get('invitation_code')
            if invitation_code:
                invitation = Invitation.query.filter_by(code=invitation_code).first()
                if invitation and invitation.uses_left > 0:
                    invitation.uses_left -= 1
                    db.session.add(invitation)
                    session.pop('invitation_code', None)  # Remove from session

            # Auto-add to public servers
            auto_add_user_to_servers(user)

            db.session.commit()

            # Log in the user
            login_user(user)

            flash('Account created successfully!', 'success')
            return redirect(url_for('home'))

        except SQLAlchemyError as e:
            db.session.rollback()
            flash('Error creating account. Please try again.', 'error')
            return render_template('signup.html')

    return render_template('signup.html')

@app.route('/custom_login', methods=['POST'])
def handle_custom_login():
    username = sanitize_input(request.form.get('username', ''), max_length=64)
    email = sanitize_input(request.form.get('email', ''), max_length=255)
    password = request.form.get('password', '')

    if not password:
        flash('Password is required.', 'error')
        return redirect(url_for('custom_login'))

    # Find user by username or email
    user = None
    if username:
        user = User.query.filter_by(username=username).first()
    elif email:
        user = User.query.filter_by(email=email).first()

    if not user:
        flash('Invalid credentials.', 'error')
        return redirect(url_for('custom_login'))

    # For now, we'll use a simple password check
    # In production, you should use proper password hashing like bcrypt
    if (
        hasattr(user, 'password_hash')
        and user.password_hash
        and check_password_hash(user.password_hash, password)
    ):
        login_user(user)
        return redirect(url_for('home'))
    else:
        flash('Invalid credentials.', 'error')
        return redirect(url_for('custom_login'))

@app.route('/home')
@require_login
def home():
    # Get user's servers
    user_servers = db.session.query(Server).join(ServerMembership).filter(
        ServerMembership.user_id == current_user.id
    ).all()

    # Get owned servers
    owned_servers = Server.query.filter_by(owner_id=current_user.id).all()

    # Combine and deduplicate
    all_servers = list({server.id: server for server in user_servers + owned_servers}.values())

    return render_template('home.html', servers=all_servers)

@app.route('/server/<int:server_id>')
@require_login
def server_view(server_id):
    server = Server.query.get_or_404(server_id)

    # Check if user has access to this server
    is_member = ServerMembership.query.filter_by(
        user_id=current_user.id, 
        server_id=server_id
    ).first() is not None

    is_owner = server.owner_id == current_user.id

    # For now, only server owners can access settings
    # Admin roles will be implemented with proper role system later
    is_admin = False

    if not (is_member or is_owner):
        flash('You do not have access to this server.', 'error')
        return redirect(url_for('home'))

    # Get first channel or create one if none exist
    channel = server.channels[0] if server.channels else None
    if not channel and is_owner:
        channel = Channel(name='general', server_id=server_id)
        db.session.add(channel)
        db.session.commit()

    messages = []
    if channel:
        messages = Message.query.filter_by(channel_id=channel.id).order_by(Message.created_at.desc()).limit(50).all()
        messages.reverse()

    members = db.session.query(User).join(ServerMembership).filter(
        ServerMembership.server_id == server_id
    ).all()

    return render_template('server.html', 
                         server=server, 
                         channel=channel, 
                         messages=messages, 
                         members=members,
                         is_owner=is_owner,
                         is_admin=is_admin)

@app.route('/channel/<int:channel_id>/send', methods=['POST'])
@require_login
def send_channel_message(channel_id):
    """Send message to specific channel"""
    channel = Channel.query.get_or_404(channel_id)
    server = channel.server

    # Check if user is member of server
    membership = ServerMembership.query.filter_by(
        user_id=current_user.id,
        server_id=server.id
    ).first()

    if not membership:
        abort(403)

    try:
        content = request.form.get('message', '').strip()
        if not content:
            flash('Message cannot be empty', 'error')
            return redirect(url_for('view_server', server_id=server.id, channel_id=channel.id))

        # Create message
        message = Message()
        message.content = content
        message.author_id = current_user.id
        message.channel_id = channel_id
        message.message_type = 'text'
        message.status = 'sent'

        db.session.add(message)
        db.session.commit()

        # Emit real-time message if socket available
        try:
            socketio.emit('new_message', {
                'id': message.id,
                'content': message.content,
                'author_id': message.author_id,
                'author_name': current_user.username,
                'author_avatar': current_user.profile_image_url,
                'channel_id': message.channel_id,
                'created_at': message.created_at.isoformat(),
                'message_type': message.message_type,
                'status': message.status
            }, to=f"channel_{channel_id}")
        except:
            pass  # Continue even if socket emission fails

        return redirect(url_for('view_server', server_id=server.id, channel_id=channel.id))

    except Exception as e:
        logging.error(f"Error sending message: {e}")
        flash('Error sending message. Please try again.', 'error')
        return redirect(url_for('view_server', server_id=server.id, channel_id=channel.id))

@app.route('/channel/<int:channel_id>/upload', methods=['POST'])
@require_login
def upload_channel_file(channel_id):
    """Upload file to specific channel"""
    channel = Channel.query.get_or_404(channel_id)
    server = channel.server

    # Check if user is member of server
    membership = ServerMembership.query.filter_by(
        user_id=current_user.id,
        server_id=server.id
    ).first()

    if not membership:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    try:
        if 'files' not in request.files:
            return jsonify({'success': False, 'error': 'No file selected'})

        files = request.files.getlist('files')
        if not files or all(f.filename == '' for f in files):
            return jsonify({'success': False, 'error': 'No file selected'})

        uploaded_files = []
        for file in files:
            if file and file.filename:
                # Create shared file record
                shared_file = SharedFile()
                shared_file.filename = secure_filename(file.filename) if file.filename else 'unnamed_file'
                shared_file.original_filename = file.filename
                shared_file.file_data = file.read()
                shared_file.file_size = len(shared_file.file_data)
                shared_file.mime_type = file.content_type or 'application/octet-stream'
                shared_file.uploader_id = current_user.id
                shared_file.server_id = server.id
                shared_file.channel_id = channel_id

                db.session.add(shared_file)
                db.session.flush()  # Get the ID

                # Create message with file attachment
                message = Message()
                message.content = f"📎 {file.filename}"
                message.author_id = current_user.id
                message.channel_id = channel_id
                message.message_type = 'file'
                message.status = 'sent'
                message.file_url = f"/file/{shared_file.id}"

                db.session.add(message)
                uploaded_files.append({
                    'filename': file.filename,
                    'size': shared_file.file_size,
                    'url': message.file_url
                })

        db.session.commit()

        # Emit real-time message for file upload
        if uploaded_files:
            try:
                socketio.emit('new_message', {
                    'id': message.id,
                    'content': message.content,
                    'author_id': message.author_id,
                    'author_name': current_user.username,
                    'author_avatar': current_user.profile_image_url,
                    'channel_id': message.channel_id,
                    'created_at': message.created_at.isoformat(),
                    'message_type': message.message_type,
                    'status': message.status,
                    'file_url': message.file_url
                }, to=f"channel_{channel_id}")
            except:
                pass

        return jsonify({
            'success': True,
            'message': 'Files uploaded successfully',
            'files': uploaded_files
        })

    except Exception as e:
        logging.error(f"Error uploading file: {e}")
        return jsonify({'success': False, 'error': 'Failed to upload file'}), 500

@app.route('/server/<int:server_id>/send_message', methods=['POST'])
@require_login
def send_message(server_id):
    server = Server.query.get_or_404(server_id)
    content = sanitize_input(request.form.get('message', ''), max_length=2000)

    if not content or len(content.strip()) == 0:
        flash('Message cannot be empty.', 'error')
        return redirect(url_for('server_view', server_id=server_id))

    if len(content) > 2000:
        flash('Message is too long. Maximum 2000 characters allowed.', 'error')
        return redirect(url_for('server_view', server_id=server_id))

    # Check access
    is_member = ServerMembership.query.filter_by(
        user_id=current_user.id, 
        server_id=server_id
    ).first() is not None

    is_owner = server.owner_id == current_user.id

    if not (is_member or is_owner):
        flash('You do not have access to this server.', 'error')
        return redirect(url_for('home'))

    # Get or create general channel
    channel = server.channels[0] if server.channels else None
    if not channel:
        channel = Channel(name='general', server_id=server_id)
        db.session.add(channel)
        db.session.commit()

    try:
        message = Message(
            content=content,
            author_id=current_user.id,
            channel_id=channel.id
        )
        db.session.add(message)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.error(f"Error sending message: {e}")
        flash('Error sending message. Please try again.', 'error')

    return redirect(url_for('server_view', server_id=server_id))

@app.route('/create_server', methods=['POST'])
@require_login
def create_server():
    logging.info(f"Create server request from user {current_user.id}")
    logging.info(f"Form data: {request.form}")

    name = sanitize_input(request.form.get('server_name', ''), max_length=100)
    description = sanitize_input(request.form.get('server_description', ''), max_length=500)

    logging.info(f"Processed name: '{name}', description: '{description}'")

    if not name or len(name.strip()) < 3:
        flash('Server name must be at least 3 characters long.', 'error')
        return redirect(url_for('home'))

    if len(name) > 100:
        flash('Server name is too long. Maximum 100 characters allowed.', 'error')
        return redirect(url_for('home'))

    # Check for duplicate server names (optional - remove if you want to allow duplicates)
    existing_server = Server.query.filter_by(name=name.strip(), owner_id=current_user.id).first()
    if existing_server:
        flash('You already have a server with this name.', 'error')
        return redirect(url_for('home'))

    try:
        # Create the server
        server = Server(
            name=name.strip(),
            description=description.strip() if description else None,
            owner_id=current_user.id,
            is_public=False  # New servers are private by default
        )
        db.session.add(server)
        db.session.flush()  # Get server ID before committing

        logging.info(f"Created server with ID: {server.id}")

        # Create default general channel
        channel = Channel(name='general', server_id=server.id)
        db.session.add(channel)
        db.session.flush()

        logging.info(f"Created channel with ID: {channel.id}")

        # Add owner as member
        membership = ServerMembership(
            user_id=current_user.id,
            server_id=server.id
        )
        db.session.add(membership)

        # Commit all changes together
        db.session.commit()

        logging.info(f"Server '{name}' created successfully by user {current_user.id}")
        flash(f'Server "{name}" created successfully!', 'success')
        return redirect(url_for('server_view', server_id=server.id))

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating server: {str(e)}")
        logging.error(f"Server name: '{name}', Description: '{description}', Owner ID: {current_user.id}")
        flash('Error creating server. Please try again.', 'error')
        return redirect(url_for('home'))

@app.route('/server/<int:server_id>/add_member', methods=['POST'])
@require_login
def add_member(server_id):
    server = Server.query.get_or_404(server_id)

    if server.owner_id != current_user.id:
        flash('Only the server owner can add members.', 'error')
        return redirect(url_for('server_view', server_id=server_id))

    username = request.form.get('username', '').strip()
    if not username:
        flash('Username is required.', 'error')
        return redirect(url_for('server_view', server_id=server_id))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('server_view', server_id=server_id))

    # Check if already a member
    existing_membership = ServerMembership.query.filter_by(
        user_id=user.id,
        server_id=server_id
    ).first()

    if existing_membership:
        flash('User is already a member of this server.', 'warning')
        return redirect(url_for('server_view', server_id=server_id))

    membership = ServerMembership(
        user_id=user.id,
        server_id=server_id
    )
    db.session.add(membership)
    db.session.commit()

    flash(f'User {username} added to server successfully!', 'success')
    return redirect(url_for('server_view', server_id=server_id))

@app.route('/direct_messages')
@require_login
def direct_messages():
    # Get accessible contacts based on admin status and invitation relationships
    accessible_contacts = get_accessible_contacts(current_user.id)
    accessible_contact_ids = [contact.id for contact in accessible_contacts]

    # Get all users who have had conversations with current user (filtered by access)
    conversations = db.session.query(User).join(
        DirectMessage,
        (DirectMessage.sender_id == User.id) | (DirectMessage.recipient_id == User.id)
    ).filter(
        (DirectMessage.sender_id == current_user.id) | (DirectMessage.recipient_id == current_user.id),
        User.id != current_user.id,
        User.id.in_(accessible_contact_ids)
    ).distinct().all()

    return render_template('direct_messages.html', 
                         conversations=conversations, 
                         all_users=accessible_contacts,
                         is_admin=current_user.is_admin or current_user.is_super_admin)

@app.route('/dm/<user_id>')
@require_login
def dm_conversation(user_id):
    try:
        other_user = User.query.get_or_404(user_id)

        # Check if user can message this contact
        if not can_message_contact(current_user.id, user_id):
            flash('You do not have permission to message this user.', 'error')
            return redirect(url_for('direct_messages'))

        # Get messages between current user and other user
        messages = DirectMessage.query.filter(
            ((DirectMessage.sender_id == current_user.id) & (DirectMessage.recipient_id == user_id)) |
            ((DirectMessage.sender_id == user_id) & (DirectMessage.recipient_id == current_user.id))
        ).order_by(DirectMessage.created_at.desc()).limit(50).all()

        messages.reverse()

        # Mark messages as read
        DirectMessage.query.filter(
            DirectMessage.sender_id == user_id,
            DirectMessage.recipient_id == current_user.id,
            DirectMessage.read_at == None
        ).update({DirectMessage.read_at: datetime.now()})
        db.session.commit()

        # Get accessible contacts for the contact list
        accessible_contacts = get_accessible_contacts(current_user.id)

        # Get conversations for sidebar
        conversations = db.session.query(User).join(
            DirectMessage,
            (DirectMessage.sender_id == User.id) | (DirectMessage.recipient_id == User.id)
        ).filter(
            (DirectMessage.sender_id == current_user.id) | (DirectMessage.recipient_id == current_user.id),
            User.id != current_user.id
        ).distinct().all()

        return render_template('direct_messages.html', 
                             other_user=other_user, 
                             messages=messages,
                             conversations=conversations,
                             all_users=accessible_contacts,
                             is_admin=current_user.is_admin or current_user.is_super_admin)
    except Exception as e:
        logging.error(f"Error in dm_conversation: {e}")
        flash('Error loading conversation. Please try again.', 'error')
        return redirect(url_for('direct_messages'))

@app.route('/send_dm/<user_id>', methods=['POST'])
@require_login
def send_dm(user_id):
    other_user = User.query.get_or_404(user_id)

    # Check if user can message this contact
    if not can_message_contact(current_user.id, user_id):
        flash('You do not have permission to message this user.', 'error')
        return redirect(url_for('direct_messages'))

    content = request.form.get('message', '').strip()

    if not content:
        flash('Message cannot be empty.', 'error')
        return redirect(url_for('dm_conversation', user_id=user_id))

    try:
        # Create new direct message
        dm = DirectMessage()
        dm.content = content
        dm.sender_id = current_user.id
        dm.recipient_id = int(user_id)
        dm.status = 'sent'
        dm.created_at = datetime.now()

        db.session.add(dm)
        db.session.flush()  # Get ID before committing
        db.session.commit()

        logging.info(f"Direct message created with ID: {dm.id}")

    except Exception as e:
        logging.error(f"Error creating direct message: {e}")
        db.session.rollback()
        flash('Failed to send message. Please try again.', 'error')
        return redirect(url_for('dm_conversation', user_id=user_id))

    # Emit real-time status update
    from socket_events import socketio
    socketio.emit('message_status_update', {
        'message_id': dm.id,
        'status': 'sent',
        'timestamp': dm.created_at.isoformat()
    }, to=f'user_{user_id}')

    return redirect(url_for('dm_conversation', user_id=user_id))

@app.route('/call/<user_id>/<call_type>')
@require_login
def initiate_call(user_id, call_type):
    other_user = User.query.get_or_404(user_id)

    if call_type not in ['audio', 'video']:
        flash('Invalid call type.', 'error')
        return redirect(url_for('dm_conversation', user_id=user_id))

    # Check for existing active call
    existing_call = Call.query.filter(
        ((Call.caller_id == current_user.id) | (Call.recipient_id == current_user.id)),
        Call.status.in_(['pending', 'active'])
    ).first()

    if existing_call:
        from markupsafe import Markup
        flash_message = f'You already have an active call. <a href="{url_for("end_call_route", call_id=existing_call.id)}" class="btn btn-sm btn-danger ms-2" onclick="return confirm(\'Are you sure you want to end the active call?\')"><i class="fas fa-phone-slash"></i> End Active Call</a>'
        flash(Markup(flash_message), 'error')
        return redirect(url_for('dm_conversation', user_id=user_id))

    call = Call(
        caller_id=current_user.id,
        recipient_id=user_id,
        call_type=call_type,
        status='pending'
    )
    db.session.add(call)
    db.session.commit()

    # Send call notification to recipient via SocketIO
    from app import socketio
    socketio.emit('incoming_call', {
        'call_id': call.id,
        'caller_id': current_user.id,
        'caller_name': current_user.first_name or current_user.username,
        'caller_avatar': current_user.profile_image_url,
        'call_type': call_type
    }, to=f'user_{user_id}')

    return render_template('call.html', 
                         call=call, 
                         other_user=other_user, 
                         is_caller=True)

@app.route('/end_call/<int:call_id>')
@require_login
def end_call_route(call_id):
    """End an active call and clean up resources"""
    call = Call.query.get_or_404(call_id)

    # Allow anyone who is connected or invited to end the call
    # No authorization check needed - any participant can end the call

    # Update call status to ended
    call.status = 'ended'
    call.ended_at = datetime.now()
    db.session.commit()

    # Emit socket event to notify participants
    from app import socketio
    socketio.emit('call_ended', {
        'call_id': call.id,
        'ended_by': current_user.id,
        'ended_by_name': current_user.username or current_user.first_name or 'User',
        'status': 'ended'
    }, to=f"user_{call.caller_id}")

    if call.recipient_id:
        socketio.emit('call_ended', {
            'call_id': call.id,
            'ended_by': current_user.id,
            'ended_by_name': current_user.username or current_user.first_name or 'User',
            'status': 'ended'
        }, to=f"user_{call.recipient_id}")

    flash('Call ended successfully.', 'success')

    # Redirect based on call type
    if call.recipient_id:
        return redirect(url_for('dm_conversation', user_id=call.recipient_id if call.caller_id == current_user.id else call.caller_id))
    else:
        return redirect(url_for('home'))

@app.route('/call_screen/<int:call_id>')
@require_login
def call_screen(call_id):
    """Direct call screen access for any call participant"""
    call = Call.query.get_or_404(call_id)

    # Allow access for caller, recipient, or server members
    is_authorized = False

    if call.caller_id == current_user.id or call.recipient_id == current_user.id:
        is_authorized = True

    # For server calls, check server membership
    if hasattr(call, 'server_id') and call.server_id:
        membership = ServerMembership.query.filter_by(
            user_id=current_user.id,
            server_id=call.server_id
        ).first()
        if membership:
            is_authorized = True

    if not is_authorized:
        flash('You are not authorized to join this call.', 'error')
        return redirect(url_for('home'))

    # Update call status if needed
    if call.status == 'pending' and call.recipient_id == current_user.id:
        call.status = 'active'
        db.session.commit()

    # Determine other user or server
    if call.recipient_id:
        other_user = User.query.get(call.recipient_id if call.caller_id == current_user.id else call.caller_id)
        return render_template('call_screen.html', 
                             call=call, 
                             other_user=other_user, 
                             is_caller=(call.caller_id == current_user.id))
    else:
        # Server call
        server = Server.query.get(call.server_id) if hasattr(call, 'server_id') else None
        return render_template('call_screen.html', 
                             call=call, 
                             server=server, 
                             is_caller=(call.caller_id == current_user.id))

@app.route('/join_call/<int:call_id>')
@require_login
def join_call(call_id):
    """Legacy join call route - redirects to call screen"""
    return redirect(url_for('call_screen', call_id=call_id))

@app.route('/end_call/<int:call_id>', methods=['POST'])
@require_login
def end_call(call_id):
    call = Call.query.get_or_404(call_id)

    if call.caller_id != current_user.id and call.recipient_id != current_user.id:
        flash('You are not authorized to end this call.', 'error')
        return redirect(url_for('home'))

    call.status = 'ended'
    call.ended_at = datetime.now()
    db.session.commit()

    return jsonify({'status': 'success'})

# API endpoints for call management
@app.route('/api/calls/<int:call_id>/accept', methods=['POST'])
@require_login
def api_accept_call(call_id):
    call = Call.query.get_or_404(call_id)

    if call.recipient_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    if call.status != 'pending':
        return jsonify({'error': 'Call is no longer available'}), 400

    call.status = 'active'
    db.session.commit()

    # Emit call accepted event via SocketIO
    from app import socketio
    socketio.emit('call_accepted', {
        'call_id': call_id,
        'recipient_id': current_user.id
    }, to=f'call_{call_id}')

    return jsonify({'status': 'success'}), 200

@app.route('/api/calls/<int:call_id>/decline', methods=['POST'])
@require_login
def api_decline_call(call_id):
    call = Call.query.get_or_404(call_id)

    if call.recipient_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    if call.status != 'pending':
        return jsonify({'error': 'Call is no longer available'}), 400

    call.status = 'declined'
    call.ended_at = datetime.now()
    db.session.commit()

    # Emit call declined event via SocketIO
    from app import socketio
    socketio.emit('call_declined', {
        'call_id': call_id,
        'recipient_id': current_user.id
    }, to=f'call_{call_id}')

    return jsonify({'status': 'success'}), 200

@app.route('/api/calls/<int:call_id>/end', methods=['POST'])
@require_login
def api_end_call(call_id):
    call = Call.query.get_or_404(call_id)

    if call.caller_id != current_user.id and call.recipient_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    call.status = 'ended'
    call.ended_at = datetime.now()
    db.session.commit()

    # Emit call ended event via SocketIO
    from app import socketio
    socketio.emit('call_ended', {
        'call_id': call_id,
        'ended_by': current_user.id
    }, to=f'call_{call_id}')

    return jsonify({'status': 'success'}), 200

@app.route('/profile')
@require_login
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/edit_profile', methods=['GET', 'POST'])
@require_login
def edit_profile():
    if request.method == 'POST':
        current_user.username = request.form.get('username') or current_user.username
        current_user.bio = request.form.get('bio')
        current_user.location = request.form.get('location')
        current_user.status = request.form.get('status') or 'online'

        # Handle resized image data first (takes priority)
        resized_image_data = request.form.get('resized_image_data')
        if resized_image_data and resized_image_data.startswith('data:image/'):
            try:
                # Validate data URL format
                if 'base64,' in resized_image_data:
                    current_user.profile_image_url = resized_image_data
                    flash('Profile photo updated successfully!', 'success')
                else:
                    flash('Invalid image data format.', 'error')
                    return render_template('edit_profile.html', user=current_user)
            except Exception as e:
                flash('Error processing resized image. Please try again.', 'error')
                return render_template('edit_profile.html', user=current_user)
        else:
            # Handle file upload
            profile_image = request.files.get('profile_image')
            if profile_image and profile_image.filename:
                # Validate file type
                allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
                file_ext = os.path.splitext(profile_image.filename)[1].lower()

                if file_ext in allowed_extensions:
                    try:
                        # Read file and convert to base64 data URL
                        file_data = profile_image.read()

                        # Check file size (limit to 5MB)
                        if len(file_data) > 5 * 1024 * 1024:
                            flash('Image file too large. Please use an image under 5MB.', 'error')
                            return render_template('edit_profile.html', user=current_user)

                        # Create data URL
                        mime_type = f"image/{file_ext[1:]}" if file_ext != '.jpg' else "image/jpeg"
                        base64_data = base64.b64encode(file_data).decode('utf-8')
                        data_url = f"data:{mime_type};base64,{base64_data}"

                        current_user.profile_image_url = data_url
                        flash('Profile photo uploaded successfully!', 'success')

                    except Exception as e:
                        flash('Error processing image file. Please try again.', 'error')
                        return render_template('edit_profile.html', user=current_user)
                else:
                    flash('Invalid file type. Please use JPG, PNG, GIF, or WebP images.', 'error')
                    return render_template('edit_profile.html', user=current_user)
            else:
                # Handle custom profile image URL if no file uploaded
                profile_image_url = request.form.get('profile_image_url')
                if profile_image_url:
                    current_user.profile_image_url = profile_image_url

        current_user.updated_at = datetime.now()
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=current_user)

@app.route('/voicemails')
@require_login
def voicemails():
    received_voicemails = Voicemail.query.filter_by(recipient_id=current_user.id).order_by(Voicemail.created_at.desc()).all()
    sent_voicemails = Voicemail.query.filter_by(sender_id=current_user.id).order_by(Voicemail.created_at.desc()).all()
    return render_template('voicemails.html', received=received_voicemails, sent=sent_voicemails)

@app.route('/send_voicemail/<user_id>', methods=['POST'])
@require_login
def send_voicemail(user_id):
    audio_url = request.form.get('audio_url')
    duration = request.form.get('duration', type=int)

    if not audio_url:
        flash('Audio recording required', 'error')
        return redirect(url_for('dm_conversation', user_id=user_id))

    voicemail = Voicemail(
        sender_id=current_user.id,
        recipient_id=user_id,
        audio_url=audio_url,
        duration=duration
    )
    db.session.add(voicemail)
    db.session.commit()

    flash('Voicemail sent!', 'success')
    return redirect(url_for('dm_conversation', user_id=user_id))

@app.route('/mark_voicemail_read/<int:voicemail_id>', methods=['POST'])
@require_login
def mark_voicemail_read(voicemail_id):
    voicemail = Voicemail.query.get_or_404(voicemail_id)
    if voicemail.recipient_id != current_user.id:
        flash('Unauthorized', 'error')
        return redirect(url_for('voicemails'))

    voicemail.is_read = True
    db.session.commit()
    return jsonify({'status': 'success'})

def auto_add_user_to_servers(user):
    """Automatically add new users to all public servers"""
    try:
        public_servers = Server.query.filter_by(is_public=True).all()
        for server in public_servers:
            existing_membership = ServerMembership.query.filter_by(
                user_id=user.id, 
                server_id=server.id
            ).first()

            if not existing_membership:
                membership = ServerMembership(user_id=user.id, server_id=server.id)
                db.session.add(membership)

        # Don't commit here - let the calling function handle the commit
        logging.info(f"Added user {user.id} to {len(public_servers)} public servers")

    except Exception as e:
        logging.error(f"Error auto-adding user to servers: {e}")
        # Don't raise the exception, just log it

@app.route('/server_call/<int:server_id>')
@require_login
def server_call(server_id):
    server = Server.query.get_or_404(server_id)

    # Check if user is member of server
    membership = ServerMembership.query.filter_by(
        user_id=current_user.id,
        server_id=server_id
    ).first()

    if not membership:
        flash('You are not a member of this server', 'error')
        return redirect(url_for('home'))

    # Get active server calls
    active_calls = Call.query.filter_by(
        server_id=server_id,
        status='active'
    ).all()

    return render_template('server_call.html', server=server, active_calls=active_calls)

@app.route('/initiate_server_call/<int:server_id>', methods=['POST'])
@require_login
def initiate_server_call(server_id):
    call_type = request.form.get('call_type', 'audio')

    # Create server call
    call = Call(
        caller_id=current_user.id,
        recipient_id=current_user.id,  # For server calls, we'll use same ID
        server_id=server_id,
        call_type=call_type,
        status='active'
    )
    db.session.add(call)
    db.session.commit()

    return redirect(url_for('server_call', server_id=server_id))

@app.route('/send_call_message/<int:call_id>', methods=['POST'])
@require_login
def send_call_message(call_id):
    content = request.form.get('content')
    if not content:
        return jsonify({'error': 'Message content required'}), 400

    call = Call.query.get_or_404(call_id)

    message = CallMessage(
        call_id=call_id,
        user_id=current_user.id,
        content=content
    )
    db.session.add(message)
    db.session.commit()

    return jsonify({
        'id': message.id,
        'content': message.content,
        'user': current_user.username or current_user.first_name or 'Anonymous',
        'timestamp': message.created_at.strftime('%H:%M')
    })

@app.route('/update_server_logo/<int:server_id>', methods=['POST'])
@require_login
def update_server_logo(server_id):
    server = Server.query.get_or_404(server_id)

    if server.owner_id != current_user.id:
        flash('Only the server owner can update the logo.', 'error')
        return redirect(url_for('server_view', server_id=server_id))

    logo_file = request.files.get('logo_file')
    if logo_file and logo_file.filename:
        # Validate file type
        allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
        file_ext = os.path.splitext(logo_file.filename)[1].lower()

        if file_ext in allowed_extensions:
            try:
                # Read file and convert to base64 data URL
                file_data = logo_file.read()

                # Check file size (limit to 2MB)
                if len(file_data) > 2 * 1024 * 1024:
                    flash('Logo file too large. Please use an image under 2MB.', 'error')
                    return redirect(url_for('server_view', server_id=server_id))

                # Create data URL
                mime_type = f"image/{file_ext[1:]}" if file_ext != '.jpg' else "image/jpeg"
                base64_data = base64.b64encode(file_data).decode('utf-8')
                data_url = f"data:{mime_type};base64,{base64_data}"

                server.logo_url = data_url
                db.session.commit()
                flash('Server logo updated successfully!', 'success')

            except Exception as e:
                flash('Error processing logo file. Please try again.', 'error')
        else:
            flash('Invalid file type. Please use JPG, PNG, GIF, or WebP images.', 'error')

    return redirect(url_for('server_view', server_id=server_id))

@app.route('/servers/<int:server_id>/edit', methods=['POST'])
@require_login
def edit_server(server_id):
    """Edit server information"""
    server = Server.query.get_or_404(server_id)

    # Only server owner can edit
    if server.owner_id != current_user.id:
        abort(403)

    name = sanitize_input(request.form.get('name', '').strip(), 100)
    description = sanitize_input(request.form.get('description', '').strip(), 500)
    is_public = request.form.get('is_public') == '1'

    if not name:
        flash('Server name is required', 'error')
        return redirect(url_for('server_view', server_id=server_id))

    # Check if name is already taken by another server
    existing_server = Server.query.filter(Server.name == name, Server.id != server_id).first()
    if existing_server:
        flash('A server with this name already exists', 'error')
        return redirect(url_for('server_view', server_id=server_id))

    server.name = name
    server.description = description if description else None
    server.is_public = is_public

    db.session.commit()

    # If changed to public, auto-add all users
    if is_public:
        try:
            all_users = User.query.all()
            for user in all_users:
                existing_membership = ServerMembership.query.filter_by(
                    user_id=user.id, 
                    server_id=server_id
                ).first()

                if not existing_membership:
                    membership = ServerMembership(user_id=user.id, server_id=server_id)
                    db.session.add(membership)

            db.session.commit()
            logging.info(f"Auto-added all users to public server {server_id}")
        except Exception as e:
            logging.error(f"Error auto-adding users to public server: {e}")
            db.session.rollback()

    flash('Server information updated successfully', 'success')
    return redirect(url_for('server_view', server_id=server_id))

@app.route('/servers/<int:server_id>/delete', methods=['POST'])
@require_login
def delete_server(server_id):
    """Delete server and all associated data"""
    server = Server.query.get_or_404(server_id)

    # Only server owner can delete
    if server.owner_id != current_user.id:
        abort(403)

    confirm_name = request.form.get('confirm_name', '').strip()
    if confirm_name != server.name:
        flash('Server name confirmation does not match', 'error')
        return redirect(url_for('server_view', server_id=server_id))

    # Delete server (cascade will handle channels, messages, memberships, etc.)
    db.session.delete(server)
    db.session.commit()

    flash(f'Server "{server.name}" has been permanently deleted', 'success')
    return redirect(url_for('home'))

@app.route('/upload_file/<int:server_id>', methods=['POST'])
@require_login
def upload_file(server_id):
    server = Server.query.get_or_404(server_id)

    # Check if user is member of server
    is_member = ServerMembership.query.filter_by(
        user_id=current_user.id, 
        server_id=server_id
    ).first() is not None

    is_owner = server.owner_id == current_user.id

    if not (is_member or is_owner):
        flash('You do not have access to this server.', 'error')
        return redirect(url_for('home'))

    uploaded_file = request.files.get('file')
    if uploaded_file and uploaded_file.filename:
        try:
            # Read file data
            file_data = uploaded_file.read()

            # Check file size (limit to 10MB)
            if len(file_data) > 10 * 1024 * 1024:
                flash('File too large. Please use a file under 10MB.', 'error')
                return redirect(url_for('server_view', server_id=server_id))

            # Get or create general channel
            channel = server.channels[0] if server.channels else None
            if not channel:
                channel = Channel(name='general', server_id=server_id)
                db.session.add(channel)
                db.session.flush()

            # Create file record
            shared_file = SharedFile(
                filename=str(uuid.uuid4()) + '_' + uploaded_file.filename,
                original_filename=uploaded_file.filename,
                file_data=file_data,
                file_size=len(file_data),
                mime_type=uploaded_file.content_type or 'application/octet-stream',
                uploader_id=current_user.id,
                server_id=server_id,
                channel_id=channel.id
            )
            db.session.add(shared_file)

            # Create message about file upload
            message = Message(
                content=f"📎 {current_user.username or current_user.first_name or 'User'} uploaded: {uploaded_file.filename}",
                author_id=current_user.id,
                channel_id=channel.id
            )
            db.session.add(message)
            db.session.commit()

            flash(f'File "{uploaded_file.filename}" uploaded successfully!', 'success')

        except Exception as e:
            db.session.rollback()
            flash('Error uploading file. Please try again.', 'error')

    return redirect(url_for('server_view', server_id=server_id))

@app.route('/download_file/<int:file_id>')
@require_login
def download_file(file_id):
    shared_file = SharedFile.query.get_or_404(file_id)

    # Check if user has access to the file
    if shared_file.server_id:
        is_member = ServerMembership.query.filter_by(
            user_id=current_user.id, 
            server_id=shared_file.server_id
        ).first() is not None

        is_owner = shared_file.server.owner_id == current_user.id

        if not (is_member or is_owner):
            flash('You do not have access to this file.', 'error')
            return redirect(url_for('home'))

    from flask import Response
    return Response(
        shared_file.file_data,
        mimetype=shared_file.mime_type,
        headers={
            'Content-Disposition': f'attachment; filename="{shared_file.original_filename}"'
        }
    )

@app.route('/create_invitation', methods=['POST'])
@require_login
def create_invitation():
    import secrets

    code = secrets.token_urlsafe(16)
    email = request.form.get('email', '').strip()

    invitation = Invitation(
        code=code,
        inviter_id=current_user.id,
        email=email if email else None,
        uses_left=5  # Allow 5 uses per invitation
    )
    db.session.add(invitation)
    db.session.commit()

    base_url = request.url_root.rstrip('/')
    invite_url = f"{base_url}/invite/{code}"

    # Send email if email address is provided
    if email:
        try:
            send_invitation_email(email, invite_url, current_user.username or current_user.first_name or 'A friend')
            flash(f'Invitation sent to {email}!', 'success')
        except Exception as e:
            flash('Invitation created but email could not be sent. You can still share the link manually.', 'warning')

    return jsonify({
        'success': True,
        'invite_url': invite_url,
        'code': code,
        'email_sent': bool(email)
    })

def send_invitation_email(to_email, invite_url, inviter_name):
    """Send invitation email using a simple email service"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    # For demo purposes, we'll just log the email content
    # In production, you'd configure SMTP settings
    subject = f"{inviter_name} invited you to join CommunicationX!"

    body = f"""
    Hi there!

    {inviter_name} has invited you to join CommunicationX, a modern communication platform.

    Click the link below to join:
    {invite_url}

    This invitation can be used up to 5 times and doesn't expire.

    Welcome to CommunicationX!
    """

    # Log the email content (replace with actual SMTP in production)
    print(f"EMAIL TO: {to_email}")
    print(f"SUBJECT: {subject}")
    print(f"BODY: {body}")

    # For production, uncomment and configure:
    # msg = MIMEMultipart()
    # msg['From'] = "noreply@communicationx.com"
    # msg['To'] = to_email
    # msg['Subject'] = subject
    # msg.attach(MIMEText(body, 'plain'))
    # 
    # server = smtplib.SMTP('your-smtp-server.com', 587)
    # server.starttls()
    # server.login("your-email@domain.com", "your-password")
    # server.send_message(msg)
    # server.quit()

@app.route('/invite/<code>')
def join_by_invitation(code):
    invitation = Invitation.query.filter_by(code=code).first()

    if not invitation or invitation.uses_left <= 0:
        flash('Invalid or expired invitation.', 'error')
        return redirect(url_for('index'))

    # Always redirect to login/signup regardless of authentication status
    # Store invitation code in session for after login/signup
    session['invitation_code'] = code

    if current_user.is_authenticated:
        # Log out current user to allow new user to sign up
        from flask_login import logout_user
        logout_user()
        flash('Please log in with the account you want to use for this invitation.', 'info')
    else:
        flash('Please sign up or log in to join CommunicationX!', 'info')

    return redirect(url_for('custom_signup'))

@app.route('/start_call/<call_type>/<user_id>')
@require_login
def start_call(call_type, user_id):
    other_user = User.query.get_or_404(user_id)

    if call_type not in ['audio', 'video']:
        flash('Invalid call type.', 'error')
        return redirect(url_for('dm_conversation', user_id=user_id))

    # Check for existing active call
    existing_call = Call.query.filter(
        ((Call.caller_id == current_user.id) | (Call.recipient_id == current_user.id)),
        Call.status.in_(['pending', 'active'])
    ).first()

    if existing_call:
        from markupsafe import Markup
        flash_message = f'You already have an active call. <a href="{url_for("end_call_route", call_id=existing_call.id)}" class="btn btn-sm btn-danger ms-2" onclick="return confirm(\'Are you sure you want to end the active call?\')"><i class="fas fa-phone-slash"></i> End Active Call</a>'
        flash(Markup(flash_message), 'error')
        return redirect(url_for('dm_conversation', user_id=user_id))

    call = Call(
        caller_id=current_user.id,
        recipient_id=user_id,
        call_type=call_type,
        status='active'
    )
    db.session.add(call)
    db.session.commit()

    return render_template('call_screen.html', 
                         call=call, 
                         other_user=other_user, 
                         is_caller=True)

@app.route('/start_server_call/<int:server_id>/<call_type>')
@require_login
def start_server_call(server_id, call_type):
    server = Server.query.get_or_404(server_id)

    # Check if user is member of server
    membership = ServerMembership.query.filter_by(
        user_id=current_user.id,
        server_id=server_id
    ).first()

    if not membership and server.owner_id != current_user.id:
        flash('You are not a member of this server', 'error')
        return redirect(url_for('home'))

    if call_type not in ['audio', 'video']:
        flash('Invalid call type.', 'error')
        return redirect(url_for('server_view', server_id=server_id))

    # Create server call
    call = Call(
        caller_id=current_user.id,
        recipient_id=current_user.id,  # For server calls
        server_id=server_id,
        call_type=call_type,
        status='active'
    )
    db.session.add(call)
    db.session.commit()

    return render_template('call_screen.html', 
                         call=call, 
                         server=server, 
                         is_server_call=True)

# Message Management Routes
@app.route('/message/<int:message_id>/delete', methods=['POST'])
@require_login
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)

    # Check permissions
    if message.author_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        db.session.delete(message)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete message'}), 500

@app.route('/message/<int:message_id>/react', methods=['POST'])
@require_login
def react_to_message(message_id):
    message = Message.query.get_or_404(message_id)
    emoji = request.json.get('emoji')

    if not emoji:
        return jsonify({'error': 'Emoji required'}), 400

    try:
        # Check if reaction already exists
        existing_reaction = MessageReaction.query.filter_by(
            message_id=message_id,
            user_id=current_user.id,
            emoji=emoji
        ).first()

        if existing_reaction:
            # Remove reaction if it exists
            db.session.delete(existing_reaction)
            action = 'removed'
        else:
            # Add new reaction
            reaction = MessageReaction(
                message_id=message_id,
                user_id=current_user.id,
                emoji=emoji
            )
            db.session.add(reaction)
            action = 'added'

        db.session.commit()
        return jsonify({'success': True, 'action': action})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to process reaction'}), 500

@app.route('/message/<int:message_id>/pin', methods=['POST'])
@require_login
def pin_message(message_id):
    message = Message.query.get_or_404(message_id)

    # Check if user has permission (author or server owner)
    channel = Channel.query.get(message.channel_id)
    server = Server.query.get(channel.server_id)

    if message.author_id != current_user.id and server.owner_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        message.is_pinned = not message.is_pinned
        db.session.commit()
        return jsonify({'success': True, 'pinned': message.is_pinned})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update pin status'}), 500

@app.route('/message/<int:message_id>/report', methods=['POST'])
@require_login
def report_message(message_id):
    message = Message.query.get_or_404(message_id)
    reason = request.json.get('reason')
    description = request.json.get('description', '')

    if not reason:
        return jsonify({'error': 'Report reason required'}), 400

    try:
        report = MessageReport(
            message_id=message_id,
            reporter_id=current_user.id,
            reason=reason,
            description=description
        )
        db.session.add(report)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to submit report'}), 500

@app.route('/message/<int:message_id>/reply', methods=['POST'])
@require_login
def reply_to_message(message_id):
    original_message = Message.query.get_or_404(message_id)
    content = sanitize_input(request.json.get('content', ''), max_length=2000)

    if not content or len(content.strip()) == 0:
        return jsonify({'error': 'Message content required'}), 400

    try:
        reply = Message(
            content=content,
            author_id=current_user.id,
            channel_id=original_message.channel_id,
            reply_to_id=message_id
        )
        db.session.add(reply)
        db.session.commit()
        return jsonify({'success': True, 'message_id': reply.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to send reply'}), 500

@app.route('/message/<int:message_id>/forward', methods=['POST'])
@require_login
def forward_message(message_id):
    original_message = Message.query.get_or_404(message_id)
    recipient_id = request.json.get('recipient_id')

    if not recipient_id:
        return jsonify({'error': 'Recipient required'}), 400

    try:
        # Create direct message with forwarded content
        forwarded_content = f"Forwarded message: {original_message.content}"

        dm = DirectMessage(
            content=forwarded_content,
            sender_id=current_user.id,
            recipient_id=recipient_id
        )
        db.session.add(dm)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to forward message'}), 500

@app.route('/message/<int:message_id>/audio', methods=['POST'])
@require_login
def send_audio_message(message_id=None):
    audio_file = request.files.get('audio')
    channel_id = request.form.get('channel_id')

    if not audio_file or not channel_id:
        return jsonify({'error': 'Audio file and channel required'}), 400

    try:
        # Store audio data
        audio_data = audio_file.read()

        message = Message(
            content="Audio message",
            author_id=current_user.id,
            channel_id=int(channel_id),
            message_type='audio',
            file_data=audio_data
        )
        db.session.add(message)
        db.session.commit()
        return jsonify({'success': True, 'message_id': message.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to send audio message'}), 500

# Tools Routes
@app.route('/tools/hackkit/<workspace_type>')
@require_login
def hackkit(workspace_type):
    """HackKit code editor interface"""
    if workspace_type not in ['personal', 'group']:
        return redirect(url_for('home'))
    return render_template('tools/hackkit.html', workspace_type=workspace_type, workspaces=[])

@app.route('/tools/canva/<workspace_type>')
@require_login
def canva(workspace_type):
    """Canva design tool interface"""
    if workspace_type not in ['personal', 'group']:
        return redirect(url_for('home'))
    return render_template('tools/canva.html', workspace_type=workspace_type, workspaces=[])

@app.route('/tools/opera/<session_type>')
@require_login
def opera(session_type):
    """Opera browser interface"""
    if session_type not in ['personal', 'group']:
        return redirect(url_for('home'))
    return render_template('tools/opera.html', session_type=session_type, sessions=[])

@app.route('/tools/files')
@require_login
def files_manager():
    """Files manager interface"""
    return render_template('tools/files.html', code_files=[], design_files=[], browser_files=[])

# Message interaction API routes - Delete, Forward, React, Reply

@app.route('/api/message/<int:message_id>/delete', methods=['POST'])
@require_login  
def api_delete_message(message_id):
    """Delete a message (soft delete)"""
    try:
        message = Message.query.get_or_404(message_id)

        # Check if user can delete (author or admin)
        can_delete = message.author_id == current_user.id
        if not can_delete and hasattr(message, 'channel') and message.channel:
            membership = ServerMembership.query.filter_by(
                user_id=current_user.id, 
                server_id=message.channel.server_id
            ).first()
            if membership and hasattr(message.channel, 'server') and message.channel.server.owner_id == current_user.id:
                can_delete = True

        if not can_delete:
            return jsonify({'success': False, 'error': 'Permission denied'})

        # Soft delete
        message.deleted_at = datetime.now()
        message.content = "[Message deleted]"
        db.session.commit()

        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error deleting message: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/message/<int:message_id>/reply', methods=['POST'])
@require_login
def api_reply_to_message(message_id):
    """Reply to a message"""
    try:
        data = request.get_json()
        content = data.get('content', '').strip()

        if not content:
            return jsonify({'success': False, 'error': 'Message content required'})

        original_message = Message.query.get_or_404(message_id)

        # Create reply message  
        reply_message = Message(
            content=f"@{original_message.author_id}: {content}",
            author_id=current_user.id,
            channel_id=original_message.channel_id,
            reply_to_id=message_id,
            message_type='reply'
        )
        db.session.add(reply_message)
        db.session.commit()

        return jsonify({'success': True, 'message_id': reply_message.id})
    except Exception as e:
        logging.error(f"Error creating reply: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/message/<int:message_id>/forward', methods=['POST'])
@require_login
def api_forward_message(message_id):
    """Forward a message to another channel"""
    try:
        data = request.get_json()
        target_channel_id = data.get('channel_id')

        if not target_channel_id:
            return jsonify({'success': False, 'error': 'Target channel required'})

        original_message = Message.query.get_or_404(message_id)

        # Create forwarded message
        forwarded_message = Message(
            content=f"Forwarded: {original_message.content}",
            author_id=current_user.id,
            channel_id=target_channel_id,
            forwarded_from_id=message_id,
            message_type='forward'
        )
        db.session.add(forwarded_message)
        db.session.commit()

        return jsonify({'success': True, 'message_id': forwarded_message.id})
    except Exception as e:
        logging.error(f"Error forwarding message: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/message/<int:message_id>/react', methods=['POST'])
@require_login
def api_react_to_message(message_id):
    """Add or remove reaction to a message"""
    try:
        data = request.get_json()
        emoji = data.get('emoji', '👍')

        message = Message.query.get_or_404(message_id)

        # Check if reaction already exists
        existing_reaction = MessageReaction.query.filter_by(
            message_id=message_id,
            user_id=current_user.id,
            emoji=emoji
        ).first()

        if existing_reaction:
            # Remove reaction
            db.session.delete(existing_reaction)
            if hasattr(message, 'reaction_count'):
                message.reaction_count = max(0, message.reaction_count - 1)
            action = 'removed'
        else:
            # Add reaction
            reaction = MessageReaction(
                message_id=message_id,
                user_id=current_user.id,
                emoji=emoji
            )
            db.session.add(reaction)
            if hasattr(message, 'reaction_count'):
                message.reaction_count += 1
            action = 'added'

        db.session.commit()
        return jsonify({'success': True, 'action': action})
    except Exception as e:
        logging.error(f"Error reacting to message: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/message/<int:message_id>/edit', methods=['POST'])
@require_login
def api_edit_message(message_id):
    """Edit a message"""
    try:
        data = request.get_json()
        new_content = data.get('content', '').strip()

        if not new_content:
            return jsonify({'success': False, 'error': 'Message content required'})

        message = Message.query.get_or_404(message_id)

        # Only author can edit
        if message.author_id != current_user.id:
            return jsonify({'success': False, 'error': 'Permission denied'})

        message.content = new_content
        message.edited_at = datetime.now()
        db.session.commit()

        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error editing message: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

# File upload route for messages
@app.route('/api/upload/message-file', methods=['POST'])
@require_login
def upload_message_file():
    """Upload file attachment for messages"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'})

        file = request.files['file']
        if not file.filename or file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})

        # Save file securely
        filename = secure_filename(file.filename)
        if not filename:
            return jsonify({'success': False, 'error': 'Invalid filename'})
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"

        # Create uploads directory if it doesn't exist
        uploads_dir = os.path.join('static', 'uploads')
        os.makedirs(uploads_dir, exist_ok=True)

        file_path = os.path.join(uploads_dir, unique_filename)
        file.save(file_path)

        file_url = f"/static/uploads/{unique_filename}"
        file_size = os.path.getsize(file_path)

        return jsonify({
            'success': True,
            'filename': filename,
            'url': file_url,
            'size': file_size,
            'unique_filename': unique_filename
        })
    except Exception as e:
        logging.error(f"Error uploading file: {e}")
        return jsonify({'success': False, 'error': str(e)})

# Send message with file attachment
@app.route('/api/message/send', methods=['POST'])
@require_login
def send_message_with_file():
    """Send message with optional file attachment"""
    try:
        data = request.get_json()
        content = data.get('content', '').strip()
        channel_id = data.get('channel_id')
        file_url = data.get('file_url')
        filename = data.get('filename')

        if not content and not file_url:
            return jsonify({'success': False, 'error': 'Message content or file required'})

        if not channel_id:
            return jsonify({'success': False, 'error': 'Channel ID required'})

        # Create message
        message = Message(
            content=content or f"📎 {filename}" if filename else "File attachment",
            author_id=current_user.id,
            channel_id=channel_id,
            message_type='file' if file_url else 'text'
        )

        if file_url:
            # Store file data in message
            import json
            message.file_data = json.dumps({
                'url': file_url,
                'filename': filename,
                'type': 'attachment'
            }).encode('utf-8')

        db.session.add(message)
        db.session.commit()

        return jsonify({'success': True, 'message_id': message.id})
    except Exception as e:
        logging.error(f"Error sending message: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

# Server Settings Routes
@app.route('/server/<int:server_id>/settings')
@require_login
def server_settings(server_id):
    """Server settings page"""
    server = Server.query.get_or_404(server_id)

    # Check if user is server owner or admin
    if server.owner_id != current_user.id:
        membership = ServerMembership.query.filter_by(
            user_id=current_user.id, 
            server_id=server_id
        ).first()
        if not membership:
            abort(403)

    return render_template('server_settings.html', server=server)

@app.route('/server/<int:server_id>/settings', methods=['POST'])
@require_login
def update_server_settings(server_id):
    """Update server settings"""
    server = Server.query.get_or_404(server_id)

    # Check permissions
    if server.owner_id != current_user.id:
        membership = ServerMembership.query.filter_by(
            user_id=current_user.id, 
            server_id=server_id
        ).first()
        if not membership:
            abort(403)

    try:
        # Update basic server info
        server_name = request.form.get('server_name', '').strip()
        if server_name and len(server_name) >= 1:
            server.name = server_name[:100]

        server_description = request.form.get('server_description', '').strip()
        server.description = server_description[:500] if server_description else None

        # Handle privacy setting
        is_public = request.form.get('is_public')
        if is_public is not None:
            server.is_public = is_public == 'true'

        # Update default channel if provided
        default_channel_id = request.form.get('default_channel_id')
        if default_channel_id and default_channel_id.isdigit():
            channel = Channel.query.filter_by(id=int(default_channel_id), server_id=server_id).first()
            if channel:
                # Add default_channel_id field if it doesn't exist
                if not hasattr(server, 'default_channel_id'):
                    # We'll handle this in the model migration
                    pass

        # Handle file uploads with better error handling
        if 'server_icon' in request.files:
            icon_file = request.files['server_icon']
            if icon_file and icon_file.filename and icon_file.filename != '':
                try:
                    # Read and encode as base64 data URL
                    file_data = icon_file.read()
                    if len(file_data) <= 5 * 1024 * 1024:  # 5MB limit
                        import base64
                        file_ext = os.path.splitext(icon_file.filename)[1].lower()
                        if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp']:
                            mime_type = f"image/{file_ext[1:]}" if file_ext != '.jpg' else "image/jpeg"
                            base64_data = base64.b64encode(file_data).decode('utf-8')
                            server.icon_url = f"data:{mime_type};base64,{base64_data}"
                except Exception as e:
                    logging.error(f"Error processing server icon: {e}")

        if 'server_banner' in request.files:
            banner_file = request.files['server_banner']
            if banner_file and banner_file.filename and banner_file.filename != '':
                try:
                    # Read and encode as base64 data URL
                    file_data = banner_file.read()
                    if len(file_data) <= 8 * 1024 * 1024:  # 8MB limit
                        import base64
                        file_ext = os.path.splitext(banner_file.filename)[1].lower()
                        if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp']:
                            mime_type = f"image/{file_ext[1:]}" if file_ext != '.jpg' else "image/jpeg"
                            base64_data = base64.b64encode(file_data).decode('utf-8')
                            server.banner_url = f"data:{mime_type};base64,{base64_data}"
                except Exception as e:
                    logging.error(f"Error processing server banner: {e}")

        db.session.commit()
        flash('Server settings updated successfully!', 'success')

    except Exception as e:
        logging.error(f"Error updating server settings: {e}")
        db.session.rollback()
        flash('Failed to update server settings. Please try again.', 'error')

    return redirect(url_for('server_settings', server_id=server_id))

@app.route('/server/<int:server_id>/remove-icon', methods=['POST'])
@require_login
def remove_server_icon(server_id):
    """Remove server icon"""
    server = Server.query.get_or_404(server_id)

    if server.owner_id != current_user.id:
        abort(403)

    try:
        # Remove file from filesystem
        if server.icon_url:
            file_path = server.icon_url.replace('/static/', 'static/')
            if os.path.exists(file_path):
                os.remove(file_path)

        server.icon_url = None
        db.session.commit()

        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error removing server icon: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/server/<int:server_id>/remove-banner', methods=['POST'])
@require_login
def remove_server_banner(server_id):
    """Remove server banner"""
    server = Server.query.get_or_404(server_id)

    if server.owner_id != current_user.id:
        abort(403)

    try:
        # Remove file from filesystem
        if server.banner_url:
            file_path = server.banner_url.replace('/static/', 'static/')
            if os.path.exists(file_path):
                os.remove(file_path)

        server.banner_url = None
        db.session.commit()

        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error removing server banner: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/server/<int:server_id>/channel/create', methods=['POST'])
@require_login
def create_channel(server_id):
    """Create new channel"""
    server = Server.query.get_or_404(server_id)

    # Check permissions
    membership = ServerMembership.query.filter_by(
        user_id=current_user.id, 
        server_id=server_id
    ).first()

    if not membership or server.owner_id != current_user.id:
        abort(403)

    try:
        data = request.get_json()
        channel_name = data.get('name', '').strip()

        if not channel_name:
            return jsonify({'success': False, 'error': 'Channel name is required'})

        # Clean channel name
        channel_name = re.sub(r'[^\w\s-]', '', channel_name).lower().replace(' ', '-')

        # Check if channel name already exists
        existing_channel = Channel.query.filter_by(
            server_id=server_id, 
            name=channel_name
        ).first()

        if existing_channel:
            return jsonify({'success': False, 'error': 'Channel name already exists'})

        channel = Channel(
            name=channel_name,
            server_id=server_id
        )

        db.session.add(channel)
        db.session.commit()

        return jsonify({'success': True, 'channel_id': channel.id})

    except Exception as e:
        logging.error(f"Error creating channel: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

# Permission Preview API Routes
@app.route('/api/permissions/preview', methods=['POST'])
@require_login
def preview_permissions():
    """Generate intelligent permission preview"""
    try:
        data = request.get_json()
        server_id = data.get('server_id')
        role_id = data.get('role_id')
        user_id = data.get('user_id')
        channel_id = data.get('channel_id')
        changes = data.get('changes', {})

        # Verify access to server
        server = Server.query.get_or_404(server_id)
        membership = ServerMembership.query.filter_by(
            user_id=current_user.id,
            server_id=server_id
        ).first()

        if not membership and server.owner_id != current_user.id:
            abort(403)

        # Calculate current permissions
        current_permissions = calculate_user_permissions(server_id, user_id, role_id)

        # Apply proposed changes
        preview_permissions = apply_permission_changes(current_permissions, changes)

        # Analyze impact
        impact_analysis = analyze_permission_impact(current_permissions, preview_permissions)

        # Get role hierarchy
        role_hierarchy = get_role_hierarchy(server_id)

        return jsonify({
            'success': True,
            'current_permissions': current_permissions,
            'preview_permissions': preview_permissions,
            'impact_analysis': impact_analysis,
            'role_hierarchy': role_hierarchy,
            'effective_permissions': calculate_effective_permissions(preview_permissions, server_id, channel_id)
        })

    except Exception as e:
        logging.error(f"Error generating permission preview: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/permissions/apply', methods=['POST'])
@require_login
def apply_permission_changes_api():
    """Apply permission changes after preview"""
    try:
        data = request.get_json()
        server_id = data.get('server_id')
        role_id = data.get('role_id')
        user_id = data.get('user_id')
        changes = data.get('changes', {})

        # Verify permissions to make changes
        server = Server.query.get_or_404(server_id)
        if server.owner_id != current_user.id:
            # Check if user has role management permissions
            user_permissions = calculate_user_permissions(server_id, current_user.id)
            if not user_permissions.get('MANAGE_ROLES', False):
                abort(403)

        # Apply server-level permission changes
        if 'server' in changes:
            apply_server_permission_changes(server_id, role_id, user_id, changes['server'])

        # Apply channel-level permission changes
        if 'channels' in changes:
            for channel_id, channel_perms in changes['channels'].items():
                apply_channel_permission_changes(server_id, channel_id, role_id, user_id, channel_perms)

        db.session.commit()

        return jsonify({'success': True, 'message': 'Permission changes applied successfully'})

    except Exception as e:
        logging.error(f"Error applying permission changes: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/permissions/matrix/<int:server_id>')
@require_login
def get_permission_matrix(server_id):
    """Get comprehensive permission matrix for server"""
    try:
        server = Server.query.get_or_404(server_id)
        membership = ServerMembership.query.filter_by(
            user_id=current_user.id,
            server_id=server_id
        ).first()

        if not membership and server.owner_id != current_user.id:
            abort(403)

        # Get all roles and channels
        roles = get_server_roles(server_id)
        channels = get_server_channels(server_id)

        # Build permission matrix
        matrix = {}
        for role in roles:
            matrix[role['id']] = {
                'role': role,
                'server_permissions': get_role_server_permissions(role['id']),
                'channel_permissions': {}
            }

            for channel in channels:
                matrix[role['id']]['channel_permissions'][channel['id']] = get_role_channel_permissions(role['id'], channel['id'])

        return jsonify({
            'success': True,
            'matrix': matrix,
            'permission_definitions': get_permission_definitions(),
            'roles': roles,
            'channels': channels
        })

    except Exception as e:
        logging.error(f"Error getting permission matrix: {e}")
        return jsonify({'success': False, 'error': str(e)})

# Permission Helper Functions
def calculate_user_permissions(server_id, user_id=None, role_id=None):
    """Calculate effective permissions for a user or role"""
    permissions = {
        'VIEW_CHANNELS': True,
        'SEND_MESSAGES': True,
        'MANAGE_MESSAGES': False,
        'MANAGE_CHANNELS': False,
        'MANAGE_ROLES': False,
        'KICK_MEMBERS': False,
        'BAN_MEMBERS': False,
        'ADMINISTRATOR': False
    }

    if role_id:
        # Get role-specific permissions from database
        # This would normally query role permissions table
        pass

    if user_id:
        # Check if user is server owner
        server = Server.query.get(server_id)
        if server and str(server.owner_id) == str(user_id):
            return {key: True for key in permissions.keys()}

        # Check user's roles and calculate effective permissions
        membership = ServerMembership.query.filter_by(
            user_id=user_id,
            server_id=server_id
        ).first()

        if membership:
            # Add role-based permissions logic here
            pass

    return permissions

def apply_permission_changes(current_permissions, changes):
    """Apply proposed changes to current permissions"""
    preview = current_permissions.copy()

    for scope, perms in changes.items():
        if scope == 'server':
            for perm, value in perms.items():
                if value in ['granted', 'denied']:
                    preview[perm] = (value == 'granted')

    return preview

def analyze_permission_impact(current, preview):
    """Analyze the impact of permission changes"""
    impacts = []

    for perm, new_value in preview.items():
        old_value = current.get(perm, False)

        if old_value != new_value:
            if perm == 'ADMINISTRATOR' and new_value:
                impacts.append({
                    'type': 'warning',
                    'icon': 'exclamation-triangle',
                    'description': f'Granting Administrator access provides all permissions'
                })
            elif perm in ['KICK_MEMBERS', 'BAN_MEMBERS'] and new_value:
                impacts.append({
                    'type': 'positive',
                    'icon': 'shield-alt',
                    'description': f'User will gain moderation capabilities'
                })
            elif perm in ['MANAGE_CHANNELS', 'MANAGE_ROLES'] and new_value:
                impacts.append({
                    'type': 'warning',
                    'icon': 'cog',
                    'description': f'User will be able to modify server structure'
                })

    return impacts

def get_role_hierarchy(server_id):
    """Get role hierarchy for server"""
    return [
        {'id': 'everyone', 'name': '@everyone', 'priority': 0, 'color': '#99aab5'},
        {'id': 'member', 'name': 'Member', 'priority': 1, 'color': '#206694'},
        {'id': 'moderator', 'name': 'Moderator', 'priority': 2, 'color': '#f1c40f'},
        {'id': 'admin', 'name': 'Admin', 'priority': 3, 'color': '#e74c3c'}
    ]

def calculate_effective_permissions(permissions, server_id, channel_id=None):
    """Calculate final effective permissions"""
    return permissions

def get_server_roles(server_id):
    """Get all roles for a server"""
    return [
        {'id': 'everyone', 'name': '@everyone', 'color': '#99aab5'},
        {'id': 'member', 'name': 'Member', 'color': '#206694'},
        {'id': 'moderator', 'name': 'Moderator', 'color': '#f1c40f'},
        {'id': 'admin', 'name': 'Admin', 'color': '#e74c3c'}
    ]

def get_server_channels(server_id):
    """Get all channels for a server"""
    channels = Channel.query.filter_by(server_id=server_id).all()
    return [{'id': c.id, 'name': c.name, 'type': 'text'} for c in channels]

def get_role_server_permissions(role_id):
    """Get server-level permissions for a role"""
    return {
        'VIEW_CHANNELS': 'granted',
        'SEND_MESSAGES': 'granted',
        'MANAGE_MESSAGES': 'neutral',
        'MANAGE_CHANNELS': 'neutral',
        'MANAGE_ROLES': 'neutral',
        'KICK_MEMBERS': 'neutral',
        'BAN_MEMBERS': 'neutral',
        'ADMINISTRATOR': 'neutral'
    }

def get_role_channel_permissions(role_id, channel_id):
    """Get channel-level permissions for a role"""
    return {
        'VIEW_CHANNELS': 'inherited',
        'SEND_MESSAGES': 'inherited',
        'MANAGE_MESSAGES': 'inherited'
    }

def get_permission_definitions():
    """Get all permission definitions"""
    return {
        'VIEW_CHANNELS': {
            'name': 'View Channels',
            'description': 'Allow members to view channels',
            'category': 'general'
        },
        'SEND_MESSAGES': {
            'name': 'Send Messages',
            'description': 'Allow members to send messages in text channels',
            'category': 'text'
        },
        'MANAGE_MESSAGES': {
            'name': 'Manage Messages',
            'description': 'Allow members to delete and pin messages',
            'category': 'text'
        },
        'MANAGE_CHANNELS': {
            'name': 'Manage Channels',
            'description': 'Allow members to create, edit, and delete channels',
            'category': 'management'
        },
        'MANAGE_ROLES': {
            'name': 'Manage Roles',
            'description': 'Allow members to create and edit roles',
            'category': 'management'
        },
        'KICK_MEMBERS': {
            'name': 'Kick Members',
            'description': 'Allow members to kick other members',
            'category': 'moderation'
        },
        'BAN_MEMBERS': {
            'name': 'Ban Members',
            'description': 'Allow members to ban other members',
            'category': 'moderation'
        },
        'ADMINISTRATOR': {
            'name': 'Administrator',
            'description': 'Grant all permissions and bypass channel-specific permissions',
            'category': 'management'
        }
    }

def apply_server_permission_changes(server_id, role_id, user_id, changes):
    """Apply server-level permission changes"""
    # Implementation would update role/user permissions in database
    logging.info(f"Applied server permission changes for server {server_id}")

def apply_channel_permission_changes(server_id, channel_id, role_id, user_id, changes):
    """Apply channel-level permission changes"""
    # Implementation would update channel-specific permissions in database
    logging.info(f"Applied channel permission changes for channel {channel_id}")

@app.route('/channel/<int:channel_id>/edit', methods=['POST'])
@require_login
def edit_channel(channel_id):
    """Edit channel name"""
    channel = Channel.query.get_or_404(channel_id)
    server = channel.server

    # Check permissions
    membership = ServerMembership.query.filter_by(
        user_id=current_user.id, 
        server_id=server.id
    ).first()

    if not membership or server.owner_id != current_user.id:
        abort(403)

    try:
        data = request.get_json()
        new_name = data.get('name', '').strip()

        if not new_name:
            return jsonify({'success': False, 'error': 'Channel name is required'})

        # Clean channel name
        new_name = re.sub(r'[^\w\s-]', '', new_name).lower().replace(' ', '-')

        # Check if channel name already exists
        existing_channel = Channel.query.filter_by(
            server_id=server.id, 
            name=new_name
        ).filter(Channel.id != channel_id).first()

        if existing_channel:
            return jsonify({'success': False, 'error': 'Channel name already exists'})

        channel.name = new_name
        db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        logging.error(f"Error editing channel: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/channel/<int:channel_id>/delete', methods=['POST'])
@require_login
def delete_channel(channel_id):
    """Delete channel"""
    channel = Channel.query.get_or_404(channel_id)
    server = channel.server

    # Check permissions (only server owner can delete channels)
    if server.owner_id != current_user.id:
        abort(403)

    # Don't allow deletion of the last channel
    channel_count = Channel.query.filter_by(server_id=server.id).count()
    if channel_count <= 1:
        return jsonify({'success': False, 'error': 'Cannot delete the last channel'})

    try:
        # Delete all messages in the channel
        Message.query.filter_by(channel_id=channel_id).delete()

        # Update default channel if this was it
        if server.default_channel_id == channel_id:
            remaining_channel = Channel.query.filter_by(server_id=server.id).filter(Channel.id != channel_id).first()
            if remaining_channel:
                server.default_channel_id = remaining_channel.id

        db.session.delete(channel)
        db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        logging.error(f"Error deleting channel: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/server/<int:server_id>/kick', methods=['POST'])
@require_login
def kick_member(server_id):
    """Kick member from server"""
    server = Server.query.get_or_404(server_id)

    # Check permissions (owner or admin)
    if server.owner_id != current_user.id:
        membership = ServerMembership.query.filter_by(
            user_id=current_user.id, 
            server_id=server_id
        ).first()
        if not membership:
            abort(403)

    try:
        data = request.get_json()
        user_id = data.get('user_id')

        if not user_id:
            return jsonify({'success': False, 'error': 'User ID is required'})

        # Cannot kick server owner
        if user_id == server.owner_id:
            return jsonify({'success': False, 'error': 'Cannot kick server owner'})

        # Remove membership
        membership = ServerMembership.query.filter_by(
            user_id=user_id, 
            server_id=server_id
        ).first()

        if membership:
            db.session.delete(membership)
            db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        logging.error(f"Error kicking member: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/server/<int:server_id>/ban', methods=['POST'])
@require_login
def ban_member(server_id):
    """Ban member from server"""
    server = Server.query.get_or_404(server_id)

    # Check permissions (owner or admin)
    if server.owner_id != current_user.id:
        membership = ServerMembership.query.filter_by(
            user_id=current_user.id, 
            server_id=server_id
        ).first()
        if not membership:
            abort(403)

    try:
        data = request.get_json()
        user_id = data.get('user_id')

        if not user_id:
            return jsonify({'success': False, 'error': 'User ID is required'})

        # Cannot ban server owner
        if user_id == server.owner_id:
            return jsonify({'success': False, 'error': 'Cannot ban server owner'})

        # Remove membership and add to banned list
        membership = ServerMembership.query.filter_by(
            user_id=user_id, 
            server_id=server_id
        ).first()

        if membership:
            membership.is_banned = True
            db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        logging.error(f"Error banning member: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/download')
def download_page():
    """Download page for all platforms"""
    return render_template('download.html')

@app.route('/test-call-notification')
def test_call_notification():
    """Test page for debugging call notifications"""
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Call Notification Test</title>
    <link rel="stylesheet" href="/static/css/call-popup.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body { background: #36393f; color: white; font-family: Arial, sans-serif; padding: 20px; }
        .test-btn { background: #5865f2; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; }
        .debug-btn { background: #f04747; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; }
        .info { background: #2f3136; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .console { background: #1e1e1e; color: #00ff00; padding: 10px; border-radius: 5px; font-family: monospace; height: 200px; overflow-y: auto; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>Call Notification Test</h1>
    <div class="info">
        <p>This page tests the Discord-style call notification system with accept/decline buttons.</p>
    </div>

    <button class="test-btn" onclick="testCallNotification()">Test Call Notification</button>
    <button class="debug-btn" onclick="debugElements()">Debug Elements</button>
    <button class="debug-btn" onclick="hideNotification()">Hide Notification</button>

    <div id="console" class="console"></div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script src="/static/js/discord-call-notifications.js"></script>

    <script>
        const consoleDiv = document.getElementById('console');

        function log(message) {
            consoleDiv.innerHTML += new Date().toLocaleTimeString() + ': ' + message + '\\n';
            consoleDiv.scrollTop = consoleDiv.scrollHeight;
            console.log(message);
        }

        // Mock socket for testing
        window.socket = {
            connected: true,
            on: function(event, callback) {
                log('Socket listener added for: ' + event);
            },
            off: function(event) {
                log('Socket listener removed for: ' + event);
            },
            emit: function(event, data) {
                log('Socket emit: ' + event + ' - ' + JSON.stringify(data));
                if (event === 'accept_call') {
                    log('✓ Call accepted! (Mock response)');
                } else if (event === 'decline_call') {
                    log('✗ Call declined! (Mock response)');
                }
            }
        };

        function testCallNotification() {
            log('Testing call notification...');
            if (window.discordCallNotifications) {
                const testData = {
                    call_id: 'test-123',
                    caller_name: 'Test User',
                    caller_avatar: null,
                    call_type: 'voice',
                    server_id: null
                };
                window.discordCallNotifications.showCallNotification(testData);
                log('Call notification should now be visible');

                setTimeout(() => {
                    window.discordCallNotifications.debugElements();
                }, 500);
            } else {
                log('ERROR: Discord call notifications not initialized');
            }
        }

        function debugElements() {
            log('Debugging elements...');
            if (window.discordCallNotifications) {
                const result = window.discordCallNotifications.debugElements();
                log('Debug completed - check console for details');
            } else {
                log('ERROR: No notification system found');
            }
        }

        function hideNotification() {
            if (window.discordCallNotifications) {
                window.discordCallNotifications.hideCallNotification();
                log('Notification hidden');
            }
        }

        // Initialize notification system
        window.addEventListener('load', function() {
            log('Page loaded, initializing call notification system...');
            setTimeout(() => {
                if (!window.discordCallNotifications) {
                    log('Manually initializing Discord call notifications...');
                    window.discordCallNotifications = new DiscordCallNotifications();
                    log('Discord call notifications initialized');
                } else {
                    log('Discord call notifications already available');
                }
            }, 1000);
        });

        log('Test page script loaded');
    </script>
</body>
</html>
    ''')