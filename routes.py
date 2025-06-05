from flask import session, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user, login_user
from app import app, db, limiter
from replit_auth import require_login, make_replit_blueprint
from models import User, Server, Channel, Message, DirectMessage, ServerMembership, Call, CallMessage, Voicemail
from datetime import datetime
import bleach
import hashlib
import uuid
from sqlalchemy.exc import SQLAlchemyError

app.register_blueprint(make_replit_blueprint(), url_prefix="/auth")

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
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('splash.html')

@app.route('/landing')
def landing():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def custom_login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
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
            user_id = str(uuid.uuid4())
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            user = User(
                id=user_id,
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password_hash=password_hash
            )
            
            db.session.add(user)
            db.session.commit()
            
            # Auto-add to public servers
            auto_add_user_to_servers(user)
            
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
@limiter.limit("5 per minute")
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
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    if hasattr(user, 'password_hash') and user.password_hash == password_hash:
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
                         is_owner=is_owner)

@app.route('/server/<int:server_id>/send_message', methods=['POST'])
@require_login
@limiter.limit("30 per minute")
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
@limiter.limit("5 per hour")
def create_server():
    name = sanitize_input(request.form.get('server_name', ''), max_length=100)
    description = sanitize_input(request.form.get('server_description', ''), max_length=500)
    
    if not name or len(name.strip()) < 3:
        flash('Server name must be at least 3 characters long.', 'error')
        return redirect(url_for('home'))
    
    if len(name) > 100:
        flash('Server name is too long. Maximum 100 characters allowed.', 'error')
        return redirect(url_for('home'))
    
    try:
        server = Server(
            name=name,
            description=description,
            owner_id=current_user.id
        )
        db.session.add(server)
        db.session.flush()  # Get server ID before committing
        
        # Create default general channel
        channel = Channel(name='general', server_id=server.id)
        db.session.add(channel)
        db.session.commit()
        
        flash(f'Server "{name}" created successfully!', 'success')
        return redirect(url_for('server_view', server_id=server.id))
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.error(f"Error creating server: {e}")
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
    # Get all users who have had conversations with current user
    conversations = db.session.query(User).join(
        DirectMessage,
        (DirectMessage.sender_id == User.id) | (DirectMessage.recipient_id == User.id)
    ).filter(
        (DirectMessage.sender_id == current_user.id) | (DirectMessage.recipient_id == current_user.id),
        User.id != current_user.id
    ).distinct().all()
    
    # Get all users for potential new conversations
    all_users = User.query.filter(User.id != current_user.id).all()
    
    return render_template('direct_messages.html', 
                         conversations=conversations, 
                         all_users=all_users)

@app.route('/dm/<user_id>')
@require_login
def dm_conversation(user_id):
    other_user = User.query.get_or_404(user_id)
    
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
    
    return render_template('direct_messages.html', 
                         other_user=other_user, 
                         messages=messages,
                         all_users=User.query.filter(User.id != current_user.id).all())

@app.route('/send_dm/<user_id>', methods=['POST'])
@require_login
def send_dm(user_id):
    other_user = User.query.get_or_404(user_id)
    content = request.form.get('message', '').strip()
    
    if not content:
        flash('Message cannot be empty.', 'error')
        return redirect(url_for('dm_conversation', user_id=user_id))
    
    dm = DirectMessage(
        content=content,
        sender_id=current_user.id,
        recipient_id=user_id
    )
    db.session.add(dm)
    db.session.commit()
    
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
        flash('You already have an active call.', 'error')
        return redirect(url_for('dm_conversation', user_id=user_id))
    
    call = Call(
        caller_id=current_user.id,
        recipient_id=user_id,
        call_type=call_type,
        status='pending'
    )
    db.session.add(call)
    db.session.commit()
    
    return render_template('call.html', 
                         call=call, 
                         other_user=other_user, 
                         is_caller=True)

@app.route('/join_call/<int:call_id>')
@require_login
def join_call(call_id):
    call = Call.query.get_or_404(call_id)
    
    if call.recipient_id != current_user.id:
        flash('You are not authorized to join this call.', 'error')
        return redirect(url_for('home'))
    
    if call.status != 'pending':
        flash('This call is no longer available.', 'error')
        return redirect(url_for('home'))
    
    call.status = 'active'
    db.session.commit()
    
    other_user = User.query.get(call.caller_id)
    return render_template('call.html', 
                         call=call, 
                         other_user=other_user, 
                         is_caller=False)

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
        
        # Handle custom profile image URL
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
    public_servers = Server.query.filter_by(is_public=True).all()
    for server in public_servers:
        existing_membership = ServerMembership.query.filter_by(
            user_id=user.id, 
            server_id=server.id
        ).first()
        
        if not existing_membership:
            membership = ServerMembership(user_id=user.id, server_id=server.id)
            db.session.add(membership)
    
    db.session.commit()

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
