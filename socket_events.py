from flask_socketio import emit, join_room, leave_room, disconnect
from flask_login import current_user
from app import socketio, db
from models import Call, Message, DirectMessage, MessageReadStatus, User, Channel, Server
from contact_manager import can_message_contact
from datetime import datetime
import logging
import uuid

# Store typing users for cleanup
typing_users = {}

# Store active calls for Discord-like call system
active_calls = {}

# Discord-style call notification events
@socketio.on('initiate_call')
def on_initiate_call(data):
    """Handle Discord-style call initiation with notifications"""
    if not current_user.is_authenticated:
        disconnect()
        return
    
    try:
        recipient_id = data.get('recipient_id')
        call_type = data.get('call_type', 'voice')  # voice or video
        server_id = data.get('server_id')
        
        if not recipient_id:
            emit('call_error', {'error': 'No recipient specified'})
            return
        
        # Check if recipient exists
        recipient = User.query.get(recipient_id)
        if not recipient:
            emit('call_error', {'error': 'User not found'})
            return
        
        # Check if user can call this contact
        if not can_message_contact(current_user.id, recipient_id):
            emit('call_error', {'error': 'You do not have permission to call this user'})
            return
        
        # Create call record
        call = Call()
        call.caller_id = current_user.id
        call.recipient_id = recipient_id
        call.call_type = call_type
        call.status = 'ringing'
        call.started_at = datetime.now()
        if server_id:
            call.server_id = server_id
        
        db.session.add(call)
        db.session.flush()
        call_id = call.id
        db.session.commit()
        
        # Store in active calls
        active_calls[call_id] = {
            'call_id': call_id,
            'caller_id': current_user.id,
            'recipient_id': recipient_id,
            'call_type': call_type,
            'server_id': server_id,
            'status': 'ringing',
            'created_at': datetime.now()
        }
        
        # Send Discord-style notification to recipient
        call_notification = {
            'call_id': call_id,
            'caller_id': current_user.id,
            'caller_name': current_user.username or current_user.first_name or f"User {current_user.id}",
            'caller_avatar': current_user.profile_image_url,
            'call_type': call_type,
            'server_id': server_id
        }
        
        emit('incoming_call', call_notification, to=f"user_{recipient_id}")
        emit('call_initiated', {'call_id': call_id, 'status': 'ringing'})
        
        # Auto-timeout after 30 seconds
        def timeout_call():
            socketio.sleep(30)
            if call_id in active_calls and active_calls[call_id]['status'] == 'ringing':
                active_calls[call_id]['status'] = 'timeout'
                # Update database
                call_record = Call.query.get(call_id)
                if call_record:
                    call_record.status = 'missed'
                    call_record.ended_at = datetime.now()
                    db.session.commit()
                
                # Notify caller about timeout and voicemail option
                socketio.emit('call_timeout', {
                    'call_id': call_id,
                    'message': 'Your call has not been picked so now you can record your voicemail'
                }, to=f"user_{current_user.id}")
                
                # Remove from active calls
                if call_id in active_calls:
                    del active_calls[call_id]
        
        socketio.start_background_task(timeout_call)
        
        logging.info(f"Discord-style call initiated: {current_user.id} -> {recipient_id}")
        
    except Exception as e:
        logging.error(f"Error initiating call: {e}")
        db.session.rollback()
        emit('call_error', {'error': 'Failed to initiate call'})

@socketio.on('accept_call')
def on_accept_call(data):
    """Handle Discord-style call acceptance"""
    if not current_user.is_authenticated:
        disconnect()
        return
    
    try:
        call_id = data.get('call_id')
        if not call_id:
            return
        
        call = Call.query.get(call_id)
        if not call or call.recipient_id != current_user.id:
            emit('call_error', {'error': 'Invalid call'})
            return
        
        # Update call status
        call.status = 'active'
        call.answered_at = datetime.now()
        db.session.commit()
        
        # Update active calls
        if call_id in active_calls:
            active_calls[call_id]['status'] = 'active'
        
        # Notify both parties
        emit('call_accepted', {'call_id': call_id}, to=f"user_{call.caller_id}")
        emit('call_accepted', {'call_id': call_id})
        
        logging.info(f"Call accepted: {call_id}")
        
    except Exception as e:
        logging.error(f"Error accepting call: {e}")
        emit('call_error', {'error': 'Failed to accept call'})

@socketio.on('decline_call')
def on_decline_call(data):
    """Handle Discord-style call decline"""
    if not current_user.is_authenticated:
        disconnect()
        return
    
    try:
        call_id = data.get('call_id')
        if not call_id:
            return
        
        call = Call.query.get(call_id)
        if not call or call.recipient_id != current_user.id:
            emit('call_error', {'error': 'Invalid call'})
            return
        
        # Update call status
        call.status = 'declined'
        call.ended_at = datetime.now()
        db.session.commit()
        
        # Remove from active calls
        if call_id in active_calls:
            del active_calls[call_id]
        
        # Notify caller
        emit('call_declined', {'call_id': call_id}, to=f"user_{call.caller_id}")
        emit('call_declined', {'call_id': call_id})
        
        logging.info(f"Call declined: {call_id}")
        
    except Exception as e:
        logging.error(f"Error declining call: {e}")
        emit('call_error', {'error': 'Failed to decline call'})

@socketio.on('end_call')
def on_end_call(data):
    """Handle Discord-style call ending"""
    if not current_user.is_authenticated:
        disconnect()
        return
    
    try:
        call_id = data.get('call_id')
        if not call_id:
            return
        
        call = Call.query.get(call_id)
        if not call or (call.caller_id != current_user.id and call.recipient_id != current_user.id):
            emit('call_error', {'error': 'Invalid call'})
            return
        
        # Update call status
        call.status = 'ended'
        call.ended_at = datetime.now()
        db.session.commit()
        
        # Remove from active calls
        if call_id in active_calls:
            del active_calls[call_id]
        
        # Notify both parties
        other_user_id = call.recipient_id if call.caller_id == current_user.id else call.caller_id
        emit('call_ended', {'call_id': call_id}, to=f"user_{other_user_id}")
        emit('call_ended', {'call_id': call_id})
        
        logging.info(f"Call ended: {call_id}")
        
    except Exception as e:
        logging.error(f"Error ending call: {e}")
        emit('call_error', {'error': 'Failed to end call'})

@socketio.on('join_call')
def on_join_call(data):
    if not current_user.is_authenticated:
        disconnect()
        return
    
    try:
        call_id = data.get('call_id')
        if not call_id:
            return
        
        # Verify user has access to this call
        call = Call.query.get(call_id)
        if not call or (call.caller_id != current_user.id and call.recipient_id != current_user.id):
            disconnect()
            return
        
        join_room(f"call_{call_id}")
        emit('user_joined', {'user_id': current_user.id}, to=f"call_{call_id}")
    except Exception as e:
        logging.error(f"Error in join_call: {e}")
        disconnect()

@socketio.on('leave_call')
def on_leave_call(data):
    call_id = data['call_id']
    leave_room(f"call_{call_id}")
    emit('user_left', {'user_id': current_user.id}, to=f"call_{call_id}")

@socketio.on('webrtc_offer')
def on_webrtc_offer(data):
    if not current_user.is_authenticated:
        disconnect()
        return
    
    call_id = data.get('call_id')
    offer = data.get('offer')
    
    if call_id and offer:
        emit('webrtc_offer', {
            'call_id': call_id,
            'offer': offer,
            'sender_id': current_user.id
        }, to=f"call_{call_id}", include_self=False)

@socketio.on('webrtc_answer')
def on_webrtc_answer(data):
    if not current_user.is_authenticated:
        disconnect()
        return
    
    call_id = data.get('call_id')
    answer = data.get('answer')
    
    if call_id and answer:
        emit('webrtc_answer', {
            'call_id': call_id,
            'answer': answer,
            'sender_id': current_user.id
        }, to=f"call_{call_id}", include_self=False)

@socketio.on('webrtc_ice_candidate')
def on_webrtc_ice_candidate(data):
    if not current_user.is_authenticated:
        disconnect()
        return
    
    call_id = data.get('call_id')
    candidate = data.get('candidate')
    
    if call_id and candidate:
        emit('webrtc_ice_candidate', {
            'call_id': call_id,
            'candidate': candidate,
            'sender_id': current_user.id
        }, to=f"call_{call_id}", include_self=False)

# Message Status and Typing Events

@socketio.on('typing')
def on_typing(data):
    """Handle typing indicators"""
    if not current_user.is_authenticated:
        return
    
    channel_id = data.get('channel_id')
    if not channel_id:
        return
    
    emit('user_typing', {
        'user_id': current_user.id,
        'username': current_user.username,
        'channel_id': channel_id
    }, to=f"channel_{channel_id}", include_self=False)

@socketio.on('stop_typing')
def on_stop_typing(data):
    """Handle stop typing indicators"""
    if not current_user.is_authenticated:
        return
    
    channel_id = data.get('channel_id')
    if not channel_id:
        return
    
    emit('user_stopped_typing', {
        'user_id': current_user.id,
        'channel_id': channel_id
    }, to=f"channel_{channel_id}", include_self=False)

@socketio.on('mark_message_read')
def on_mark_message_read(data):
    """Mark message as read and update status"""
    if not current_user.is_authenticated:
        return
    
    try:
        message_id = data.get('message_id')
        message_type = data.get('type', 'channel')
        
        if not message_id:
            return
        
        now = datetime.now()
        
        if message_type == 'dm':
            dm = DirectMessage.query.get(message_id)
            if dm and dm.recipient_id == current_user.id and not dm.read_at:
                dm.read_at = now
                dm.status = 'read'
                db.session.commit()
                
                emit('message_status_update', {
                    'message_id': message_id,
                    'status': 'read',
                    'timestamp': now.isoformat(),
                    'read_by': [{
                        'user_id': current_user.id,
                        'username': current_user.username,
                        'avatar': current_user.profile_image_url
                    }]
                }, to=f"user_{dm.sender_id}")
                
        else:
            message = Message.query.get(message_id)
            if not message:
                return
            
            existing_read = MessageReadStatus.query.filter_by(
                message_id=message_id,
                user_id=current_user.id
            ).first()
            
            if not existing_read:
                read_status = MessageReadStatus()
                read_status.message_id = message_id
                read_status.user_id = current_user.id
                read_status.read_at = now
                db.session.add(read_status)
                
                read_by_users = db.session.query(MessageReadStatus, User).join(
                    User, MessageReadStatus.user_id == User.id
                ).filter(MessageReadStatus.message_id == message_id).all()
                
                read_by = [{
                    'user_id': user.id,
                    'username': user.username,
                    'avatar': user.profile_image_url
                } for _, user in read_by_users]
                
                if len(read_by) == 1 and message.status != 'read':
                    message.status = 'read'
                    message.read_at = now
                
                db.session.commit()
                
                emit('message_status_update', {
                    'message_id': message_id,
                    'status': 'read',
                    'timestamp': now.isoformat(),
                    'read_by': read_by
                }, to=f"channel_{message.channel_id}")
                
    except Exception as e:
        logging.error(f"Error marking message as read: {e}")
        db.session.rollback()

# Removed duplicate send_message handler

@socketio.on('send_dm')
def on_send_dm(data):
    """Handle sending direct messages"""
    if not current_user.is_authenticated:
        emit('dm_error', {'error': 'Not authenticated'})
        return
    
    try:
        content = data.get('content', '').strip()
        recipient_id = data.get('recipient_id')
        reply_to = data.get('reply_to')
        
        if not content or not recipient_id:
            emit('dm_error', {'error': 'Missing content or recipient'})
            return
        
        # Verify recipient exists
        recipient = User.query.get(recipient_id)
        if not recipient:
            emit('dm_error', {'error': 'Recipient not found'})
            return
        
        # Check if user can message this contact
        if not can_message_contact(current_user.id, recipient_id):
            emit('dm_error', {'error': 'You do not have permission to message this user'})
            return
        
        # Create new direct message
        dm = DirectMessage()
        dm.content = content
        dm.sender_id = current_user.id  # Use integer directly
        dm.recipient_id = int(recipient_id)  # Ensure it's an integer
        dm.status = 'sent'
        dm.created_at = datetime.now()
        
        db.session.add(dm)
        db.session.flush()  # Get the ID before committing
        db.session.commit()
        
        logging.info(f"DM created with ID: {dm.id} from {current_user.id} to {recipient_id}")
        
        # Create consistent room name for DM conversation
        user_ids = sorted([str(current_user.id), str(recipient_id)])
        dm_room = f"dm_{user_ids[0]}_{user_ids[1]}"
        
        # Broadcast message data
        message_data = {
            'id': dm.id,
            'content': dm.content,
            'sender_id': str(dm.sender_id),
            'sender_name': current_user.username or current_user.first_name or f'User {current_user.id}',
            'sender_avatar': current_user.profile_image_url,
            'recipient_id': str(dm.recipient_id),
            'reply_to_id': reply_to,
            'status': dm.status,
            'created_at': dm.created_at.isoformat(),
            'type': 'text'
        }
        
        print(f"[SOCKET] Emitting DM to rooms: {dm_room}, user_{recipient_id}, user_{current_user.id}")
        
        # Emit to DM conversation room and individual user rooms
        emit('new_dm', message_data, to=dm_room)
        emit('new_dm', message_data, to=f"user_{recipient_id}")
        emit('new_dm', message_data, to=f"user_{current_user.id}")
        
        # Confirm message was sent
        emit('dm_sent', {'message_id': dm.id, 'status': 'sent'})
        
    except Exception as e:
        logging.error(f"Error sending DM: {e}")
        db.session.rollback()
        emit('dm_error', {'error': 'Failed to send direct message'})

@socketio.on('join_channel')
def on_join_channel(data):
    """Join a channel room for real-time updates"""
    if not current_user.is_authenticated:
        print("[SOCKET] Unauthenticated user tried to join channel")
        return
    
    channel_id = data.get('channel_id')
    if channel_id:
        join_room(f"channel_{channel_id}")
        print(f"[SOCKET] User {current_user.id} joined channel {channel_id}")
        emit('joined_channel', {'channel_id': channel_id})

@socketio.on('join_user_room')
def on_join_user_room(data):
    """Join user room for direct messages"""
    if not current_user.is_authenticated:
        return
    
    join_room(f"user_{current_user.id}")
    emit('joined_user_room', {'user_id': current_user.id})

@socketio.on('join_dm_conversation')
def on_join_dm_conversation(data):
    """Join a specific DM conversation room"""
    if not current_user.is_authenticated:
        return
    
    other_user_id = data.get('other_user_id')
    if not other_user_id:
        return
    
    # Create consistent room name regardless of user order
    user_ids = sorted([str(current_user.id), str(other_user_id)])
    room = f"dm_{user_ids[0]}_{user_ids[1]}"
    join_room(room)
    print(f"[SOCKET] User {current_user.id} joined DM conversation: {room}")
    emit('joined_dm_conversation', {'room': room, 'other_user_id': other_user_id})

@socketio.on('upload_file')
def on_upload_file(data):
    """Handle file upload notification"""
    if not current_user.is_authenticated:
        return
    
    try:
        file_url = data.get('file_url')
        file_name = data.get('file_name')
        channel_id = data.get('channel_id')
        recipient_id = data.get('recipient_id')
        
        if not file_url or not file_name:
            return
        
        # Create file message
        content = f"📎 {file_name}"
        
        if channel_id:
            # Send to channel
            message = Message()
            message.content = content
            message.author_id = current_user.id
            message.channel_id = channel_id
            message.status = 'sent'
            message.created_at = datetime.now()
            message.file_url = file_url
            
            db.session.add(message)
            db.session.commit()
            
            message_data = {
                'id': message.id,
                'content': message.content,
                'author_id': message.author_id,
                'author_name': current_user.username,
                'author_avatar': current_user.profile_image_url,
                'channel_id': message.channel_id,
                'status': message.status,
                'created_at': message.created_at.isoformat(),
                'type': 'file',
                'file_url': file_url,
                'file_name': file_name
            }
            
            emit('new_message', message_data, to=f"channel_{channel_id}")
            
        elif recipient_id:
            # Send as DM
            dm = DirectMessage()
            dm.content = content
            dm.sender_id = current_user.id
            dm.recipient_id = recipient_id
            dm.status = 'sent'
            dm.created_at = datetime.now()
            
            db.session.add(dm)
            db.session.commit()
            
            message_data = {
                'id': dm.id,
                'content': dm.content,
                'sender_id': dm.sender_id,
                'sender_name': current_user.username,
                'sender_avatar': current_user.profile_image_url,
                'recipient_id': dm.recipient_id,
                'status': dm.status,
                'created_at': dm.created_at.isoformat(),
                'type': 'file',
                'file_url': file_url,
                'file_name': file_name
            }
            
            emit('new_dm', message_data, to=f"user_{recipient_id}")
            emit('new_dm', message_data, to=f"user_{current_user.id}")
            
    except Exception as e:
        logging.error(f"Error handling file upload: {e}")
        emit('message_error', {'error': 'Failed to send file'})

# Duplicate handler removed

@socketio.on('connect')
def on_connect():
    print(f"[SOCKET] Connect attempt - authenticated: {current_user.is_authenticated}")
    if current_user.is_authenticated:
        join_room(f"user_{current_user.id}")
        current_user.status = 'online'
        current_user.last_seen = datetime.now()
        db.session.commit()
        emit('connected', {'user_id': current_user.id})
        print(f"[SOCKET] User {current_user.id} connected successfully")
    else:
        print("[SOCKET] Unauthenticated connection attempt")

@socketio.on('disconnect')
def on_disconnect():
    if current_user.is_authenticated:
        # Clean up typing indicators
        keys_to_remove = [key for key in typing_users.keys() if key.startswith(f"{current_user.id}_")]
        for key in keys_to_remove:
            del typing_users[key]
            
        leave_room(f"user_{current_user.id}")
        current_user.status = 'away'
        current_user.last_seen = datetime.now()
        db.session.commit()
        emit('disconnected', {'user_id': current_user.id})
        logging.info(f"User {current_user.id} disconnected from socket")

@socketio.on('send_message')
def on_send_message(data):
    """Handle real-time message sending"""
    print(f"[SOCKET] Received send_message event: {data}")
    
    if not current_user.is_authenticated:
        print("[SOCKET] Unauthenticated user tried to send message")
        emit('message_error', {'error': 'Not authenticated'})
        return
    
    try:
        content = data.get('content', '').strip()
        channel_id = data.get('channel_id')
        message_type = data.get('type', 'text')
        
        print(f"[SOCKET] Message details - Content: {content}, Channel: {channel_id}, User: {current_user.id}")
        
        if not content or not channel_id:
            print(f"[SOCKET] Missing content or channel_id: content={content}, channel_id={channel_id}")
            emit('message_error', {'error': 'Missing content or channel'})
            return
        
        # Create message
        message = Message()
        message.content = content
        message.author_id = current_user.id
        message.channel_id = int(channel_id)
        message.message_type = message_type
        message.status = 'sent'
        message.created_at = datetime.now()
        db.session.add(message)
        db.session.commit()
        
        print(f"[SOCKET] Message saved with ID: {message.id}")
        
        # Emit to channel
        message_data = {
            'id': message.id,
            'content': message.content,
            'author_id': message.author_id,
            'author_name': current_user.username or f"User {current_user.id}",
            'author_avatar': current_user.profile_image_url,
            'channel_id': message.channel_id,
            'created_at': message.created_at.isoformat(),
            'message_type': message.message_type,
            'status': message.status
        }
        
        print(f"[SOCKET] Emitting message to channel_{channel_id}: {message_data}")
        emit('new_message', message_data, to=f"channel_{channel_id}")
        # Also emit to sender to confirm message was sent
        emit('message_sent', {'id': message.id, 'status': 'sent'})
        
    except Exception as e:
        print(f"[SOCKET] Error sending message: {e}")
        emit('message_error', {'error': 'Failed to send message'})

# Removed duplicate on_send_dm handler
        
    except Exception as e:
        logging.error(f"Error sending DM: {e}")
        emit('dm_error', {'error': 'Failed to send message'})

# Enhanced typing indicators and improved messaging
@socketio.on('typing_start')
def on_typing_start(data):
    if not current_user.is_authenticated:
        return
    
    try:
        channel_id = data.get('channel_id')
        recipient_id = data.get('recipient_id')
        
        user_info = {
            'user_id': current_user.id,
            'username': current_user.username or current_user.first_name or 'User',
            'avatar': current_user.profile_image_url
        }
        
        if channel_id:
            # Channel typing indicator
            channel = Channel.query.get(channel_id)
            if channel:
                server_id = channel.server_id
                room_name = f"channel_{channel_id}"
                typing_users[f"{current_user.id}_{channel_id}"] = datetime.now()
                emit('user_typing', user_info, to=room_name, include_self=False)
                
        elif recipient_id:
            # DM typing indicator
            room_name = f"user_{recipient_id}"
            typing_users[f"{current_user.id}_{recipient_id}"] = datetime.now()
            emit('user_typing_dm', user_info, to=room_name)
            
    except Exception as e:
        logging.error(f"Error in typing_start: {e}")

@socketio.on('typing_stop')
def on_typing_stop(data):
    if not current_user.is_authenticated:
        return
    
    try:
        channel_id = data.get('channel_id')
        recipient_id = data.get('recipient_id')
        
        user_info = {
            'user_id': current_user.id,
            'username': current_user.username or current_user.first_name or 'User'
        }
        
        if channel_id:
            # Channel typing stop
            room_name = f"channel_{channel_id}"
            key = f"{current_user.id}_{channel_id}"
            if key in typing_users:
                del typing_users[key]
            emit('user_stopped_typing', user_info, to=room_name, include_self=False)
            
        elif recipient_id:
            # DM typing stop
            room_name = f"user_{recipient_id}"
            key = f"{current_user.id}_{recipient_id}"
            if key in typing_users:
                del typing_users[key]
            emit('user_stopped_typing_dm', user_info, to=room_name)
            
    except Exception as e:
        logging.error(f"Error in typing_stop: {e}")

# Duplicate join_channel handler removed - using the one above

@socketio.on('leave_channel')
def on_leave_channel(data):
    if not current_user.is_authenticated:
        return
    
    try:
        channel_id = data.get('channel_id')
        if channel_id:
            leave_room(f"channel_{channel_id}")
            emit('user_left_channel', {
                'user_id': current_user.id,
                'username': current_user.username or current_user.first_name or 'User'
            }, to=f"channel_{channel_id}")
            
    except Exception as e:
        logging.error(f"Error leaving channel: {e}")

@socketio.on('message_reaction')
def on_message_reaction(data):
    if not current_user.is_authenticated:
        return
    
    try:
        message_id = data.get('message_id')
        emoji = data.get('emoji')
        action = data.get('action', 'add')  # 'add' or 'remove'
        
        if not message_id or not emoji:
            return
            
        # Handle reaction logic here
        reaction_data = {
            'message_id': message_id,
            'emoji': emoji,
            'user_id': current_user.id,
            'username': current_user.username or current_user.first_name or 'User',
            'action': action
        }
        
        # Emit to relevant room (channel or DM)
        message = Message.query.get(message_id)
        if message and message.channel_id:
            emit('reaction_updated', reaction_data, to=f"channel_{message.channel_id}")
        else:
            # For DM reactions
            dm = DirectMessage.query.get(message_id)
            if dm:
                emit('reaction_updated', reaction_data, to=f"user_{dm.sender_id}")
                emit('reaction_updated', reaction_data, to=f"user_{dm.recipient_id}")
                
    except Exception as e:
        logging.error(f"Error handling reaction: {e}")

@socketio.on('start_call')
def on_start_call(data):
    if not current_user.is_authenticated:
        return
    
    try:
        recipient_id = data.get('recipient_id')
        call_type = data.get('call_type', 'audio')
        
        if recipient_id:
            call_id = str(uuid.uuid4())
            
            # Store call info in active calls
            active_calls[call_id] = {
                'caller_id': current_user.id,
                'recipient_id': recipient_id,
                'call_type': call_type,
                'status': 'pending',
                'created_at': datetime.now()
            }
            
            # Auto-cleanup call after 30 seconds if not connected
            def cleanup_call():
                if call_id in active_calls and active_calls[call_id]['status'] == 'pending':
                    logging.info(f"Auto-cleaning up call {call_id} after 30 seconds")
                    
                    # Notify participants that call timed out
                    timeout_data = {
                        'call_id': call_id,
                        'status': 'timeout',
                        'message': 'Call timed out after 30 seconds'
                    }
                    
                    emit('call_timeout', timeout_data, to=f"user_{current_user.id}")
                    emit('call_timeout', timeout_data, to=f"user_{recipient_id}")
                    
                    # Remove from active calls
                    del active_calls[call_id]
            
            # Schedule cleanup after 30 seconds
            socketio.start_background_task(lambda: socketio.sleep(30) or cleanup_call())
            
            call_data = {
                'caller_id': current_user.id,
                'caller_name': current_user.username or current_user.first_name or 'User',
                'caller_avatar': current_user.profile_image_url,
                'call_type': call_type,
                'call_id': call_id
            }
            
            # Send Discord-like call popup to recipient
            emit('incoming_call', call_data, to=f"user_{recipient_id}")
            emit('call_initiated', call_data, to=f"user_{current_user.id}")
            
    except Exception as e:
        logging.error(f"Error starting call: {e}")

# Removed duplicate on_accept_call handler

# Removed duplicate on_decline_call handler

# Removed duplicate on_end_call handler

@socketio.on('force_end_call')
def on_force_end_call(data):
    """Force end call with immediate cleanup"""
    if not current_user.is_authenticated:
        return
    
    try:
        call_id = data.get('call_id')
        user_id = data.get('user_id', current_user.id)
        
        logging.info(f"Force ending call {call_id} by user {user_id}")
        
        # Remove from active calls immediately
        if call_id in active_calls:
            del active_calls[call_id]
        
        # Force cleanup notification
        call_data = {
            'call_id': call_id,
            'ended_by': user_id,
            'ended_by_name': current_user.username or current_user.first_name or 'User',
            'status': 'force_ended'
        }
        
        # Broadcast force end to all possible rooms
        emit('call_force_ended', call_data, broadcast=True)
        emit('call_ended', call_data, to=f"call_{call_id}")
            
    except Exception as e:
        logging.error(f"Error force ending call: {e}")

@socketio.on('screen_share_started')
def on_screen_share_started(data):
    """Handle screen share start notification"""
    if not current_user.is_authenticated:
        return
    
    try:
        call_id = data.get('call_id')
        user_id = data.get('user_id', current_user.id)
        
        if call_id in active_calls:
            call_info = active_calls[call_id]
            
            # Notify other participant
            share_data = {
                'call_id': call_id,
                'sharer_id': user_id,
                'sharer_name': current_user.username or current_user.first_name or 'User',
                'status': 'screen_sharing'
            }
            
            # Send to other participant
            if call_info['caller_id'] != current_user.id:
                emit('screen_share_started', share_data, to=f"user_{call_info['caller_id']}")
            if 'recipient_id' in call_info and call_info['recipient_id'] != current_user.id:
                emit('screen_share_started', share_data, to=f"user_{call_info['recipient_id']}")
                
    except Exception as e:
        logging.error(f"Error handling screen share start: {e}")

@socketio.on('screen_share_stopped')
def on_screen_share_stopped(data):
    """Handle screen share stop notification"""
    if not current_user.is_authenticated:
        return
    
    try:
        call_id = data.get('call_id')
        user_id = data.get('user_id', current_user.id)
        
        if call_id in active_calls:
            call_info = active_calls[call_id]
            
            # Notify other participant
            share_data = {
                'call_id': call_id,
                'sharer_id': user_id,
                'sharer_name': current_user.username or current_user.first_name or 'User',
                'status': 'stopped_sharing'
            }
            
            # Send to other participant
            if call_info['caller_id'] != current_user.id:
                emit('screen_share_stopped', share_data, to=f"user_{call_info['caller_id']}")
            if 'recipient_id' in call_info and call_info['recipient_id'] != current_user.id:
                emit('screen_share_stopped', share_data, to=f"user_{call_info['recipient_id']}")
                
    except Exception as e:
        logging.error(f"Error handling screen share stop: {e}")

@socketio.on('voice_message')
def on_voice_message(data):
    if not current_user.is_authenticated:
        return
    
    try:
        channel_id = data.get('channel_id')
        recipient_id = data.get('recipient_id')
        audio_data = data.get('audio_data')
        duration = data.get('duration', 0)
        
        if not audio_data:
            return
            
        voice_message_data = {
            'id': f"voice_{datetime.now().timestamp()}",
            'type': 'voice',
            'sender_id': current_user.id,
            'sender_name': current_user.username or current_user.first_name or 'User',
            'sender_avatar': current_user.profile_image_url,
            'duration': duration,
            'created_at': datetime.now().isoformat()
        }
        
        if channel_id:
            emit('new_voice_message', voice_message_data, to=f"channel_{channel_id}")
        elif recipient_id:
            emit('new_voice_message', voice_message_data, to=f"user_{recipient_id}")
            emit('new_voice_message', voice_message_data, to=f"user_{current_user.id}")
            
    except Exception as e:
        logging.error(f"Error handling voice message: {e}")

# Duplicate connect/disconnect handlers removed - using the ones above
