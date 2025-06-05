from flask_socketio import emit, join_room, leave_room, disconnect
from flask_login import current_user
from app import socketio
from models import Call
import logging

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
        emit('user_joined', {'user_id': current_user.id}, room=f"call_{call_id}")
    except Exception as e:
        logging.error(f"Error in join_call: {e}")
        disconnect()

@socketio.on('leave_call')
def on_leave_call(data):
    call_id = data['call_id']
    leave_room(f"call_{call_id}")
    emit('user_left', {'user_id': current_user.id}, room=f"call_{call_id}")

@socketio.on('offer')
def on_offer(data):
    call_id = data['call_id']
    emit('offer', data, room=f"call_{call_id}", include_self=False)

@socketio.on('answer')
def on_answer(data):
    call_id = data['call_id']
    emit('answer', data, room=f"call_{call_id}", include_self=False)

@socketio.on('ice_candidate')
def on_ice_candidate(data):
    call_id = data['call_id']
    emit('ice_candidate', data, room=f"call_{call_id}", include_self=False)
