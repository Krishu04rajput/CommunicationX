"""
Contact Access Management System
Restricts contact visibility and messaging based on admin status and invitation relationships
"""

from datetime import datetime
from sqlalchemy import or_, and_
from models import User, ContactAccess, Invitation, DirectMessage, db
from flask_login import current_user
import logging

def can_see_contact(user_id, contact_id):
    """
    Check if a user can see another user as a contact
    
    Rules:
    - Admins can see all contacts
    - Regular users can only see admins and users they have invitation relationships with
    """
    if user_id == contact_id:
        return True
    
    # Get the user making the request
    user = User.query.get(user_id)
    contact = User.query.get(contact_id)
    
    if not user or not contact:
        return False
    
    # Admins can see all contacts
    if user.is_admin or user.is_super_admin:
        return True
    
    # Regular users can always see admins
    if contact.is_admin or contact.is_super_admin:
        return True
    
    # Check if they have an invitation relationship
    return has_invitation_relationship(user_id, contact_id)

def can_message_contact(user_id, contact_id):
    """
    Check if a user can message another user
    
    Rules:
    - Admins can message anyone
    - Regular users can only message admins and users they have invitation relationships with
    """
    if user_id == contact_id:
        return False  # Can't message yourself
    
    # Get the user making the request
    user = User.query.get(user_id)
    contact = User.query.get(contact_id)
    
    if not user or not contact:
        return False
    
    # Banned users cannot message anyone
    if user.is_banned:
        return False
    
    # Cannot message banned users
    if contact.is_banned:
        return False
    
    # Admins can message anyone
    if user.is_admin or user.is_super_admin:
        return True
    
    # Regular users can always message admins
    if contact.is_admin or contact.is_super_admin:
        return True
    
    # Check if they have an invitation relationship
    return has_invitation_relationship(user_id, contact_id)

def has_invitation_relationship(user_id, contact_id):
    """
    Check if two users have an invitation relationship
    Returns True if either user invited the other or they have mutual contact access
    """
    # Check if either user invited the other
    invitation_exists = Invitation.query.filter(
        or_(
            and_(Invitation.inviter_id == user_id, Invitation.email == User.query.get(contact_id).email),
            and_(Invitation.inviter_id == contact_id, Invitation.email == User.query.get(user_id).email)
        )
    ).first()
    
    if invitation_exists:
        return True
    
    # Check contact access records
    access_exists = ContactAccess.query.filter(
        and_(
            ContactAccess.is_active == True,
            or_(
                and_(ContactAccess.user_id == user_id, ContactAccess.contact_id == contact_id),
                and_(ContactAccess.user_id == contact_id, ContactAccess.contact_id == user_id)
            )
        )
    ).first()
    
    return access_exists is not None

def get_accessible_contacts(user_id):
    """
    Get list of contacts that a user can see and message
    """
    user = User.query.get(user_id)
    if not user:
        return []
    
    # Admins can see all active users
    if user.is_admin or user.is_super_admin:
        return User.query.filter(
            and_(
                User.id != user_id,
                User.is_banned == False
            )
        ).all()
    
    # Regular users see admins + invitation-related users
    accessible_user_ids = set()
    
    # Add all admins
    admin_users = User.query.filter(
        and_(
            User.id != user_id,
            User.is_banned == False,
            or_(User.is_admin == True, User.is_super_admin == True)
        )
    ).all()
    
    for admin in admin_users:
        accessible_user_ids.add(admin.id)
    
    # Add users with invitation relationships
    # Users who invited this user
    invitations_received = Invitation.query.filter(
        Invitation.email == user.email
    ).all()
    
    for invitation in invitations_received:
        if invitation.inviter_id != user_id:
            accessible_user_ids.add(invitation.inviter_id)
    
    # Users this user invited
    invitations_sent = Invitation.query.filter(
        Invitation.inviter_id == user_id
    ).all()
    
    for invitation in invitations_sent:
        invited_user = User.query.filter(User.email == invitation.email).first()
        if invited_user and invited_user.id != user_id:
            accessible_user_ids.add(invited_user.id)
    
    # Add users from contact access records
    contact_access_records = ContactAccess.query.filter(
        and_(
            ContactAccess.is_active == True,
            or_(
                ContactAccess.user_id == user_id,
                ContactAccess.contact_id == user_id
            )
        )
    ).all()
    
    for record in contact_access_records:
        other_user_id = record.contact_id if record.user_id == user_id else record.user_id
        if other_user_id != user_id:
            accessible_user_ids.add(other_user_id)
    
    # Get user objects
    accessible_contacts = User.query.filter(
        and_(
            User.id.in_(accessible_user_ids),
            User.is_banned == False
        )
    ).all()
    
    return accessible_contacts

def create_contact_access(user_id, contact_id, access_type, granted_by=None, invitation_id=None):
    """
    Create a contact access record
    """
    try:
        # Check if access already exists
        existing = ContactAccess.query.filter(
            and_(
                ContactAccess.user_id == user_id,
                ContactAccess.contact_id == contact_id,
                ContactAccess.is_active == True
            )
        ).first()
        
        if existing:
            return existing
        
        access = ContactAccess(
            user_id=user_id,
            contact_id=contact_id,
            access_type=access_type,
            granted_by=granted_by,
            invitation_id=invitation_id,
            created_at=datetime.now(),
            is_active=True
        )
        
        db.session.add(access)
        db.session.commit()
        
        # Create reciprocal access for mutual relationships
        if access_type == 'mutual':
            reciprocal = ContactAccess(
                user_id=contact_id,
                contact_id=user_id,
                access_type=access_type,
                granted_by=granted_by,
                invitation_id=invitation_id,
                created_at=datetime.now(),
                is_active=True
            )
            db.session.add(reciprocal)
            db.session.commit()
        
        return access
        
    except Exception as e:
        logging.error(f"Error creating contact access: {e}")
        db.session.rollback()
        return None

def process_invitation_contact_access(invitation_id):
    """
    Process contact access when an invitation is used
    """
    try:
        invitation = Invitation.query.get(invitation_id)
        if not invitation:
            return False
        
        # Find the user who used the invitation
        invited_user = User.query.filter(User.email == invitation.email).first()
        if not invited_user:
            return False
        
        # Create mutual contact access
        create_contact_access(
            user_id=invitation.inviter_id,
            contact_id=invited_user.id,
            access_type='invitation',
            granted_by=invitation.inviter_id,
            invitation_id=invitation_id
        )
        
        create_contact_access(
            user_id=invited_user.id,
            contact_id=invitation.inviter_id,
            access_type='invitation',
            granted_by=invitation.inviter_id,
            invitation_id=invitation_id
        )
        
        logging.info(f"Contact access created between {invitation.inviter_id} and {invited_user.id}")
        return True
        
    except Exception as e:
        logging.error(f"Error processing invitation contact access: {e}")
        db.session.rollback()
        return False

def filter_message_recipients(user_id, potential_recipients):
    """
    Filter a list of potential message recipients based on access rules
    """
    accessible_recipients = []
    
    for recipient in potential_recipients:
        if can_message_contact(user_id, recipient.id):
            accessible_recipients.append(recipient)
    
    return accessible_recipients

def get_conversation_participants(user_id):
    """
    Get users that this user has had conversations with (and can still message)
    """
    # Get unique user IDs from direct messages
    conversation_user_ids = set()
    
    # Messages sent by user
    sent_messages = DirectMessage.query.filter(
        DirectMessage.sender_id == user_id
    ).with_entities(DirectMessage.recipient_id).distinct().all()
    
    for msg in sent_messages:
        conversation_user_ids.add(msg[0])
    
    # Messages received by user
    received_messages = DirectMessage.query.filter(
        DirectMessage.recipient_id == user_id
    ).with_entities(DirectMessage.sender_id).distinct().all()
    
    for msg in received_messages:
        conversation_user_ids.add(msg[0])
    
    # Filter based on current access permissions
    accessible_participants = []
    for participant_id in conversation_user_ids:
        if can_message_contact(user_id, participant_id):
            participant = User.query.get(participant_id)
            if participant:
                accessible_participants.append(participant)
    
    return accessible_participants