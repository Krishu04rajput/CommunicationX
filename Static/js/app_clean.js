// CommunicationX Main JavaScript - Clean Version

// Initialize socket connection
if (!window.socket) {
    window.socket = null;
}

function initializeSocket() {
    if (typeof io !== 'undefined' && !window.socket) {
        console.log('Initializing socket connection...');
        try {
            window.socket = io();
        } catch (error) {
            console.error('Failed to initialize socket:', error);
            return;
        }
        
        window.socket.on('connect', function() {
            console.log('Connected to server');
        });
        
        window.socket.on('disconnect', function() {
            console.log('Disconnected from server');
        });
        
        window.socket.on('connect_error', function(error) {
            console.error('Socket connection error:', error);
        });
        
        // Message handlers
        window.socket.on('new_message', function(data) {
            console.log('New message received:', data);
            addMessageToUI(data, 'channel');
        });
        
        window.socket.on('new_dm', function(data) {
            console.log('New DM received:', data);
            addMessageToUI(data, 'dm');
        });
        
        window.socket.on('message_error', function(data) {
            console.error('Message error:', data);
            showNotification('Failed to send message: ' + data.error, 'error');
        });
        
        // Call handlers
        window.socket.on('call_incoming', function(data) {
            console.log('Incoming call:', data);
            if (window.callPopup) {
                window.callPopup.showCallPopup(data);
            }
        });
        
        window.socket.on('call_ended', function(data) {
            console.log('Call ended:', data);
            if (window.callPopup) {
                window.callPopup.hideCallPopup();
            }
        });
        
        // Listen for new messages
        window.socket.on('new_message', function(data) {
            console.log('New message received:', data);
            addMessageToUI(data, 'channel');
        });
        
        // Listen for new direct messages
        window.socket.on('new_dm', function(data) {
            console.log('New DM received:', data);
            addMessageToUI(data, 'dm');
        });
        
        // Listen for message errors
        window.socket.on('message_error', function(data) {
            console.error('Message error:', data);
            showNotification(data.error || 'Failed to send message', 'error');
        });
        
        // Join current channel on connect
        const currentPath = window.location.pathname;
        if (currentPath.includes('/server/') && currentPath.includes('/channel/')) {
            const pathParts = currentPath.split('/');
            const channelIndex = pathParts.indexOf('channel') + 1;
            if (channelIndex < pathParts.length) {
                const channelId = pathParts[channelIndex];
                console.log('Joining channel:', channelId);
                window.socket.emit('join_channel', { channel_id: channelId });
            }
        }
        
        // Join user room for direct messages
        if (currentPath.includes('/dm/') || currentPath.includes('/direct-messages')) {
            console.log('Joining user room for DMs');
            window.socket.emit('join_user_room', {});
            
            // Extract user ID from DM path if available
            const pathParts = currentPath.split('/');
            const dmIndex = pathParts.indexOf('dm') + 1;
            if (dmIndex < pathParts.length) {
                const otherUserId = pathParts[dmIndex];
                console.log('Joining DM conversation with user:', otherUserId);
                window.socket.emit('join_dm_conversation', { other_user_id: otherUserId });
            }
        }
    }
}

function addMessageToUI(messageData, type) {
    const container = type === 'dm' ? 
        document.querySelector('.dm-messages') : 
        document.querySelector('.messages-container');
        
    if (!container) return;
    
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message';
    messageDiv.innerHTML = `
        <div class="message-header">
            <strong>${messageData.author_name || messageData.sender_name}</strong>
            <span class="message-time">${new Date(messageData.created_at).toLocaleTimeString()}</span>
        </div>
        <div class="message-content">${messageData.content}</div>
    `;
    
    container.appendChild(messageDiv);
    container.scrollTop = container.scrollHeight;
}

// Initialize message forms function
function initializeMessageForms() {
    // Handle both server message forms and DM message forms
    const messageForms = document.querySelectorAll('.message-form');
    
    messageForms.forEach(form => {
        // Skip if already initialized
        if (form.dataset.initialized) return;
        form.dataset.initialized = 'true';
        
        const messageInput = form.querySelector('.message-input');
        if (!messageInput) return;
        
        // Form submission handler
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            const content = messageInput.value.trim();
            if (!content) return;
            
            // Get channel ID or recipient ID
            const channelId = form.getAttribute('data-channel-id');
            const recipientId = form.getAttribute('data-recipient-id');
            
            if (window.socket && window.socket.connected) {
                if (channelId) {
                    console.log('Sending channel message:', content);
                    window.socket.emit('send_message', {
                        content: content,
                        channel_id: channelId,
                        type: 'text'
                    });
                } else if (recipientId) {
                    console.log('Sending DM:', content);
                    window.socket.emit('send_dm', {
                        content: content,
                        recipient_id: recipientId
                    });
                }
                messageInput.value = '';
                messageInput.style.height = 'auto';
            } else {
                // Fallback to form submission
                console.log('Socket not connected, using form submission');
                form.submit();
            }
        });
        
        // Enter key to send message
        messageInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                form.dispatchEvent(new Event('submit'));
            }
        });
        
        // Auto-resize textarea
        messageInput.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 120) + 'px';
        });
    });
    
    console.log('Message forms initialized:', messageForms.length);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeSocket();
    initializeMessageForms();
    
    // Set up delayed initialization to ensure all components are loaded
    setTimeout(() => {
        initializeMessageForms();
        console.log('CommunicationX JavaScript loaded successfully');
    }, 100);
});

// Global function definitions for template usage
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'block';
        modal.classList.add('show');
        modal.style.position = 'fixed';
        modal.style.top = '0';
        modal.style.left = '0';
        modal.style.width = '100%';
        modal.style.height = '100%';
        modal.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
        modal.style.zIndex = '1000';
        modal.style.display = 'flex';
        modal.style.justifyContent = 'center';
        modal.style.alignItems = 'center';
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
        modal.classList.remove('show');
    }
}

function toggleMessageMenu(messageId) {
    const menu = document.querySelector(`[data-message-id="${messageId}"] .message-menu`);
    if (menu) {
        menu.classList.toggle('show');
    }
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 4px;
        color: white;
        z-index: 9999;
        background: ${type === 'error' ? '#dc3545' : type === 'success' ? '#28a745' : '#007bff'};
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Invitation functionality
async function createInvitation(event) {
    if (event) {
        event.preventDefault();
    }

    try {
        const email = document.getElementById('inviteEmail')?.value || '';
        const formData = new FormData();
        if (email) {
            formData.append('email', email);
        }

        const response = await fetch('/create_invitation', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.success) {
            const urlElement = document.getElementById('invitationUrl');
            const resultElement = document.getElementById('invitationResult');
            if (urlElement) urlElement.value = data.invite_url;
            if (resultElement) resultElement.style.display = 'block';
            showNotification('Invitation created successfully!', 'success');
        } else {
            alert('Error creating invitation: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error creating invitation:', error);
        alert('Error creating invitation: ' + error.message);
    }
}

// Copy invitation URL
function copyInvitationUrl() {
    const urlElement = document.getElementById('invitationUrl');
    if (urlElement) {
        navigator.clipboard.writeText(urlElement.value).then(() => {
            showNotification('Invitation URL copied!', 'success');
        }).catch(() => {
            // Fallback for older browsers
            urlElement.select();
            document.execCommand('copy');
            showNotification('Invitation URL copied!', 'success');
        });
    }
}

// Message functions
function deleteMessage(messageId) {
    if (confirm('Are you sure you want to delete this message?')) {
        fetch(`/message/${messageId}/delete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }).then(response => {
            if (response.ok) {
                document.querySelector(`[data-message-id="${messageId}"]`)?.remove();
                showNotification('Message deleted', 'success');
            } else {
                alert('Failed to delete message');
            }
        }).catch(error => {
            alert('Error deleting message: ' + error.message);
        });
    }
}

function replyToMessage(messageId) {
    const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
    if (messageElement) {
        const messageInput = document.querySelector('.message-input');
        if (messageInput) {
            messageInput.focus();
            messageInput.dataset.replyTo = messageId;
        }
    }
}

function forwardMessage(messageId) {
    const recipient = prompt('Enter username to forward message to:');
    if (recipient) {
        fetch(`/message/${messageId}/forward`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ recipient: recipient })
        }).then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification('Message forwarded successfully!', 'success');
            } else {
                alert('Error forwarding message: ' + data.error);
            }
        }).catch(error => {
            console.error('Error forwarding message:', error);
            alert('Failed to forward message');
        });
    }
}

function toggleReaction(messageId, emoji) {
    fetch(`/message/${messageId}/react`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ emoji: emoji })
    }).then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload();
        }
    }).catch(error => {
        console.error('Error reacting to message:', error);
    });
}

// Remove duplicate socket initialization - use the main one above

// Modal handling
document.addEventListener('DOMContentLoaded', function() {
    // Handle modal triggers
    document.querySelectorAll('[data-modal-target]').forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const modalId = this.getAttribute('data-modal-target');
            openModal(modalId);
        });
    });

    // Handle modal close buttons
    document.querySelectorAll('.modal-close, .btn-close').forEach(button => {
        button.addEventListener('click', function() {
            const modal = this.closest('.modal');
            if (modal) {
                modal.style.display = 'none';
            }
        });
    });

    // Close modal when clicking outside
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', function(e) {
            if (e.target === this) {
                this.style.display = 'none';
            }
        });
    });

    // Server creation form validation
    const createServerForm = document.querySelector('#createServerModal form');
    if (createServerForm) {
        createServerForm.addEventListener('submit', function(e) {
            const serverName = this.querySelector('input[name="server_name"]')?.value?.trim();
            if (!serverName || serverName.length < 3) {
                e.preventDefault();
                alert('Server name must be at least 3 characters long.');
                return false;
            }
            if (serverName.length > 100) {
                e.preventDefault();
                alert('Server name is too long. Maximum 100 characters allowed.');
                return false;
            }
        });
    }

    // Invitation form handling
    const invitationForm = document.querySelector('#createInvitationModal form');
    if (invitationForm) {
        invitationForm.addEventListener('submit', createInvitation);
    }

    // Message forms are now handled by initializeMessageForms() function

    // File upload handling
    const fileInput = document.getElementById('fileInput');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            const files = e.target.files;
            if (files.length > 0) {
                const channelId = document.querySelector('.message-form').dataset.channelId;
                uploadFiles(files, channelId);
            }
        });
    }
});

// Close dropdowns when clicking outside
document.addEventListener('click', function(event) {
    if (!event.target.closest('.message-actions')) {
        document.querySelectorAll('.message-dropdown, .emoji-picker').forEach(d => {
            d.style.display = 'none';
        });
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Escape to close modals
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.style.display = 'none';
        });
    }
});

// File upload functionality
function uploadFiles(files, channelId) {
    if (!files || files.length === 0 || !channelId) return;
    
    const formData = new FormData();
    for (let i = 0; i < files.length; i++) {
        formData.append('files', files[i]);
    }
    
    showNotification('Uploading files...', 'info');
    
    fetch(`/channel/${channelId}/upload`, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Files uploaded successfully!', 'success');
            // Clear file input
            const fileInput = document.getElementById('fileInput');
            if (fileInput) fileInput.value = '';
            // Refresh messages or update UI
            location.reload();
        } else {
            showNotification('Error uploading files: ' + (data.error || 'Unknown error'), 'error');
        }
    })
    .catch(error => {
        console.error('Error uploading files:', error);
        showNotification('Failed to upload files', 'error');
    });
}

// Missing function definitions
function toggleMemberList() {
    const memberList = document.querySelector('.member-list');
    if (memberList) {
        memberList.classList.toggle('show');
    }
}

// Remove duplicate socket initialization - already exists above

// Message sending functionality
function sendMessage() {
    const messageInput = document.querySelector('#messageInput, .message-input input');
    const channelId = document.querySelector('[data-channel-id]')?.getAttribute('data-channel-id');
    
    if (!messageInput || !channelId) {
        console.error('Message input or channel ID not found');
        return;
    }
    
    const content = messageInput.value.trim();
    if (!content) return;
    
    if (window.socket && window.socket.connected) {
        window.socket.emit('send_message', {
            content: content,
            channel_id: channelId,
            type: 'text'
        });
        
        messageInput.value = '';
        messageInput.focus();
    } else {
        // Fallback to form submission
        submitMessageForm(content, channelId);
    }
}

// Form submission fallback for message sending
function submitMessageForm(content, channelId) {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = `/channel/${channelId}/send`;
    
    const contentInput = document.createElement('input');
    contentInput.type = 'hidden';
    contentInput.name = 'content';
    contentInput.value = content;
    
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
    if (csrfToken) {
        const csrfInput = document.createElement('input');
        csrfInput.type = 'hidden';
        csrfInput.name = 'csrf_token';
        csrfInput.value = csrfToken;
        form.appendChild(csrfInput);
    }
    
    form.appendChild(contentInput);
    document.body.appendChild(form);
    form.submit();
}

// Add message to chat UI
function addMessageToChat(messageData) {
    const messagesContainer = document.querySelector('.messages-container, .chat-messages');
    if (!messagesContainer) return;
    
    const messageElement = document.createElement('div');
    messageElement.className = 'message';
    messageElement.innerHTML = `
        <div class="message-content">
            <div class="message-header">
                <span class="message-author">${messageData.author_name}</span>
                <span class="message-time">${new Date(messageData.created_at).toLocaleTimeString()}</span>
            </div>
            <div class="message-text">${messageData.content}</div>
        </div>
    `;
    
    messagesContainer.appendChild(messageElement);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// File upload functionality
function handleFileUpload() {
    const fileInput = document.querySelector('#fileInput, .file-input input[type="file"]');
    const channelId = document.querySelector('[data-channel-id]')?.getAttribute('data-channel-id');
    
    if (!fileInput || !channelId) {
        console.error('File input or channel ID not found');
        return;
    }
    
    const files = fileInput.files;
    if (files.length === 0) return;
    
    const formData = new FormData();
    for (let i = 0; i < files.length; i++) {
        formData.append('files', files[i]);
    }
    
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
    if (csrfToken) {
        formData.append('csrf_token', csrfToken);
    }
    
    fetch(`/channel/${channelId}/upload`, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('File uploaded successfully!', 'success');
            if (data.message) {
                addMessageToChat(data.message);
            }
        } else {
            showNotification('Failed to upload file: ' + data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Upload error:', error);
        showNotification('Failed to upload file', 'error');
    });
    
    fileInput.value = '';
}

console.log('CommunicationX JavaScript loaded successfully');