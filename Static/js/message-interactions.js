// Message interaction functionality - Delete, Forward, React, Reply

document.addEventListener('DOMContentLoaded', function() {
    // Add message interaction buttons to existing messages
    addInteractionButtons();
    
    // Listen for new messages and add interaction buttons
    if (window.socket) {
        window.socket.on('new_message', function(data) {
            setTimeout(() => {
                addInteractionButtons();
            }, 100);
        });
    } else {
        console.log('Socket not available for message interactions');
    }
        setTimeout(() => {
            addInteractionButtons();
        }, 100);
    });
});

function addInteractionButtons() {
    const messages = document.querySelectorAll('.message:not(.has-interactions)');
    
    messages.forEach(message => {
        const messageId = message.dataset.messageId;
        if (!messageId) return;
        
        message.classList.add('has-interactions');
        
        // Create interaction buttons container
        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'message-actions';
        actionsDiv.innerHTML = `
            <button class="action-btn react-btn" data-message-id="${messageId}" title="React">😊</button>
            <button class="action-btn reply-btn" data-message-id="${messageId}" title="Reply">↩️</button>
            <button class="action-btn forward-btn" data-message-id="${messageId}" title="Forward">↪️</button>
            <button class="action-btn edit-btn" data-message-id="${messageId}" title="Edit">✏️</button>
            <button class="action-btn delete-btn" data-message-id="${messageId}" title="Delete">🗑️</button>
        `;
        
        // Add to message
        const messageContent = message.querySelector('.message-content');
        if (messageContent) {
            messageContent.appendChild(actionsDiv);
        }
        
        // Add reactions container
        const reactionsDiv = document.createElement('div');
        reactionsDiv.className = 'message-reactions';
        reactionsDiv.id = `reactions-${messageId}`;
        messageContent.appendChild(reactionsDiv);
    });
    
    // Add event listeners
    addInteractionEventListeners();
}

function addInteractionEventListeners() {
    // React button
    document.querySelectorAll('.react-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const messageId = this.dataset.messageId;
            showEmojiPicker(messageId, this);
        });
    });
    
    // Reply button
    document.querySelectorAll('.reply-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const messageId = this.dataset.messageId;
            showReplyDialog(messageId);
        });
    });
    
    // Forward button
    document.querySelectorAll('.forward-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const messageId = this.dataset.messageId;
            showForwardDialog(messageId);
        });
    });
    
    // Edit button
    document.querySelectorAll('.edit-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const messageId = this.dataset.messageId;
            showEditDialog(messageId);
        });
    });
    
    // Delete button
    document.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const messageId = this.dataset.messageId;
            showDeleteConfirmation(messageId);
        });
    });
}

function showEmojiPicker(messageId, button) {
    const emojis = ['👍', '👎', '❤️', '😂', '😮', '😢', '😡', '👏', '🎉', '🔥'];
    
    // Remove existing picker
    const existingPicker = document.querySelector('.emoji-picker');
    if (existingPicker) {
        existingPicker.remove();
    }
    
    // Create emoji picker
    const picker = document.createElement('div');
    picker.className = 'emoji-picker';
    picker.innerHTML = emojis.map(emoji => 
        `<button class="emoji-option" data-emoji="${emoji}">${emoji}</button>`
    ).join('');
    
    // Position picker
    const rect = button.getBoundingClientRect();
    picker.style.position = 'fixed';
    picker.style.top = (rect.top - 50) + 'px';
    picker.style.left = rect.left + 'px';
    picker.style.backgroundColor = 'white';
    picker.style.border = '1px solid #ccc';
    picker.style.borderRadius = '8px';
    picker.style.padding = '8px';
    picker.style.display = 'flex';
    picker.style.gap = '4px';
    picker.style.zIndex = '1000';
    picker.style.boxShadow = '0 2px 8px rgba(0,0,0,0.2)';
    
    document.body.appendChild(picker);
    
    // Add emoji click handlers
    picker.querySelectorAll('.emoji-option').forEach(emojiBtn => {
        emojiBtn.addEventListener('click', function() {
            const emoji = this.dataset.emoji;
            reactToMessage(messageId, emoji);
            picker.remove();
        });
    });
    
    // Close picker when clicking outside
    setTimeout(() => {
        document.addEventListener('click', function closePickerHandler(e) {
            if (!picker.contains(e.target) && e.target !== button) {
                picker.remove();
                document.removeEventListener('click', closePickerHandler);
            }
        });
    }, 100);
}

function reactToMessage(messageId, emoji) {
    fetch(`/api/message/${messageId}/react`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ emoji: emoji })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            updateReactionDisplay(messageId, emoji, data.action);
        } else {
            alert('Error: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error reacting to message:', error);
        alert('Failed to react to message');
    });
}

function updateReactionDisplay(messageId, emoji, action) {
    const reactionsContainer = document.getElementById(`reactions-${messageId}`);
    if (!reactionsContainer) return;
    
    let reactionBtn = reactionsContainer.querySelector(`[data-emoji="${emoji}"]`);
    
    if (action === 'added') {
        if (!reactionBtn) {
            reactionBtn = document.createElement('button');
            reactionBtn.className = 'reaction-btn';
            reactionBtn.dataset.emoji = emoji;
            reactionBtn.innerHTML = `${emoji} 1`;
            reactionsContainer.appendChild(reactionBtn);
        } else {
            const count = parseInt(reactionBtn.textContent.split(' ')[1] || '0') + 1;
            reactionBtn.innerHTML = `${emoji} ${count}`;
        }
    } else if (action === 'removed' && reactionBtn) {
        const count = parseInt(reactionBtn.textContent.split(' ')[1] || '1') - 1;
        if (count <= 0) {
            reactionBtn.remove();
        } else {
            reactionBtn.innerHTML = `${emoji} ${count}`;
        }
    }
}

function showReplyDialog(messageId) {
    const content = prompt('Enter your reply:');
    if (content && content.trim()) {
        replyToMessage(messageId, content.trim());
    }
}

function replyToMessage(messageId, content) {
    fetch(`/api/message/${messageId}/reply`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ content: content })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Message will be added via socket
            alert('Reply sent successfully!');
        } else {
            alert('Error: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error replying to message:', error);
        alert('Failed to send reply');
    });
}

function showForwardDialog(messageId) {
    // Simple channel selection for now
    const channelId = prompt('Enter channel ID to forward to:');
    if (channelId && channelId.trim()) {
        forwardMessage(messageId, parseInt(channelId.trim()));
    }
}

function forwardMessage(messageId, channelId) {
    fetch(`/api/message/${messageId}/forward`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ channel_id: channelId })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Message forwarded successfully!');
        } else {
            alert('Error: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error forwarding message:', error);
        alert('Failed to forward message');
    });
}

function showEditDialog(messageId) {
    const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
    const currentContent = messageElement.querySelector('.message-content').textContent.split(':')[1]?.trim();
    
    const newContent = prompt('Edit message:', currentContent);
    if (newContent && newContent.trim() && newContent.trim() !== currentContent) {
        editMessage(messageId, newContent.trim());
    }
}

function editMessage(messageId, content) {
    fetch(`/api/message/${messageId}/edit`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ content: content })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Update message content in DOM
            const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
            const contentElement = messageElement.querySelector('.message-content');
            const authorName = contentElement.textContent.split(':')[0];
            contentElement.innerHTML = `${authorName}: ${content} <span class="edited-indicator">(edited)</span>`;
            alert('Message edited successfully!');
        } else {
            alert('Error: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error editing message:', error);
        alert('Failed to edit message');
    });
}

function showDeleteConfirmation(messageId) {
    if (confirm('Are you sure you want to delete this message?')) {
        deleteMessage(messageId);
    }
}

function deleteMessage(messageId) {
    fetch(`/api/message/${messageId}/delete`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Update message content in DOM
            const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
            const contentElement = messageElement.querySelector('.message-content');
            const authorName = contentElement.textContent.split(':')[0];
            contentElement.innerHTML = `${authorName}: [Message deleted]`;
            
            // Remove action buttons
            const actionsElement = messageElement.querySelector('.message-actions');
            if (actionsElement) {
                actionsElement.remove();
            }
            
            alert('Message deleted successfully!');
        } else {
            alert('Error: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error deleting message:', error);
        alert('Failed to delete message');
    });
}