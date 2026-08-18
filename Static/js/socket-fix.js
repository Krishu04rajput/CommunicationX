// Fixed Socket.IO initialization
console.log('Initializing socket connection with proper error handling...');

let socket = null;
let socketReady = false;

function initializeSocket() {
    if (typeof io === 'undefined') {
        console.error('Socket.IO library not loaded');
        return;
    }

    try {
        socket = io({
            transports: ['polling', 'websocket'],
            upgrade: true,
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionAttempts: 3,
            timeout: 10000
        });

        socket.on('connect', function() {
            console.log('Socket connected successfully');
            socketReady = true;
            
            // Enable all interface elements that depend on socket
            enableSocketDependentElements();
        });

        socket.on('disconnect', function(reason) {
            console.log('Socket disconnected:', reason);
            socketReady = false;
        });

        socket.on('connect_error', function(error) {
            console.log('Socket connection error:', error);
            socketReady = false;
            
            // Fallback to basic functionality without socket
            enableBasicFunctionality();
        });

        // Message handlers
        socket.on('new_message', function(data) {
            console.log('New message received:', data);
            handleNewMessage(data);
        });

        socket.on('new_dm', function(data) {
            console.log('New DM received:', data);
            handleNewDM(data);
        });

        socket.on('incoming_call', function(data) {
            console.log('Incoming call:', data);
            handleIncomingCall(data);
        });

    } catch (error) {
        console.error('Failed to initialize socket:', error);
        enableBasicFunctionality();
    }
}

function enableSocketDependentElements() {
    console.log('Enabling socket-dependent interface elements...');
    
    // Enable message sending
    const messageInputs = document.querySelectorAll('.message-input');
    messageInputs.forEach(input => {
        input.disabled = false;
        input.placeholder = 'Type a message...';
    });

    // Enable call buttons
    const callButtons = document.querySelectorAll('[data-action="start-call"]');
    callButtons.forEach(btn => {
        btn.disabled = false;
        btn.classList.remove('disabled');
    });
}

function enableBasicFunctionality() {
    console.log('Enabling basic functionality without socket...');
    
    // Enable forms to work with HTTP POST
    const messageInputs = document.querySelectorAll('.message-input');
    messageInputs.forEach(input => {
        input.disabled = false;
        input.placeholder = 'Type a message... (real-time disabled)';
    });

    // Enable navigation and basic buttons
    enableBasicButtons();
}

function enableBasicButtons() {
    // Enable all basic buttons that don't require socket
    const buttons = document.querySelectorAll('button, .btn');
    buttons.forEach(btn => {
        if (!btn.classList.contains('socket-required')) {
            btn.disabled = false;
            btn.classList.remove('disabled');
        }
    });

    // Enable form submissions
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            // Allow normal form submission
            console.log('Form submitted:', form.action);
        });
    });

    // Enable modal controls
    setupModalControls();
}

function setupModalControls() {
    // Modal opening
    document.addEventListener('click', function(e) {
        if (e.target.matches('[data-modal-target]')) {
            const modalId = e.target.getAttribute('data-modal-target');
            openModal(modalId);
        }

        if (e.target.matches('[data-modal]')) {
            const modalId = e.target.getAttribute('data-modal');
            openModal(modalId);
        }

        if (e.target.matches('.modal-close, [data-dismiss="modal"]')) {
            const modal = e.target.closest('.modal');
            if (modal) {
                closeModal(modal.id);
            }
        }
    });

    // Close modal when clicking outside
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('modal')) {
            closeModal(e.target.id);
        }
    });
}

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'block';
        modal.classList.add('show');
        document.body.style.overflow = 'hidden';
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
        modal.classList.remove('show');
        document.body.style.overflow = '';
    }
}

function handleNewMessage(data) {
    // Add message to chat interface
    const messagesContainer = document.querySelector('.messages-container');
    if (messagesContainer && data.message) {
        const messageElement = createMessageElement(data.message);
        messagesContainer.appendChild(messageElement);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
}

function handleNewDM(data) {
    // Handle direct message
    handleNewMessage(data);
}

function handleIncomingCall(data) {
    // Show call notification
    console.log('Handling incoming call:', data);
    if (window.showCallNotification) {
        window.showCallNotification(data);
    }
}

function createMessageElement(message) {
    const div = document.createElement('div');
    div.className = 'message';
    div.innerHTML = `
        <div class="message-content">
            <div class="message-author">${message.author_name || 'User'}</div>
            <div class="message-text">${message.content}</div>
            <div class="message-time">${new Date(message.created_at).toLocaleTimeString()}</div>
        </div>
    `;
    return div;
}

// Initialize socket when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, initializing socket and basic functionality...');
    
    // Always enable basic functionality first
    enableBasicFunctionality();
    
    // Then try to initialize socket
    setTimeout(initializeSocket, 100);
});

// Global socket reference for other scripts
window.socket = socket;
window.socketReady = socketReady;