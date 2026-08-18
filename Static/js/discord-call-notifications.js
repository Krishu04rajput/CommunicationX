/**
 * Discord-style Call Notification System
 * Provides global call notifications with accept/decline options and sound effects
 * Works across all screens of the application
 */

class DiscordCallNotifications {
    constructor() {
        this.currentCallPopup = null;
        this.notificationSound = null;
        this.ringtoneInterval = null;
        this.initialized = false;
        this.init();
    }

    init() {
        if (this.initialized) return;
        
        console.log('Initializing Discord-style call notifications...');
        
        // Create notification sound
        this.createNotificationSound();
        
        // Setup global socket listeners
        this.setupSocketListeners();
        
        // Create global call popup container
        this.createCallPopupContainer();
        
        this.initialized = true;
        console.log('Discord call notifications initialized');
    }

    createNotificationSound() {
        // Create audio context for notification sounds
        try {
            const AudioContext = window.AudioContext || window.webkitAudioContext;
            this.audioContext = new AudioContext();
            
            // Create ringtone sound using Web Audio API
            this.createRingtoneSound();
        } catch (error) {
            console.warn('Audio context not available, using fallback sounds');
            this.createFallbackSound();
        }
    }

    createRingtoneSound() {
        // Create a pleasant Discord-like ringtone
        this.playRingtone = () => {
            if (!this.audioContext) return;
            
            const oscillator = this.audioContext.createOscillator();
            const gainNode = this.audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(this.audioContext.destination);
            
            // Discord-like ringtone frequencies
            oscillator.frequency.setValueAtTime(659.25, this.audioContext.currentTime); // E5
            oscillator.frequency.setValueAtTime(783.99, this.audioContext.currentTime + 0.2); // G5
            oscillator.frequency.setValueAtTime(659.25, this.audioContext.currentTime + 0.4); // E5
            
            oscillator.type = 'sine';
            gainNode.gain.setValueAtTime(0.1, this.audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + 0.6);
            
            oscillator.start(this.audioContext.currentTime);
            oscillator.stop(this.audioContext.currentTime + 0.6);
        };
    }

    createFallbackSound() {
        // Fallback beep sound
        this.playRingtone = () => {
            try {
                const audio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmIdBjmS2fPNeSwGJHfH8N2QQAoUXrTp66hVFAlGn+DyvmIdBjmS2fPNeSsFJHbH8N2QQAoUXrTp66hVFQlGn+DyvmIdBjmS2fLMeSsFJHbH8N2QQAsUXbTp66hVFQlHn+DyvmIcBzqS2fHMeSsFJXbH8N2QQAsUXbPo66lUFAlHn+DyvmIcBjmT2fPNeSsFJHfH8N2QQAoUXrTp66hVFQpGnt/yvmMdBjiS2fLNeSsGJHfH8N+QQAoUXrTp66hVFAlGnt/yvmIdBjiS2fPNeSsGJHbH8N+QQAoUXrTp66hVFAlFnt/yvmIdBjiS2fPNeSsGJHbG8N+QQAoUXrTp66hVFQlFnt/yv2IdBjiS2fLMeSsGJHbG8N+QQAoUXrPp66lUFAlFnt/yv2IdBjiS2fLNeSsGJHbG8N+QQAoUXrPp66lUFAlFn9/yv2IcBjiS2fPNeSwFJHfH8N2QQAoUXrTp66hVFQlGn9/yv2IcBjiS2fPNeSwFJHfH8N2QQAoUXrTp66hVFQlGn9/yv2IcBjiS2fPNeSwFJHfH8N2QQAoUXrTp66hVFQlGn+DyvmIcBjiT2fLNeSsGJHfH8N+QQAoUXrTp66hVFQlGn+DyvmIdBjiT2fPNeSsGJHfH8N+QQAoUXrTp66hVFQlGn+DyvmIdBjiT2fPNeSsGJHfH8N+QQAoUXrTp66hVFQlGn+DyvmIdBjiT2fPNeSsGJHfH8N+QQAkUXrTp66hVFQlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQQkUXrTp66hVFQlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQQkUXrTp66hVFQlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXrTp66hVFQlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAkUXbTp66lUFAlGn+DyvmIdBjmT2fLNeSsGJHjH8N2QQAk');
                audio.volume = 0.3;
                audio.play().catch(() => {});
            } catch (error) {
                console.warn('Could not play notification sound');
            }
        };
    }

    createCallPopupContainer() {
        if (document.getElementById('global-call-popup')) return;
        
        const container = document.createElement('div');
        container.id = 'global-call-popup';
        container.innerHTML = `
            <div id="call-notification-popup" class="call-popup hidden">
                <div class="call-popup-header">
                    <div class="call-popup-avatar" id="call-avatar">
                        <i class="fas fa-user"></i>
                    </div>
                    <div class="call-popup-info">
                        <div class="call-popup-name" id="call-caller-name">Unknown</div>
                        <div class="call-popup-type" id="call-type">
                            <i class="fas fa-phone"></i>
                            <span>Incoming Call</span>
                        </div>
                    </div>
                </div>
                <div class="call-popup-controls">
                    <button class="call-btn decline" id="decline-call-btn" title="Decline Call">
                        <i class="fas fa-phone-slash"></i>
                    </button>
                    <button class="call-btn accept" id="accept-call-btn" title="Accept Call">
                        <i class="fas fa-phone"></i>
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(container);
        this.setupCallPopupListeners();
    }

    setupCallPopupListeners() {
        // Remove existing event listeners to prevent duplicates
        const acceptBtn = document.getElementById('accept-call-btn');
        const declineBtn = document.getElementById('decline-call-btn');
        
        if (acceptBtn) {
            // Remove existing listeners
            acceptBtn.replaceWith(acceptBtn.cloneNode(true));
            const newAcceptBtn = document.getElementById('accept-call-btn');
            newAcceptBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                console.log('Accept button clicked');
                this.acceptCall();
            });
        }
        
        if (declineBtn) {
            // Remove existing listeners
            declineBtn.replaceWith(declineBtn.cloneNode(true));
            const newDeclineBtn = document.getElementById('decline-call-btn');
            newDeclineBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                console.log('Decline button clicked');
                this.declineCall();
            });
        }
        
        console.log('Call popup listeners set up - Accept:', !!acceptBtn, 'Decline:', !!declineBtn);
    }

    setupSocketListeners() {
        const setupListeners = () => {
            if (!window.socket || !window.socket.connected) {
                setTimeout(setupListeners, 500);
                return;
            }

            console.log('Setting up Discord call notification listeners...');

            // Remove existing listeners to prevent duplicates
            window.socket.off('incoming_call');
            window.socket.off('call_ended');
            window.socket.off('call_declined');
            window.socket.off('call_accepted');

            // Listen for incoming calls
            window.socket.on('incoming_call', (data) => {
                console.log('Incoming call notification:', data);
                this.showCallNotification(data);
            });

            // Listen for call ended
            window.socket.on('call_ended', (data) => {
                console.log('Call ended notification:', data);
                this.hideCallNotification();
            });

            // Listen for call declined
            window.socket.on('call_declined', (data) => {
                console.log('Call declined notification:', data);
                this.hideCallNotification();
            });

            // Listen for call accepted
            window.socket.on('call_accepted', (data) => {
                console.log('Call accepted notification:', data);
                this.hideCallNotification();
            });
        };

        setupListeners();
    }

    showCallNotification(callData) {
        console.log('Showing Discord-style call notification:', callData);
        
        let popup = document.getElementById('call-notification-popup');
        
        // If popup doesn't exist, create it
        if (!popup) {
            console.log('Call popup not found, creating it...');
            this.createCallPopupContainer();
            popup = document.getElementById('call-notification-popup');
        }
        
        if (!popup) {
            console.error('Failed to create call popup');
            return;
        }

        const callerName = document.getElementById('call-caller-name');
        const callAvatar = document.getElementById('call-avatar');
        const callTypeEl = document.getElementById('call-type');

        // Update caller information
        if (callerName) {
            callerName.textContent = callData.caller_name || 'Unknown Caller';
        }
        
        // Update avatar
        if (callAvatar) {
            if (callData.caller_avatar) {
                callAvatar.innerHTML = `<img src="${callData.caller_avatar}" alt="Avatar">`;
            } else {
                const initial = (callData.caller_name || 'U')[0].toUpperCase();
                callAvatar.innerHTML = initial;
            }
        }
        
        // Update call type
        if (callTypeEl) {
            const isVideo = callData.call_type === 'video';
            callTypeEl.innerHTML = `
                <i class="fas fa-${isVideo ? 'video' : 'phone'}"></i>
                <span>Incoming ${isVideo ? 'Video' : 'Voice'} Call</span>
            `;
        }

        // Store current call data
        this.currentCallData = callData;
        
        // Ensure buttons are properly set up
        this.setupCallPopupListeners();
        
        // Show popup with animation
        popup.classList.remove('hidden');
        popup.classList.add('call-popup-ring');
        popup.style.display = 'block';
        popup.style.visibility = 'visible';
        
        console.log('Call popup should now be visible');
        
        // Start ringtone
        this.startRingtone();
        
        // Auto-decline after 30 seconds (Discord behavior)
        this.autoDeclineTimeout = setTimeout(() => {
            console.log('Auto-declining call after 30 seconds');
            this.declineCall();
        }, 30000);
    }

    hideCallNotification() {
        const popup = document.getElementById('call-notification-popup');
        if (popup) {
            popup.classList.add('hidden');
            popup.classList.remove('call-popup-ring');
        }
        
        this.stopRingtone();
        this.clearAutoDecline();
        this.currentCallData = null;
    }

    startRingtone() {
        if (this.ringtoneInterval) return;
        
        // Play initial ringtone
        this.playRingtone();
        
        // Repeat every 2 seconds
        this.ringtoneInterval = setInterval(() => {
            this.playRingtone();
        }, 2000);
    }

    stopRingtone() {
        if (this.ringtoneInterval) {
            clearInterval(this.ringtoneInterval);
            this.ringtoneInterval = null;
        }
    }

    clearAutoDecline() {
        if (this.autoDeclineTimeout) {
            clearTimeout(this.autoDeclineTimeout);
            this.autoDeclineTimeout = null;
        }
    }

    acceptCall() {
        console.log('Accepting call:', this.currentCallData);
        
        if (this.currentCallData && window.socket) {
            window.socket.emit('accept_call', {
                call_id: this.currentCallData.call_id
            });
            
            // Redirect to call screen
            if (this.currentCallData.server_id) {
                window.location.href = `/server/${this.currentCallData.server_id}/call`;
            } else {
                window.location.href = `/call/${this.currentCallData.call_id}`;
            }
        }
        
        this.hideCallNotification();
    }

    declineCall() {
        console.log('Declining call:', this.currentCallData);
        
        if (this.currentCallData && window.socket) {
            window.socket.emit('decline_call', {
                call_id: this.currentCallData.call_id
            });
        }
        
        this.hideCallNotification();
    }

    // Method to manually trigger a test notification (for development)
    testNotification() {
        const testData = {
            call_id: 'test-call-123',
            caller_name: 'Test User',
            caller_avatar: null,
            call_type: 'voice',
            server_id: null
        };
        
        this.showCallNotification(testData);
    }

    // Debug method to check if elements exist
    debugElements() {
        console.log('Debug: Checking call notification elements...');
        const popup = document.getElementById('call-notification-popup');
        const acceptBtn = document.getElementById('accept-call-btn');
        const declineBtn = document.getElementById('decline-call-btn');
        
        console.log('Popup element:', popup);
        console.log('Accept button:', acceptBtn);
        console.log('Decline button:', declineBtn);
        
        if (popup) {
            console.log('Popup classes:', popup.classList.toString());
            console.log('Popup display:', window.getComputedStyle(popup).display);
            console.log('Popup visibility:', window.getComputedStyle(popup).visibility);
        }
        
        return { popup, acceptBtn, declineBtn };
    }
}

// Initialize Discord call notifications when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing Discord call notifications system...');
    window.discordCallNotifications = new DiscordCallNotifications();
    
    // Add global test function for debugging
    window.testCallNotification = () => {
        console.log('Testing call notification...');
        if (window.discordCallNotifications) {
            window.discordCallNotifications.testNotification();
            setTimeout(() => {
                window.discordCallNotifications.debugElements();
            }, 500);
        } else {
            console.error('Discord call notifications not initialized');
        }
    };
});

// Also initialize if DOM is already loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        if (!window.discordCallNotifications) {
            window.discordCallNotifications = new DiscordCallNotifications();
        }
    });
} else {
    if (!window.discordCallNotifications) {
        window.discordCallNotifications = new DiscordCallNotifications();
        
        // Add global test function for debugging
        window.testCallNotification = () => {
            console.log('Testing call notification...');
            if (window.discordCallNotifications) {
                window.discordCallNotifications.testNotification();
                setTimeout(() => {
                    window.discordCallNotifications.debugElements();
                }, 500);
            } else {
                console.error('Discord call notifications not initialized');
            }
        };
    }
}

console.log('Discord call notifications script loaded');