// Discord-like Call Pickup Request System
console.log('Loading call popup system...');

class CallPopupManager {
    constructor() {
        this.currentCall = null;
        this.ringtone = null;
        this.popupElement = null;
        this.ringTimeout = null;
        this.init();
    }

    init() {
        this.createPopupElement();
        this.setupSocketListeners();
        this.createRingtone();
        console.log('Call popup system initialized');
    }

    createPopupElement() {
        // Remove any existing popup
        const existingPopup = document.querySelector('.call-popup');
        if (existingPopup) {
            existingPopup.remove();
        }

        this.popupElement = document.createElement('div');
        this.popupElement.className = 'call-popup hidden';
        this.popupElement.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            background: rgba(0, 0, 0, 0.9);
            border-radius: 12px;
            padding: 20px;
            min-width: 320px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        `;
        this.popupElement.innerHTML = `
            <div class="call-popup-header">
                <div class="call-popup-avatar">
                    <span class="avatar-text"></span>
                </div>
                <div class="call-popup-info">
                    <h4 class="call-popup-name"></h4>
                    <p class="call-popup-status">
                        <span class="call-ringing-indicator"></span>
                        Incoming call...
                        <div class="call-sound-wave">
                            <div class="call-sound-bar"></div>
                            <div class="call-sound-bar"></div>
                            <div class="call-sound-bar"></div>
                            <div class="call-sound-bar"></div>
                        </div>
                    </p>
                    <div class="call-popup-type">
                        <i class="fas fa-phone"></i>
                        <span class="call-type-text">Voice Call</span>
                    </div>
                </div>
            </div>
            <div class="call-popup-controls">
                <button class="call-btn decline" onclick="callPopup.declineCall()">
                    <i class="fas fa-phone-slash"></i>
                </button>
                <button class="call-btn accept" onclick="callPopup.acceptCall()">
                    <i class="fas fa-phone"></i>
                </button>
            </div>
        `;
        
        // Always append to document.body for global visibility
        document.body.appendChild(this.popupElement);
        
        // Ensure popup stays visible across page navigation
        this.makePopupPersistent();
    }
    
    makePopupPersistent() {
        // Check if popup exists every 500ms and recreate if needed
        this.persistenceCheck = setInterval(() => {
            if (this.currentCall && (!this.popupElement || !document.body.contains(this.popupElement))) {
                console.log('Call popup lost, recreating...');
                this.createPopupElement();
                this.showIncomingCall(this.currentCall);
            }
        }, 500);
        
        // Also listen for page visibility changes to ensure popup stays visible
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && this.currentCall) {
                console.log('Page became visible, ensuring popup is shown');
                this.showIncomingCall(this.currentCall);
            }
        });
        
        // Listen for window focus to ensure popup appears on tab switch
        window.addEventListener('focus', () => {
            if (this.currentCall) {
                console.log('Window focused, ensuring popup is visible');
                this.showIncomingCall(this.currentCall);
            }
        });
    }

    createRingtone() {
        // Create audio context for ringtone
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            this.audioContext = audioContext;
        } catch (e) {
            console.warn('Web Audio API not supported, using HTML5 audio fallback');
        }
    }

    setupSocketListeners() {
        const setupListeners = () => {
            if (!window.socket || !window.socket.connected) {
                console.log('Waiting for socket connection...');
                setTimeout(setupListeners, 1000);
                return;
            }

            console.log('Setting up call popup listeners');

            // Remove existing listeners to prevent duplicates
            window.socket.off('incoming_call');
            window.socket.off('call_cancelled');
            window.socket.off('call_accepted');
            window.socket.off('call_declined');
            window.socket.off('call_timeout');

            window.socket.on('incoming_call', (data) => {
                console.log('Incoming call received:', data);
                this.showIncomingCall(data);
            });

            window.socket.on('call_cancelled', (data) => {
                console.log('Call cancelled:', data);
                this.hideCallPopup();
            });

            window.socket.on('call_accepted', (data) => {
                console.log('Call accepted:', data);
                this.hideCallPopup();
            });

            window.socket.on('call_declined', (data) => {
                console.log('Call declined:', data);
                this.hideCallPopup();
            });

            window.socket.on('call_timeout', (data) => {
                console.log('Call timed out:', data);
                this.hideCallPopup();
                if (typeof showNotification === 'function') {
                    showNotification('Call timed out after 30 seconds', 'error');
                }
            });

            // Re-setup listeners if socket reconnects
            window.socket.on('connect', () => {
                console.log('Socket reconnected, re-setting up call popup listeners');
                setTimeout(setupListeners, 500);
            });
        };

        setupListeners();
    }

    showIncomingCall(callData) {
        console.log('Showing incoming call popup:', callData);
        this.currentCall = callData;
        
        // Ensure popup exists and is attached to body
        if (!this.popupElement || !document.body.contains(this.popupElement)) {
            console.log('Recreating call popup element');
            this.createPopupElement();
        }
        
        // Update popup content
        const avatarText = this.popupElement.querySelector('.avatar-text');
        const callerName = this.popupElement.querySelector('.call-popup-name');
        const callTypeText = this.popupElement.querySelector('.call-type-text');
        const callTypeIcon = this.popupElement.querySelector('.call-popup-type i');

        avatarText.textContent = callData.caller_name ? callData.caller_name.charAt(0).toUpperCase() : 'U';
        callerName.textContent = callData.caller_name || 'Unknown User';
        
        if (callData.call_type === 'video') {
            callTypeText.textContent = 'Video Call';
            callTypeIcon.className = 'fas fa-video';
        } else {
            callTypeText.textContent = 'Voice Call';
            callTypeIcon.className = 'fas fa-phone';
        }

        // Force popup to be visible with maximum priority
        this.popupElement.style.display = 'block';
        this.popupElement.style.visibility = 'visible';
        this.popupElement.style.opacity = '1';
        this.popupElement.style.zIndex = '999999';
        this.popupElement.style.position = 'fixed';
        this.popupElement.style.top = '20px';
        this.popupElement.style.right = '20px';
        
        // Show popup with animation
        this.popupElement.classList.remove('hidden');
        this.popupElement.classList.add('call-popup-ring');

        // Start ringtone
        this.startRingtone();

        // Auto-decline after 30 seconds if no response
        this.ringTimeout = setTimeout(() => {
            console.log('Call auto-declined after 30 seconds');
            this.declineCall();
        }, 30000);

        // Request notification permission and show browser notification
        this.showBrowserNotification(callData);
    }

    showBrowserNotification(callData) {
        if ('Notification' in window) {
            if (Notification.permission === 'granted') {
                new Notification(`Incoming call from ${callData.caller_name || 'Unknown User'}`, {
                    icon: '/static/assets/logo.svg',
                    body: `${callData.call_type === 'video' ? 'Video' : 'Voice'} call`,
                    tag: 'incoming-call'
                });
            } else if (Notification.permission !== 'denied') {
                Notification.requestPermission().then(permission => {
                    if (permission === 'granted') {
                        new Notification(`Incoming call from ${callData.caller_name || 'Unknown User'}`, {
                            icon: '/static/assets/logo.svg',
                            body: `${callData.call_type === 'video' ? 'Video' : 'Voice'} call`,
                            tag: 'incoming-call'
                        });
                    }
                });
            }
        }
    }

    startRingtone() {
        // Create ringtone using Web Audio API or play system sound
        if (this.audioContext) {
            this.playWebAudioRingtone();
        } else {
            // Fallback to system notification sound
            this.playSystemRingtone();
        }
    }

    playWebAudioRingtone() {
        // Create a simple ringtone pattern
        const frequencies = [523.25, 659.25]; // C5, E5
        let currentFreq = 0;
        
        const playTone = () => {
            if (!this.currentCall) return;
            
            const oscillator = this.audioContext.createOscillator();
            const gainNode = this.audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(this.audioContext.destination);
            
            oscillator.frequency.setValueAtTime(frequencies[currentFreq], this.audioContext.currentTime);
            oscillator.type = 'sine';
            
            gainNode.gain.setValueAtTime(0, this.audioContext.currentTime);
            gainNode.gain.linearRampToValueAtTime(0.1, this.audioContext.currentTime + 0.1);
            gainNode.gain.linearRampToValueAtTime(0, this.audioContext.currentTime + 0.5);
            
            oscillator.start(this.audioContext.currentTime);
            oscillator.stop(this.audioContext.currentTime + 0.5);
            
            currentFreq = (currentFreq + 1) % frequencies.length;
            
            setTimeout(playTone, 1000);
        };
        
        playTone();
    }

    playSystemRingtone() {
        // Use a simple beep pattern for fallback
        const beep = () => {
            if (!this.currentCall) return;
            
            // Create a short beep using data URL
            const audio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmETCEar3/S4aB0HIozU8dGEOQkVUqzd7J1UFAxHouHivWMeHVmnt/l1+LdU2BqG2NWr2+8qgKgM2L7wkHSIw1l1+Ldd6jY');
            audio.volume = 0.1;
            audio.play().catch(e => console.warn('Could not play ringtone:', e));
            
            setTimeout(beep, 2000);
        };
        
        beep();
    }

    stopRingtone() {
        // Stop any ongoing ringtone
        if (this.audioContext) {
            // Web Audio API cleanup is handled by oscillator.stop()
        }
    }

    acceptCall() {
        if (!this.currentCall) return;
        
        console.log('Accepting call:', this.currentCall.call_id);
        
        // Send accept signal to server
        if (window.socket) {
            window.socket.emit('accept_call', {
                call_id: this.currentCall.call_id
            });
        }
        
        // Navigate to call screen
        window.location.href = `/call_screen/${this.currentCall.call_id}`;
        
        this.hideCallPopup();
    }

    declineCall() {
        if (!this.currentCall) return;
        
        console.log('Declining call:', this.currentCall.call_id);
        
        // Send decline signal to server
        if (window.socket) {
            window.socket.emit('decline_call', {
                call_id: this.currentCall.call_id
            });
        }
        
        this.hideCallPopup();
    }

    hideCallPopup() {
        if (this.ringTimeout) {
            clearTimeout(this.ringTimeout);
            this.ringTimeout = null;
        }
        
        this.stopRingtone();
        this.currentCall = null;
        
        if (this.popupElement) {
            this.popupElement.classList.add('hidden');
            this.popupElement.classList.remove('call-popup-ring');
        }
        
        // Clear browser notification
        if ('Notification' in window) {
            // Close any existing notifications with the same tag
            navigator.serviceWorker.ready.then(registration => {
                registration.getNotifications({ tag: 'incoming-call' }).then(notifications => {
                    notifications.forEach(notification => notification.close());
                });
            }).catch(() => {
                // Fallback for browsers without service worker
            });
        }
    }
}

// Initialize call popup system
let callPopup = null;

document.addEventListener('DOMContentLoaded', function() {
    // Wait for socket to be ready
    const initCallPopup = () => {
        if (window.socket) {
            callPopup = new CallPopupManager();
            window.callPopup = callPopup;
        } else {
            setTimeout(initCallPopup, 100);
        }
    };
    
    initCallPopup();
});

console.log('Call popup system loaded');