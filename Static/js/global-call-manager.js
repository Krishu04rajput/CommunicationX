// Global Call Manager - Ensures call popups appear on every screen
console.log('Loading global call manager...');

class GlobalCallManager {
    constructor() {
        this.activeCall = null;
        this.popupElement = null;
        this.ringtone = null;
        this.init();
    }

    init() {
        this.createGlobalPopup();
        this.setupGlobalListeners();
        this.monitorSocketConnection();
        console.log('Global call manager initialized');
    }

    createGlobalPopup() {
        // Remove any existing popup
        const existing = document.querySelector('.global-call-popup');
        if (existing) {
            existing.remove();
        }

        this.popupElement = document.createElement('div');
        this.popupElement.className = 'global-call-popup';
        this.popupElement.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 999999;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 15px;
            padding: 20px;
            min-width: 350px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(20px);
            border: 2px solid rgba(255, 255, 255, 0.2);
            color: white;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: none;
            animation: callPopupSlide 0.3s ease-out;
        `;

        this.popupElement.innerHTML = `
            <div style="display: flex; align-items: center; margin-bottom: 15px;">
                <div style="width: 50px; height: 50px; border-radius: 50%; background: rgba(255,255,255,0.2); display: flex; align-items: center; justify-content: center; margin-right: 15px; font-size: 20px; font-weight: bold;">
                    <span class="caller-avatar">U</span>
                </div>
                <div style="flex: 1;">
                    <h4 style="margin: 0; font-size: 18px; font-weight: 600;" class="caller-name">Unknown User</h4>
                    <p style="margin: 5px 0 0 0; opacity: 0.8; font-size: 14px;">
                        <i class="fas fa-phone" style="margin-right: 5px;"></i>
                        <span class="call-type">Voice Call</span>
                    </p>
                </div>
            </div>
            <div style="display: flex; justify-content: space-between; gap: 15px;">
                <button onclick="globalCallManager.declineCall()" style="
                    background: rgba(255, 59, 48, 0.8);
                    border: none;
                    border-radius: 50%;
                    width: 60px;
                    height: 60px;
                    color: white;
                    font-size: 24px;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    backdrop-filter: blur(10px);
                " onmouseover="this.style.background='rgba(255, 59, 48, 1)'" onmouseout="this.style.background='rgba(255, 59, 48, 0.8)'">
                    <i class="fas fa-phone-slash"></i>
                </button>
                <button onclick="globalCallManager.acceptCall()" style="
                    background: rgba(52, 199, 89, 0.8);
                    border: none;
                    border-radius: 50%;
                    width: 60px;
                    height: 60px;
                    color: white;
                    font-size: 24px;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    backdrop-filter: blur(10px);
                " onmouseover="this.style.background='rgba(52, 199, 89, 1)'" onmouseout="this.style.background='rgba(52, 199, 89, 0.8)'">
                    <i class="fas fa-phone"></i>
                </button>
            </div>
        `;

        // Add CSS animation
        if (!document.querySelector('#call-popup-styles')) {
            const style = document.createElement('style');
            style.id = 'call-popup-styles';
            style.textContent = `
                @keyframes callPopupSlide {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
                .global-call-popup {
                    animation: callPopupSlide 0.3s ease-out;
                }
            `;
            document.head.appendChild(style);
        }

        document.body.appendChild(this.popupElement);
    }

    setupGlobalListeners() {
        const setupListeners = () => {
            if (!window.socket || !window.socket.connected) {
                setTimeout(setupListeners, 1000);
                return;
            }

            // Set up global call listeners only once
            if (window.callListenersSetup) {
                return;
            }
            window.callListenersSetup = true;
            console.log('Setting up global call listeners');

            // Remove existing listeners
            window.socket.off('incoming_call.global');
            window.socket.off('call_ended.global');
            window.socket.off('call_timeout.global');

            window.socket.on('incoming_call', (data) => {
                console.log('Global call manager: Incoming call', data);
                this.showCall(data);
            });

            window.socket.on('call_ended', (data) => {
                console.log('Global call manager: Call ended');
                this.hideCall();
            });

            window.socket.on('call_timeout', (data) => {
                console.log('Global call manager: Call timeout');
                this.hideCall();
            });

            window.socket.on('call_cancelled', (data) => {
                console.log('Global call manager: Call cancelled');
                this.hideCall();
            });
        };

        setupListeners();
    }

    monitorSocketConnection() {
        setInterval(() => {
            if (window.socket && window.socket.connected) {
                // Socket is connected, ensure listeners are set up
                this.setupGlobalListeners();
            }
        }, 5000);
    }

    showCall(callData) {
        console.log('Showing global call popup:', callData);
        this.activeCall = callData;

        // Ensure popup exists
        if (!this.popupElement || !document.body.contains(this.popupElement)) {
            this.createGlobalPopup();
        }

        // Update popup content
        const avatar = this.popupElement.querySelector('.caller-avatar');
        const name = this.popupElement.querySelector('.caller-name');
        const type = this.popupElement.querySelector('.call-type');
        const icon = this.popupElement.querySelector('.fas');

        avatar.textContent = callData.caller_name ? callData.caller_name.charAt(0).toUpperCase() : 'U';
        name.textContent = callData.caller_name || 'Unknown User';

        if (callData.call_type === 'video') {
            type.textContent = 'Video Call';
            icon.className = 'fas fa-video';
        } else {
            type.textContent = 'Voice Call';
            icon.className = 'fas fa-phone';
        }

        // Show popup
        this.popupElement.style.display = 'block';

        // Auto-decline after 30 seconds
        setTimeout(() => {
            if (this.activeCall && this.activeCall.call_id === callData.call_id) {
                console.log('Auto-declining call after 30 seconds');
                this.declineCall();
            }
        }, 30000);

        // Play ringtone
        this.playRingtone();
    }

    hideCall() {
        console.log('Hiding global call popup');
        this.activeCall = null;
        if (this.popupElement) {
            this.popupElement.style.display = 'none';
        }
        this.stopRingtone();
    }

    acceptCall() {
        if (!this.activeCall || !window.socket) return;

        console.log('Accepting call:', this.activeCall.call_id);
        window.socket.emit('accept_call', { call_id: this.activeCall.call_id });

        // Redirect to call screen
        window.location.href = `/call_screen/${this.activeCall.call_id}`;

        this.hideCall();
    }

    declineCall() {
        if (!this.activeCall || !window.socket) return;

        console.log('Declining call:', this.activeCall.call_id);
        window.socket.emit('decline_call', { call_id: this.activeCall.call_id });

        this.hideCall();
    }

    playRingtone() {
        // Create simple ringtone using Web Audio API
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();

            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);

            oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
            oscillator.type = 'sine';
            gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);

            oscillator.start();

            // Ring pattern: on for 1s, off for 0.5s
            this.ringtoneInterval = setInterval(() => {
                if (this.activeCall) {
                    const newOscillator = audioContext.createOscillator();
                    const newGain = audioContext.createGain();

                    newOscillator.connect(newGain);
                    newGain.connect(audioContext.destination);

                    newOscillator.frequency.setValueAtTime(800, audioContext.currentTime);
                    newOscillator.type = 'sine';
                    newGain.gain.setValueAtTime(0.1, audioContext.currentTime);

                    newOscillator.start();
                    newOscillator.stop(audioContext.currentTime + 1);
                }
            }, 1500);

            setTimeout(() => oscillator.stop(), 1000);
        } catch (error) {
            console.log('Could not play ringtone:', error);
        }
    }

    stopRingtone() {
        if (this.ringtoneInterval) {
            clearInterval(this.ringtoneInterval);
            this.ringtoneInterval = null;
        }
    }
}

// Global call manager to handle Discord-like call notifications
let globalCallManager = null;
let callNotificationSound = null;
let globalCallManagerInitialized = false;

function initializeGlobalCallManager() {
    if (globalCallManagerInitialized) {
        return;
    }
    globalCallManagerInitialized = true;
    console.log('Setting up global call listeners');
    
    // Initialize only once
    if (!window.globalCallManager) {
        window.globalCallManager = new GlobalCallManager();
        console.log('Global call manager loaded');
    }
}

// Initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeGlobalCallManager);
} else {
    initializeGlobalCallManager();
}