// Enhanced WebRTC Implementation for CommunicationX

class WebRTCCall {
    constructor(callId, isInitiator = false, callType = 'video') {
        this.callId = callId;
        this.isInitiator = isInitiator;
        this.callType = callType;
        this.localStream = null;
        this.remoteStream = null;
        this.peerConnection = null;
        this.socket = null;
        this.isMuted = false;
        this.isCameraOff = false;
        this.isConnected = false;
        this.connectionAttempts = 0;
        this.maxConnectionAttempts = 3;

        this.init();
    }

    async init() {
        try {
            console.log('Initializing WebRTC call...', { callId: this.callId, isInitiator: this.isInitiator });
            
            // Initialize socket connection first
            await this.initializeSocket();
            
            // Initialize peer connection
            this.setupPeerConnection();

            // Get user media
            await this.getUserMedia();

            // Setup socket events
            this.setupSocketEvents();

            // Join call room
            this.joinCallRoom();

            // Setup UI
            this.setupUI();
            
            // Start connection process
            await this.startConnection();

        } catch (error) {
            console.error('Error initializing call:', error);
            this.handleError('Failed to initialize call: ' + error.message);
        }
    }

    async initializeSocket() {
        return new Promise((resolve, reject) => {
            // Check if global socket exists and is connected
            if (window.socket && window.socket.connected) {
                console.log('Using existing socket connection for call');
                this.socket = window.socket;
                this.isConnected = true;
                resolve();
                return;
            }
            
            // Create new socket if needed
            if (window.io) {
                this.socket = io({
                    transports: ['websocket', 'polling'],
                    timeout: 10000,
                    reconnection: true,
                    reconnectionAttempts: 5,
                    reconnectionDelay: 1000
                });

                this.socket.on('connect', () => {
                    console.log('Socket connected for call');
                    this.isConnected = true;
                    resolve();
                });

                this.socket.on('connect_error', (error) => {
                    console.error('Socket connection error:', error);
                    reject(new Error('Socket connection failed'));
                });

                this.socket.on('disconnect', () => {
                    console.log('Socket disconnected during call');
                    this.isConnected = false;
                });
                
                this.socket.on('reconnect', () => {
                    console.log('Socket reconnected for call');
                    this.isConnected = true;
                    this.joinCallRoom();
                });
            } else {
                reject(new Error('Socket.IO not available'));
            }
        });
    }

    joinCallRoom() {
        if (this.socket && this.isConnected) {
            console.log('Joining call room:', this.callId);
            this.socket.emit('join_call', { call_id: this.callId });
        }
    }

    async startConnection() {
        if (this.isInitiator) {
            console.log('Initiator creating offer...');
            setTimeout(() => this.createOffer(), 1000); // Small delay to ensure everything is set up
        } else {
            console.log('Waiting for offer...');
        }
    }

    setupPeerConnection() {
        const configuration = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' },
                { urls: 'stun:stun2.l.google.com:19302' }
            ]
        };

        try {
            this.peerConnection = new RTCPeerConnection(configuration);
            console.log('Peer connection created');

            // Handle remote stream
            this.peerConnection.ontrack = (event) => {
                console.log('Received remote track:', event.track.kind);
                this.remoteStream = event.streams[0];
                
                const remoteVideo = document.getElementById('remoteVideo');
                if (remoteVideo) {
                    remoteVideo.srcObject = this.remoteStream;
                    this.updateCallStatus('Connected');
                }
            };

            // Handle ICE candidates
            this.peerConnection.onicecandidate = (event) => {
                if (event.candidate) {
                    console.log('Sending ICE candidate');
                    if (this.socket && this.isConnected) {
                        this.socket.emit('webrtc_ice_candidate', {
                            call_id: this.callId,
                            candidate: event.candidate
                        });
                    }
                }
            };

            // Handle connection state changes
            this.peerConnection.onconnectionstatechange = () => {
                console.log('Connection state changed:', this.peerConnection.connectionState);
                this.updateCallStatus('Connection: ' + this.peerConnection.connectionState);
                
                if (this.peerConnection.connectionState === 'connected') {
                    this.updateCallStatus('Connected');
                } else if (this.peerConnection.connectionState === 'failed') {
                    this.handleError('Connection failed');
                }
            };

            // Handle ICE connection state
            this.peerConnection.oniceconnectionstatechange = () => {
                console.log('ICE connection state:', this.peerConnection.iceConnectionState);
                
                if (this.peerConnection.iceConnectionState === 'failed') {
                    this.handleError('Connection failed - please check your network');
                }
            };

        } catch (error) {
            console.error('Error creating peer connection:', error);
            throw new Error('Failed to create peer connection');
        }
    }

    async getUserMedia() {
        try {
            const constraints = {
                video: this.callType === 'video' ? { 
                    width: { ideal: 640 }, 
                    height: { ideal: 480 },
                    facingMode: 'user'
                } : false,
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true
                }
            };

            console.log('Requesting media with constraints:', constraints);
            this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
            console.log('Got local stream:', this.localStream.getTracks().map(t => t.kind));

            // Display local video
            const localVideo = document.getElementById('localVideo');
            if (localVideo && this.callType === 'video') {
                localVideo.srcObject = this.localStream;
                localVideo.muted = true; // Prevent echo
            }

            // Add tracks to peer connection
            if (this.peerConnection) {
                this.localStream.getTracks().forEach(track => {
                    console.log('Adding track:', track.kind);
                    this.peerConnection.addTrack(track, this.localStream);
                });
            }

            this.updateCallStatus('Media ready');

        } catch (error) {
            console.error('Error accessing media devices:', error);
            
            // Try audio-only fallback
            if (this.callType === 'video') {
                try {
                    console.log('Video failed, trying audio-only...');
                    const audioConstraints = { video: false, audio: true };
                    this.localStream = await navigator.mediaDevices.getUserMedia(audioConstraints);
                    this.callType = 'audio';
                    
                    if (this.peerConnection) {
                        this.localStream.getTracks().forEach(track => {
                            this.peerConnection.addTrack(track, this.localStream);
                        });
                    }
                    
                    this.updateCallStatus('Audio Only');
                    console.log('Fallback to audio-only successful');
                } catch (audioError) {
                    console.error('Audio fallback also failed:', audioError);
                    throw new Error('Could not access microphone. Please check permissions.');
                }
            } else {
                throw new Error('Could not access microphone. Please check permissions.');
            }
        }
    }

    setupSocketEvents() {
        if (!this.socket) return;

        this.socket.on('user_joined_call', (data) => {
            console.log('User joined call:', data);
            this.updateCallStatus('User joined');
        });

        this.socket.on('user_left_call', (data) => {
            console.log('User left call:', data);
            this.updateCallStatus('User left');
            setTimeout(() => this.endCall(), 2000);
        });

        this.socket.on('webrtc_offer', async (data) => {
            console.log('Received WebRTC offer:', data);
            if (data.call_id === this.callId) {
                await this.handleOffer(data.offer);
            }
        });

        this.socket.on('webrtc_answer', async (data) => {
            console.log('Received WebRTC answer:', data);
            if (data.call_id === this.callId) {
                await this.handleAnswer(data.answer);
            }
        });

        this.socket.on('webrtc_ice_candidate', async (data) => {
            console.log('Received ICE candidate:', data);
            if (data.call_id === this.callId) {
                await this.handleIceCandidate(data.candidate);
            }
        });

        this.socket.on('call_ended', (data) => {
            console.log('Call ended by remote user:', data);
            this.updateCallStatus('Call ended');
            this.endCall();
        });

        this.socket.on('call_error', (data) => {
            console.error('Call error:', data);
            this.handleError(data.error || 'Call error occurred');
        });
    }

    async createOffer() {
        try {
            console.log('Creating offer...');
            const offer = await this.peerConnection.createOffer({
                offerToReceiveAudio: true,
                offerToReceiveVideo: this.callType === 'video'
            });
            
            await this.peerConnection.setLocalDescription(offer);
            console.log('Local description set, sending offer');
            
            if (this.socket && this.isConnected) {
                this.socket.emit('webrtc_offer', {
                    call_id: this.callId,
                    offer: offer
                });
            }
        } catch (error) {
            console.error('Error creating offer:', error);
            this.handleError('Failed to create call offer');
        }
    }

    async handleOffer(offer) {
        try {
            console.log('Handling offer...');
            await this.peerConnection.setRemoteDescription(offer);
            
            const answer = await this.peerConnection.createAnswer();
            await this.peerConnection.setLocalDescription(answer);
            
            console.log('Sending answer');
            if (this.socket && this.isConnected) {
                this.socket.emit('webrtc_answer', {
                    call_id: this.callId,
                    answer: answer
                });
            }
        } catch (error) {
            console.error('Error handling offer:', error);
            this.handleError('Failed to handle call offer');
        }
    }

    async handleAnswer(answer) {
        try {
            console.log('Handling answer...');
            await this.peerConnection.setRemoteDescription(answer);
        } catch (error) {
            console.error('Error handling answer:', error);
            this.handleError('Failed to handle call answer');
        }
    }

    async handleIceCandidate(candidate) {
        try {
            console.log('Adding ICE candidate...');
            await this.peerConnection.addIceCandidate(candidate);
        } catch (error) {
            console.error('Error adding ICE candidate:', error);
        }
    }

    setupUI() {
        // Toggle mute
        const muteBtn = document.getElementById('muteButton');
        if (muteBtn) {
            muteBtn.addEventListener('click', () => this.toggleMute());
        }

        // Toggle camera
        const cameraBtn = document.getElementById('cameraButton');
        if (cameraBtn) {
            cameraBtn.addEventListener('click', () => this.toggleCamera());
        }

        // End call
        const endBtn = document.getElementById('endCallButton');
        if (endBtn) {
            endBtn.addEventListener('click', () => this.endCall());
        }
    }

    toggleMute() {
        if (this.localStream) {
            const audioTrack = this.localStream.getAudioTracks()[0];
            if (audioTrack) {
                audioTrack.enabled = !audioTrack.enabled;
                this.isMuted = !audioTrack.enabled;
                
                const muteBtn = document.getElementById('muteButton');
                if (muteBtn) {
                    muteBtn.innerHTML = this.isMuted ? 
                        '<i class="fas fa-microphone-slash"></i>' : 
                        '<i class="fas fa-microphone"></i>';
                    muteBtn.classList.toggle('btn-danger', this.isMuted);
                    muteBtn.classList.toggle('btn-secondary', !this.isMuted);
                }
            }
        }
    }

    toggleCamera() {
        if (this.localStream && this.callType === 'video') {
            const videoTrack = this.localStream.getVideoTracks()[0];
            if (videoTrack) {
                videoTrack.enabled = !videoTrack.enabled;
                this.isCameraOff = !videoTrack.enabled;
                
                const cameraBtn = document.getElementById('cameraButton');
                if (cameraBtn) {
                    cameraBtn.innerHTML = this.isCameraOff ? 
                        '<i class="fas fa-video-slash"></i>' : 
                        '<i class="fas fa-video"></i>';
                    cameraBtn.classList.toggle('btn-danger', this.isCameraOff);
                    cameraBtn.classList.toggle('btn-secondary', !this.isCameraOff);
                }
            }
        }
    }

    endCall() {
        console.log('Ending call...');
        
        // Stop local stream
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
            this.localStream = null;
        }

        // Close peer connection
        if (this.peerConnection) {
            this.peerConnection.close();
            this.peerConnection = null;
        }

        // Notify server
        if (this.socket && this.isConnected) {
            this.socket.emit('end_call', { call_id: this.callId });
        }

        // Redirect back
        setTimeout(() => {
            window.location.href = '/';
        }, 1000);
    }

    updateCallStatus(status) {
        const statusElement = document.getElementById('callStatus');
        if (statusElement) {
            statusElement.textContent = status;
        }
        console.log('Call status:', status);
    }

    handleError(error) {
        console.error('Call error:', error);
        this.updateCallStatus('Error: ' + error);
        
        // Show error to user
        const errorDiv = document.createElement('div');
        errorDiv.className = 'alert alert-danger mt-3';
        errorDiv.textContent = error;
        
        const container = document.querySelector('.call-card');
        if (container) {
            container.appendChild(errorDiv);
        }
        
        // End call after showing error
        setTimeout(() => this.endCall(), 3000);
    }
}

// Initialize WebRTC when page loads
document.addEventListener('DOMContentLoaded', function() {
    const callContainer = document.querySelector('.call-container');
    if (callContainer) {
        const callId = callContainer.dataset.callId;
        const isInitiator = callContainer.dataset.isInitiator === 'true';
        const callType = callContainer.dataset.callType || 'video';
        
        console.log('Starting WebRTC call:', { callId, isInitiator, callType });
        window.webrtcCall = new WebRTCCall(callId, isInitiator, callType);
    }
});

// Export for global access
window.WebRTCCall = WebRTCCall;