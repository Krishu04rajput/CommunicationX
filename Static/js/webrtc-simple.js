// Simple WebRTC Call Implementation for CommunicationX

let currentCall = null;
let localStream = null;
let remoteStream = null;
let peerConnection = null;
let callSocket = null;

// WebRTC Configuration
const rtcConfig = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' }
    ]
};

// Initialize call when page loads
document.addEventListener('DOMContentLoaded', function() {
    const callData = document.querySelector('[data-call-id]');
    if (callData) {
        const callId = callData.dataset.callId;
        const isInitiator = callData.dataset.isInitiator === 'true';
        const callType = callData.dataset.callType || 'audio';

        initializeCall(callId, isInitiator, callType);
    }
});

async function initializeCall(callId, isInitiator, callType) {
    try {
        console.log('Starting call:', { callId, isInitiator, callType });

        currentCall = { callId, isInitiator, callType };

        // Initialize socket connection
        if (window.socket && window.socket.connected) {
            callSocket = window.socket;
        } else if (window.io) {
            callSocket = io();
        }

        if (!callSocket) {
            throw new Error('Socket connection failed');
        }

        // Setup socket events
        setupCallSocketEvents();

        // Get user media first
        await getUserMedia(callType);

        // Setup peer connection
        setupPeerConnection();

        // Join call room
        callSocket.emit('join_call', { call_id: callId });

        // Start connection if initiator
        if (isInitiator) {
            setTimeout(createOffer, 1000);
        }

        updateCallStatus('Connecting...');

    } catch (error) {
        console.error('Call initialization failed:', error);
        updateCallStatus('Failed to start call: ' + error.message);
    }
}

async function getUserMedia(callType) {
    try {
        const constraints = {
            audio: true,
            video: callType === 'video'
        };

        console.log('Getting user media:', constraints);
        localStream = await navigator.mediaDevices.getUserMedia(constraints);

        // Display local video if video call
        if (callType === 'video') {
            const localVideo = document.getElementById('localVideo');
            if (localVideo) {
                localVideo.srcObject = localStream;
                localVideo.muted = true;
            }
        }

        updateCallStatus('Media ready');

    } catch (error) {
        console.error('Media access failed:', error);

        // Fallback to audio only
        if (callType === 'video') {
            try {
                localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
                currentCall.callType = 'audio';
                updateCallStatus('Audio only mode');
            } catch (audioError) {
                throw new Error('Cannot access microphone');
            }
        } else {
            throw new Error('Cannot access microphone');
        }
    }
}

function setupPeerConnection() {
    peerConnection = new RTCPeerConnection(rtcConfig);

    // Add local stream tracks
    if (localStream) {
        localStream.getTracks().forEach(track => {
            peerConnection.addTrack(track, localStream);
        });
    }

    // Handle remote stream
    peerConnection.ontrack = (event) => {
        console.log('Received remote stream');
        remoteStream = event.streams[0];

        const remoteVideo = document.getElementById('remoteVideo');
        if (remoteVideo) {
            remoteVideo.srcObject = remoteStream;
        }

        updateCallStatus('Connected');
    };

    // Handle ICE candidates
    peerConnection.onicecandidate = (event) => {
        if (event.candidate && callSocket) {
            callSocket.emit('webrtc_ice_candidate', {
                call_id: currentCall.callId,
                candidate: event.candidate
            });
        }
    };

    // Handle connection state
    peerConnection.onconnectionstatechange = () => {
        console.log('Connection state:', peerConnection.connectionState);

        if (peerConnection.connectionState === 'connected') {
            updateCallStatus('Connected');
        } else if (peerConnection.connectionState === 'failed') {
            updateCallStatus('Connection failed');
        }
    };
}

function setupCallSocketEvents() {
    callSocket.on('webrtc_offer', async (data) => {
        if (data.call_id === currentCall.callId) {
            console.log('Received offer');
            await handleOffer(data.offer);
        }
    });

    callSocket.on('webrtc_answer', async (data) => {
        if (data.call_id === currentCall.callId) {
            console.log('Received answer');
            await handleAnswer(data.answer);
        }
    });

    callSocket.on('webrtc_ice_candidate', async (data) => {
        if (data.call_id === currentCall.callId) {
            console.log('Received ICE candidate');
            await peerConnection.addIceCandidate(data.candidate);
        }
    });

    callSocket.on('call_ended', () => {
        console.log('Call ended by remote user');
        endCall(false);
    });

    callSocket.on('user_joined_call', (data) => {
        console.log('User joined call:', data);
        updateCallStatus('User joined');
    });
}

async function createOffer() {
    try {
        console.log('Creating offer...');
        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);

        callSocket.emit('webrtc_offer', {
            call_id: currentCall.callId,
            offer: offer
        });

        updateCallStatus('Calling...');

    } catch (error) {
        console.error('Error creating offer:', error);
        updateCallStatus('Failed to create call');
    }
}

async function handleOffer(offer) {
    try {
        await peerConnection.setRemoteDescription(offer);
        const answer = await peerConnection.createAnswer();
        await peerConnection.setLocalDescription(answer);

        callSocket.emit('webrtc_answer', {
            call_id: currentCall.callId,
            answer: answer
        });

        updateCallStatus('Answering...');

    } catch (error) {
        console.error('Error handling offer:', error);
        updateCallStatus('Failed to answer call');
    }
}

async function handleAnswer(answer) {
    try {
        await peerConnection.setRemoteDescription(answer);
        updateCallStatus('Connecting...');
    } catch (error) {
        console.error('Error handling answer:', error);
        updateCallStatus('Connection failed');
    }
}

function toggleMute() {
    if (localStream) {
        const audioTrack = localStream.getAudioTracks()[0];
        if (audioTrack) {
            audioTrack.enabled = !audioTrack.enabled;

            const muteBtn = document.getElementById('muteButton');
            if (muteBtn) {
                if (audioTrack.enabled) {
                    muteBtn.innerHTML = '<i class="fas fa-microphone"></i>';
                    muteBtn.classList.remove('btn-danger');
                    muteBtn.classList.add('btn-secondary');
                } else {
                    muteBtn.innerHTML = '<i class="fas fa-microphone-slash"></i>';
                    muteBtn.classList.remove('btn-secondary');
                    muteBtn.classList.add('btn-danger');
                }
            }
        }
    }
}

function toggleCamera() {
    if (localStream && currentCall.callType === 'video') {
        const videoTrack = localStream.getVideoTracks()[0];
        if (videoTrack) {
            videoTrack.enabled = !videoTrack.enabled;

            const cameraBtn = document.getElementById('cameraButton');
            if (cameraBtn) {
                if (videoTrack.enabled) {
                    cameraBtn.innerHTML = '<i class="fas fa-video"></i>';
                    cameraBtn.classList.remove('btn-danger');
                    cameraBtn.classList.add('btn-secondary');
                } else {
                    cameraBtn.innerHTML = '<i class="fas fa-video-slash"></i>';
                    cameraBtn.classList.remove('btn-secondary');
                    cameraBtn.classList.add('btn-danger');
                }
            }
        }
    }
}

function endCall(notifyServer = true) {
    console.log('Ending call...');

    // Stop local stream
    if (localStream) {
        localStream.getTracks().forEach(track => track.stop());
        localStream = null;
    }

    // Close peer connection
    if (peerConnection) {
        peerConnection.close();
        peerConnection = null;
    }

    // Notify server
    if (notifyServer && callSocket && currentCall) {
        callSocket.emit('end_call', { call_id: currentCall.callId });
    }

    updateCallStatus('Call ended');

    // Redirect back
    setTimeout(() => {
        window.location.href = '/';
    }, 1500);
}

function updateCallStatus(status) {
    console.log('Call status:', status);

    const statusElement = document.getElementById('callStatus');
    if (statusElement) {
        statusElement.textContent = status;
    }

    const userStatusElement = document.querySelector('.call-status');
    if (userStatusElement) {
        userStatusElement.textContent = status;
    }
}

// Setup UI event listeners
document.addEventListener('DOMContentLoaded', function() {
    const muteBtn = document.getElementById('muteButton');
    if (muteBtn) {
        muteBtn.addEventListener('click', toggleMute);
    }

    const cameraBtn = document.getElementById('cameraButton');
    if (cameraBtn) {
        cameraBtn.addEventListener('click', toggleCamera);
    }

    const endBtn = document.getElementById('endCallButton');
    if (endBtn) {
        endBtn.addEventListener('click', () => endCall(true));
    }
});

// Export functions for global access
window.toggleMute = toggleMute;
window.toggleCamera = toggleCamera;
window.endCall = endCall;

// Handle call timeout
if (window.socket) {
    window.socket.on('call_timeout', function(data) {
            console.log('Call timed out:', data);
            showCallStatus('Call timed out', 'error');

            // End the call
            endCall();
        });
}

        // Voicemail recording
        let voicemailRecorder = null;
        let voicemailChunks = [];
        let voicemailTimer = null;
        let voicemailSeconds = 0;

        document.getElementById('recordVoicemail').addEventListener('click', function() {
            startVoicemailRecording();
        });

        document.getElementById('stopVoicemail').addEventListener('click', function() {
            stopVoicemailRecording();
        });

        document.getElementById('cancelVoicemail').addEventListener('click', function() {
            cancelVoicemailRecording();
        });

        function startVoicemailRecording() {
            navigator.mediaDevices.getUserMedia({ audio: true })
                .then(stream => {
                    voicemailRecorder = new MediaRecorder(stream);
                    voicemailChunks = [];
                    voicemailSeconds = 0;

                    voicemailRecorder.ondataavailable = function(e) {
                        voicemailChunks.push(e.data);
                    };

                    voicemailRecorder.onstop = function() {
                        const blob = new Blob(voicemailChunks, { type: 'audio/wav' });
                        sendVoicemail(blob);
                    };

                    voicemailRecorder.start();

                    // Show recording UI
                    document.getElementById('voicemailRecording').style.display = 'block';
                    document.getElementById('recordVoicemail').style.display = 'none';

                    // Start timer
                    voicemailTimer = setInterval(function() {
                        voicemailSeconds++;
                        const minutes = Math.floor(voicemailSeconds / 60);
                        const seconds = voicemailSeconds % 60;
                        document.querySelector('.recording-timer').textContent = 
                            `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                    }, 1000);

                    // Auto-stop after 5 minutes
                    setTimeout(function() {
                        if (voicemailRecorder && voicemailRecorder.state === 'recording') {
                            stopVoicemailRecording();
                        }
                    }, 300000); // 5 minutes
                })
                .catch(err => {
                    console.error('Error starting voicemail recording:', err);
                    alert('Failed to start voicemail recording');
                });
        }

        function stopVoicemailRecording() {
            if (voicemailRecorder && voicemailRecorder.state === 'recording') {
                voicemailRecorder.stop();
                clearInterval(voicemailTimer);

                // Stop all tracks
                voicemailRecorder.stream.getTracks().forEach(track => track.stop());
            }
        }

        function cancelVoicemailRecording() {
            if (voicemailRecorder && voicemailRecorder.state === 'recording') {
                voicemailRecorder.stop();
                voicemailRecorder.stream.getTracks().forEach(track => track.stop());
            }

            clearInterval(voicemailTimer);
            document.getElementById('voicemailRecording').style.display = 'none';
            document.getElementById('recordVoicemail').style.display = 'block';
            document.getElementById('endCall').style.display = 'block';
            voicemailChunks = [];
        }

        function sendVoicemail(audioBlob) {
            const formData = new FormData();
            formData.append('voicemail', audioBlob, 'voicemail.wav');
            formData.append('recipient_id', otherUserId);

            fetch('/api/send_voicemail', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showCallStatus('Voicemail sent successfully!', 'success');
                    setTimeout(() => {
                        endCall();
                    }, 2000);
                } else {
                    showCallStatus('Failed to send voicemail', 'error');
                }
            })
            .catch(error => {
                console.error('Error sending voicemail:', error);
                showCallStatus('Failed to send voicemail', 'error');
            });

            document.getElementById('voicemailRecording').style.display = 'none';
        }