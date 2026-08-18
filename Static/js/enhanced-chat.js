// Enhanced Chat and Calling Functionality for CommunicationX

class EnhancedChat {
    constructor() {
        this.isRecording = false;
        this.mediaRecorder = null;
        this.recordingChunks = [];
        this.recordingStartTime = null;
        this.typingTimer = null;
        this.replyToMessage = null;
        this.emojiPickerVisible = false;

        this.init();
    }

    init() {
        this.bindMessageInputEvents();
        this.bindFileUploadEvents();
        this.bindVoiceRecordingEvents();
        this.bindCallEvents();
        this.initEmojiPicker();
    }

    bindMessageInputEvents() {
        // Enhanced message input handling
        const messageInputs = document.querySelectorAll('.message-input.enhanced');
        messageInputs.forEach(input => {
            input.addEventListener('input', (e) => this.handleMessageInput(e.target));
            input.addEventListener('keydown', (e) => this.handleKeyDown(e));
            input.addEventListener('paste', (e) => this.handlePaste(e));
        });

        // Send button state management
        this.updateSendButtonState();
    }

    handleMessageInput(input) {
        const content = input.value.trim();
        const charCount = content.length;
        const maxLength = 2000;

        // Update character counter
        const counter = input.parentElement.querySelector('.input-counter');
        const charCountSpan = counter?.querySelector('.char-count');

        if (counter && charCountSpan) {
            charCountSpan.textContent = charCount;
            counter.style.display = charCount > maxLength * 0.8 ? 'block' : 'none';

            if (charCount > maxLength) {
                counter.style.color = '#dc3545';
            } else if (charCount > maxLength * 0.9) {
                counter.style.color = '#ffc107';
            } else {
                counter.style.color = '#6c757d';
            }
        }

        // Auto-resize textarea
        input.style.height = 'auto';
        input.style.height = Math.min(input.scrollHeight, 120) + 'px';

        // Update send button state
        this.updateSendButtonState();

        // Typing indicator
        this.handleTypingIndicator(input);
    }

    handleKeyDown(event) {
        const input = event.target;

        // Send message on Enter (but not Shift+Enter)
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault();
            const form = input.closest('form');
            if (form && input.value.trim()) {
                this.sendMessage(form);
            }
        }

        // Clear reply on Escape
        if (event.key === 'Escape') {
            this.cancelReply();
        }
    }

    handlePaste(event) {
        const items = event.clipboardData?.items;
        if (!items) return;

        for (let item of items) {
            if (item.type.indexOf('image') !== -1) {
                event.preventDefault();
                const file = item.getAsFile();
                this.handleImageUpload(file);
                break;
            }
        }
    }

    updateSendButtonState() {
        const forms = document.querySelectorAll('.message-form');
        forms.forEach(form => {
            const input = form.querySelector('.message-input');
            const sendBtn = form.querySelector('.send-btn');

            if (input && sendBtn) {
                const hasContent = input.value.trim().length > 0;
                sendBtn.disabled = !hasContent;
            }
        });
    }

    handleTypingIndicator(input) {
        const form = input.closest('form');
        const channelId = form?.dataset.channelId;
        const recipientId = form?.dataset.recipientId;

        if (!channelId && !recipientId) return;

        // Clear existing timer
        clearTimeout(this.typingTimer);

        // Send typing start event
        if (window.app?.socket) {
            window.app.socket.emit('typing_start', {
                channel_id: channelId,
                recipient_id: recipientId
            });
        }

        // Set timer to send typing stop event
        this.typingTimer = setTimeout(() => {
            if (window.app?.socket) {
                window.app.socket.emit('typing_stop', {
                    channel_id: channelId,
                    recipient_id: recipientId
                });
            }
        }, 3000);
    }

    sendMessage(form) {
        const input = form.querySelector('.message-input');
        const content = input.value.trim();

        if (!content) return;

        const channelId = form.dataset.channelId;
        const recipientId = form.dataset.recipientId;
        const replyToId = form.querySelector('#replyToId')?.value;

        const messageData = {
            content: content,
            reply_to: replyToId || null
        };

        // Use global socket
        const socket = window.socket;

        if (channelId) {
            messageData.channel_id = channelId;
            console.log('Sending channel message:', messageData);
            if (socket) {
                socket.emit('send_message', messageData);
            } else {
                // Fallback to form submission
                form.submit();
                return;
            }
        } else if (recipientId) {
            messageData.recipient_id = recipientId;
            console.log('Sending DM:', messageData);
            if (socket) {
                socket.emit('send_dm', messageData);
            } else {
                // Fallback to form submission
                form.submit();
                return;
            }
        }

        // Clear input and reset form
        input.value = '';
        input.style.height = 'auto';
        this.cancelReply();
        this.updateSendButtonState();
    }

    bindFileUploadEvents() {
        // File upload handling with 500MB limit
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const files = Array.from(e.target.files);
            if (files.length === 0) return;

            // Check file size limit (500MB)
            const maxSize = 500 * 1024 * 1024; // 500MB
            for (let file of files) {
                if (file.size > maxSize) {
                    alert(`File "${file.name}" is too large. Maximum size is 500MB.`);
                    e.target.value = ''; // Clear input
                    return;
                }
            }

            handleFileUpload(files);
        });
    });
    }

    handleFileSelection(event) {
        const files = Array.from(event.target.files);
        const previewArea = this.getFilePreviewArea(event.target);

        previewArea.innerHTML = '';
        previewArea.style.display = files.length > 0 ? 'block' : 'none';

        files.forEach((file, index) => {
            const preview = this.createFilePreview(file, index);
            previewArea.appendChild(preview);
        });
    }

    getFilePreviewArea(input) {
        const form = input.closest('form');
        return form.querySelector('.file-preview-area') || 
               form.querySelector('#filePreviewArea') || 
               form.querySelector('#dmFilePreviewArea');
    }

    createFilePreview(file, index) {
        const preview = document.createElement('div');
        preview.className = 'file-preview-item';
        preview.innerHTML = `
            <div class="file-info">
                <i class="fas fa-${this.getFileIcon(file.type)}"></i>
                <span class="file-name">${file.name}</span>
                <span class="file-size">${this.formatFileSize(file.size)}</span>
            </div>
            <button type="button" class="remove-file" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;

        // Add image preview for image files
        if (file.type.startsWith('image/')) {
            const img = document.createElement('img');
            img.className = 'image-preview';
            img.style.maxWidth = '200px';
            img.style.maxHeight = '150px';
            img.style.objectFit = 'cover';
            img.style.borderRadius = '4px';

            const reader = new FileReader();
            reader.onload = (e) => {
                img.src = e.target.result;
            };
            reader.readAsDataURL(file);

            preview.appendChild(img);
        }

        return preview;
    }

    getFileIcon(mimeType) {
        if (mimeType.startsWith('image/')) return 'image';
        if (mimeType.startsWith('video/')) return 'video';
        if (mimeType.startsWith('audio/')) return 'music';
        if (mimeType.includes('pdf')) return 'file-pdf';
        if (mimeType.includes('document') || mimeType.includes('word')) return 'file-word';
        return 'file';
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    bindVoiceRecordingEvents() {
        const voiceButtons = document.querySelectorAll('#voiceRecordBtn, #dmVoiceRecordBtn');
        voiceButtons.forEach(btn => {
            btn.addEventListener('click', () => this.toggleVoiceRecording(btn));
        });
    }

    async toggleVoiceRecording(button) {
        if (this.isRecording) {
            this.stopRecording();
        } else {
            await this.startRecording(button);
        }
    }

    async startRecording(button) {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });

            this.mediaRecorder = new MediaRecorder(stream);
            this.recordingChunks = [];
            this.recordingStartTime = Date.now();

            const recordingDiv = this.getRecordingDiv(button);
            recordingDiv.style.display = 'block';

            button.style.background = '#dc3545';
            button.style.color = 'white';

            this.mediaRecorder.ondataavailable = (event) => {
                if (event.data.size > 0) {
                    this.recordingChunks.push(event.data);
                }
            };

            this.mediaRecorder.onstop = () => {
                stream.getTracks().forEach(track => track.stop());
                this.processRecording();
            };

            this.mediaRecorder.start();
            this.isRecording = true;

            this.updateRecordingTimer(button);

        } catch (error) {
            console.error('Error starting recording:', error);
            showNotification('Could not access microphone', 'error');
        }
    }

    stopRecording() {
        if (this.mediaRecorder && this.isRecording) {
            this.mediaRecorder.stop();
            this.isRecording = false;
        }
    }

    cancelRecording() {
        if (this.isRecording) {
            this.mediaRecorder.stop();
            this.isRecording = false;
            this.recordingChunks = [];
        }

        // Hide recording indicators
        document.querySelectorAll('.voice-recording').forEach(div => {
            div.style.display = 'none';
        });

        // Reset button styles
        document.querySelectorAll('#voiceRecordBtn, #dmVoiceRecordBtn').forEach(btn => {
            btn.style.background = '';
            btn.style.color = '';
        });
    }

    getRecordingDiv(button) {
        const form = button.closest('form');
        return form.querySelector('.voice-recording') || 
               form.querySelector('#voiceRecording') || 
               form.querySelector('#dmVoiceRecording');
    }

    updateRecordingTimer(button) {
        const timerElement = this.getRecordingDiv(button).querySelector('[id$="RecordingTime"]');

        const updateTimer = () => {
            if (!this.isRecording) return;

            const elapsed = Date.now() - this.recordingStartTime;
            const seconds = Math.floor(elapsed / 1000);
            const minutes = Math.floor(seconds / 60);
            const remainingSeconds = seconds % 60;

            if (timerElement) {
                timerElement.textContent = `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
            }

            setTimeout(updateTimer, 1000);
        };

        updateTimer();
    }

    processRecording() {
        const audioBlob = new Blob(this.recordingChunks, { type: 'audio/webm' });
        // Here you would typically upload the audio file
        // For now, we'll just show a notification
        showNotification('Voice message recorded successfully', 'success');

        this.cancelRecording();
    }

    bindCallEvents() {
        // Server call buttons
        document.addEventListener('click', (e) => {
            if (e.target.matches('[onclick*="startServerCall"]')) {
                const callType = e.target.getAttribute('onclick').match(/'(\w+)'/)[1];
                this.startServerCall(callType);
            }
        });
    }

    startServerCall(callType) {
        const urlParams = new URLSearchParams(window.location.search);
        const serverId = window.location.pathname.split('/')[2];
        const channelId = urlParams.get('channel_id');

        if (serverId) {
            window.location.href = `/server/${serverId}/call?type=${callType}&channel_id=${channelId || ''}`;
        }
    }

    startDirectCall(userId, callType) {
        window.location.href = `/call/${userId}/${callType}`;
    }

    shareScreen() {
        if (navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia) {
            navigator.mediaDevices.getDisplayMedia({ video: true })
                .then(stream => {
                    showNotification('Screen sharing started', 'success');
                    // Handle screen sharing stream
                })
                .catch(err => {
                    console.error('Error sharing screen:', err);
                    showNotification('Could not start screen sharing', 'error');
                });
        } else {
            showNotification('Screen sharing not supported', 'error');
        }
    }

    shareScreenDM(userId) {
        // Similar to shareScreen but for DM context
        this.shareScreen();
    }

    initEmojiPicker() {
        // Basic emoji picker functionality
        document.addEventListener('click', (e) => {
            if (e.target.matches('.emoji-option')) {
                e.preventDefault();
                const emoji = e.target.textContent;
                this.insertEmoji(emoji);
            }
        });
    }

    toggleEmojiPicker() {
        // Toggle emoji picker visibility
        this.emojiPickerVisible = !this.emojiPickerVisible;
        // Implementation would show/hide emoji picker
    }

    insertEmoji(emoji) {
        const activeInput = document.querySelector('.message-input:focus');
        if (activeInput) {
            const cursorPos = activeInput.selectionStart;
            const textBefore = activeInput.value.substring(0, cursorPos);
            const textAfter = activeInput.value.substring(activeInput.selectionEnd);

            activeInput.value = textBefore + emoji + textAfter;
            activeInput.selectionStart = activeInput.selectionEnd = cursorPos + emoji.length;

            this.handleMessageInput(activeInput);
            activeInput.focus();
        }
    }

    replyToMessage(messageId) {
        const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
        if (!messageElement) return;

        const author = messageElement.querySelector('.message-author')?.textContent;
        const content = messageElement.querySelector('.message-text')?.textContent;

        if (author && content) {
            this.showReplyPreview(messageId, author, content);
        }
    }

    showReplyPreview(messageId, author, content) {
        const replyPreview = document.getElementById('replyPreview');
        const replyUser = replyPreview?.querySelector('.reply-user');
        const replyMessage = replyPreview?.querySelector('.reply-message');
        const replyToInput = document.getElementById('replyToId');

        if (replyPreview && replyUser && replyMessage && replyToInput) {
            replyUser.textContent = author;
            replyMessage.textContent = content.length > 50 ? content.substring(0, 50) + '...' : content;
            replyToInput.value = messageId;
            replyPreview.style.display = 'block';
        }
    }

    cancelReply() {
        const replyPreview = document.getElementById('replyPreview');
        const replyToInput = document.getElementById('replyToId');

        if (replyPreview) {
            replyPreview.style.display = 'none';
        }

        if (replyToInput) {
            replyToInput.value = '';
        }
    }
}

// Global functions for template usage
function handleMessageInput(input) {
    window.enhancedChat?.handleMessageInput(input);
}

function handleKeyDown(event) {
    window.enhancedChat?.handleKeyDown(event);
}

function toggleEmojiPicker() {
    window.enhancedChat?.toggleEmojiPicker();
}

function startServerCall(callType) {
    window.enhancedChat?.startServerCall(callType);
}

function startDirectCall(userId, callType) {
    window.enhancedChat?.startDirectCall(userId, callType);
}

function shareScreen() {
    window.enhancedChat?.shareScreen();
}

function shareScreenDM(userId) {
    window.enhancedChat?.shareScreenDM(userId);
}

function replyToMessage(messageId) {
    window.enhancedChat?.replyToMessage(messageId);
}

function cancelReply() {
    window.enhancedChat?.cancelReply();
}

function stopRecording() {
    window.enhancedChat?.stopRecording();
}

function cancelRecording() {
    window.enhancedChat?.cancelRecording();
}

function stopDmRecording() {
    window.enhancedChat?.stopRecording();
}

function cancelDmRecording() {
    window.enhancedChat?.cancelRecording();
}

// Initialize enhanced chat when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.enhancedChat = new EnhancedChat();
    console.log('Enhanced chat functionality loaded');
});