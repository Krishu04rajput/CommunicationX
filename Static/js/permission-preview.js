// Intelligent Permission Preview Visualization System
console.log('Loading permission preview system...');

class PermissionPreviewSystem {
    constructor() {
        this.overlay = null;
        this.container = null;
        this.currentContext = null;
        this.permissions = this.initializePermissions();
        this.roleHierarchy = this.initializeRoleHierarchy();
        this.init();
    }

    init() {
        this.createPreviewOverlay();
        this.attachEventListeners();
        console.log('Permission preview system initialized');
    }

    initializePermissions() {
        return {
            // Server permissions
            'MANAGE_SERVER': { name: 'Manage Server', description: 'Full server management access', level: 'admin' },
            'MANAGE_CHANNELS': { name: 'Manage Channels', description: 'Create, edit, and delete channels', level: 'moderator' },
            'MANAGE_ROLES': { name: 'Manage Roles', description: 'Create and assign roles', level: 'admin' },
            'MANAGE_MEMBERS': { name: 'Manage Members', description: 'Kick, ban, and manage members', level: 'moderator' },
            'VIEW_AUDIT_LOG': { name: 'View Audit Log', description: 'See server activity logs', level: 'moderator' },
            'MANAGE_INVITES': { name: 'Manage Invites', description: 'Create and manage server invites', level: 'moderator' },
            
            // Message permissions
            'SEND_MESSAGES': { name: 'Send Messages', description: 'Send messages in channels', level: 'member' },
            'MANAGE_MESSAGES': { name: 'Manage Messages', description: 'Delete and edit others\' messages', level: 'moderator' },
            'EMBED_LINKS': { name: 'Embed Links', description: 'Post links with previews', level: 'member' },
            'ATTACH_FILES': { name: 'Attach Files', description: 'Upload files to channels', level: 'member' },
            'MENTION_EVERYONE': { name: 'Mention Everyone', description: 'Use @everyone and @here', level: 'moderator' },
            'USE_EXTERNAL_EMOJIS': { name: 'External Emojis', description: 'Use emojis from other servers', level: 'member' },
            
            // Voice permissions
            'CONNECT': { name: 'Connect to Voice', description: 'Join voice channels', level: 'member' },
            'SPEAK': { name: 'Speak', description: 'Talk in voice channels', level: 'member' },
            'MUTE_MEMBERS': { name: 'Mute Members', description: 'Mute others in voice channels', level: 'moderator' },
            'DEAFEN_MEMBERS': { name: 'Deafen Members', description: 'Deafen others in voice channels', level: 'moderator' },
            'MOVE_MEMBERS': { name: 'Move Members', description: 'Move members between voice channels', level: 'moderator' },
            'USE_VAD': { name: 'Voice Activity', description: 'Use voice activity detection', level: 'member' },
            
            // Advanced permissions
            'ADMINISTRATOR': { name: 'Administrator', description: 'Full administrative access', level: 'owner' },
            'MANAGE_WEBHOOKS': { name: 'Manage Webhooks', description: 'Create and manage webhooks', level: 'admin' },
            'MANAGE_EMOJIS': { name: 'Manage Emojis', description: 'Add and remove server emojis', level: 'admin' },
            'CREATE_INSTANT_INVITE': { name: 'Create Invites', description: 'Generate server invites', level: 'member' }
        };
    }

    initializeRoleHierarchy() {
        return [
            {
                name: 'Owner',
                level: 'owner',
                icon: 'fas fa-crown',
                description: 'Full server ownership with all permissions',
                permissions: Object.keys(this.permissions),
                color: '#8b5cf6'
            },
            {
                name: 'Administrator',
                level: 'admin',
                icon: 'fas fa-shield-alt',
                description: 'Administrative access to server management',
                permissions: Object.keys(this.permissions).filter(p => 
                    ['admin', 'moderator', 'member'].includes(this.permissions[p].level)
                ),
                color: '#ef4444'
            },
            {
                name: 'Moderator',
                level: 'moderator',
                icon: 'fas fa-gavel',
                description: 'Moderation capabilities and member management',
                permissions: Object.keys(this.permissions).filter(p => 
                    ['moderator', 'member'].includes(this.permissions[p].level)
                ),
                color: '#f59e0b'
            },
            {
                name: 'Member',
                level: 'member',
                icon: 'fas fa-user',
                description: 'Standard member with basic permissions',
                permissions: Object.keys(this.permissions).filter(p => 
                    this.permissions[p].level === 'member'
                ),
                color: '#10b981'
            },
            {
                name: 'Guest',
                level: 'guest',
                icon: 'fas fa-user-clock',
                description: 'Limited access for temporary members',
                permissions: ['SEND_MESSAGES', 'CONNECT', 'SPEAK'],
                color: '#6b7280'
            }
        ];
    }

    createPreviewOverlay() {
        this.overlay = document.createElement('div');
        this.overlay.className = 'permission-preview-overlay';
        this.overlay.innerHTML = `
            <div class="permission-preview-container">
                <div class="permission-preview-header">
                    <div class="permission-preview-title">
                        <div class="permission-preview-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        Permission Preview
                    </div>
                    <button class="permission-close-btn" onclick="permissionPreview.hide()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="permission-preview-content" id="permissionContent">
                    <!-- Content will be dynamically generated -->
                </div>
            </div>
        `;
        document.body.appendChild(this.overlay);
        this.container = this.overlay.querySelector('.permission-preview-container');
    }

    attachEventListeners() {
        // Close on overlay click
        this.overlay.addEventListener('click', (e) => {
            if (e.target === this.overlay) {
                this.hide();
            }
        });

        // Close on escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.overlay.classList.contains('active')) {
                this.hide();
            }
        });

        // Attach to server join buttons
        document.querySelectorAll('[data-permission-preview]').forEach(element => {
            element.addEventListener('click', (e) => {
                e.preventDefault();
                const context = JSON.parse(element.dataset.permissionPreview);
                this.show(context);
            });
        });

        // Attach to role management buttons
        document.querySelectorAll('.role-preview-btn').forEach(element => {
            element.addEventListener('click', (e) => {
                e.preventDefault();
                const roleLevel = element.dataset.role;
                const serverId = element.dataset.serverId;
                this.showRolePreview(roleLevel, serverId);
            });
        });
    }

    show(context) {
        this.currentContext = context;
        this.generateContent(context);
        this.overlay.classList.add('active');
        document.body.style.overflow = 'hidden';
    }

    hide() {
        this.overlay.classList.remove('active');
        document.body.style.overflow = '';
        this.currentContext = null;
    }

    generateContent(context) {
        const content = document.getElementById('permissionContent');
        let html = '';

        switch (context.type) {
            case 'server_join':
                html = this.generateServerJoinPreview(context);
                break;
            case 'role_assignment':
                html = this.generateRoleAssignmentPreview(context);
                break;
            case 'permission_change':
                html = this.generatePermissionChangePreview(context);
                break;
            default:
                html = this.generateGeneralPreview(context);
        }

        content.innerHTML = html;
        this.attachActionListeners();
    }

    generateServerJoinPreview(context) {
        const userRole = context.userRole || 'member';
        const serverName = context.serverName || 'Server';
        
        return `
            <div class="permission-section">
                <div class="permission-section-title">
                    <i class="fas fa-server"></i>
                    Joining ${serverName}
                </div>
                <p style="color: rgb(var(--text-secondary)); margin-bottom: 1.5rem;">
                    You'll be joining as a <strong>${userRole}</strong> with the following permissions:
                </p>
                ${this.generatePermissionMatrix([userRole])}
            </div>

            <div class="permission-section">
                <div class="permission-section-title">
                    <i class="fas fa-sitemap"></i>
                    Role Hierarchy
                </div>
                ${this.generateRoleHierarchy(userRole)}
            </div>

            <div class="permission-section">
                <div class="permission-section-title">
                    <i class="fas fa-chart-line"></i>
                    Impact Analysis
                </div>
                ${this.generateImpactAnalysis(context)}
            </div>

            <div class="permission-actions">
                <button class="permission-btn permission-btn-secondary" onclick="permissionPreview.hide()">
                    <i class="fas fa-times"></i> Cancel
                </button>
                <button class="permission-btn permission-btn-primary" onclick="permissionPreview.confirmAction()">
                    <i class="fas fa-check"></i> Join Server
                </button>
            </div>
        `;
    }

    generateRoleAssignmentPreview(context) {
        const currentRole = context.currentRole || 'member';
        const newRole = context.newRole || 'member';
        
        return `
            <div class="permission-section">
                <div class="permission-section-title">
                    <i class="fas fa-user-tag"></i>
                    Role Change: ${currentRole} → ${newRole}
                </div>
                ${this.generatePermissionMatrix([currentRole, newRole])}
            </div>

            <div class="permission-section">
                <div class="permission-section-title">
                    <i class="fas fa-exchange-alt"></i>
                    Permission Changes
                </div>
                ${this.generatePermissionDiff(currentRole, newRole)}
            </div>

            <div class="permission-section">
                <div class="permission-section-title">
                    <i class="fas fa-exclamation-triangle"></i>
                    Impact Analysis
                </div>
                ${this.generateRoleChangeImpact(currentRole, newRole)}
            </div>

            <div class="permission-actions">
                <button class="permission-btn permission-btn-secondary" onclick="permissionPreview.hide()">
                    <i class="fas fa-times"></i> Cancel
                </button>
                <button class="permission-btn permission-btn-primary" onclick="permissionPreview.confirmAction()">
                    <i class="fas fa-check"></i> Apply Role
                </button>
            </div>
        `;
    }

    generatePermissionMatrix(roles) {
        const allPermissions = Object.keys(this.permissions);
        const roleData = roles.map(role => this.roleHierarchy.find(r => r.level === role) || this.roleHierarchy[3]);
        
        let html = '<div class="permission-matrix">';
        
        // Headers
        html += '<div class="permission-matrix-header">Permission</div>';
        roleData.forEach(role => {
            html += `<div class="permission-matrix-header">${role.name}</div>`;
        });
        
        // Permission rows
        allPermissions.forEach(permKey => {
            const perm = this.permissions[permKey];
            html += `<div class="permission-matrix-cell permission-matrix-row">${perm.name}</div>`;
            
            roleData.forEach(role => {
                const hasPermission = role.permissions.includes(permKey);
                const statusClass = hasPermission ? 'permission-granted' : 'permission-denied';
                const statusIcon = hasPermission ? '✓' : '✕';
                
                html += `
                    <div class="permission-matrix-cell">
                        <span class="permission-status ${statusClass}">${statusIcon}</span>
                    </div>
                `;
            });
        });
        
        html += '</div>';
        return html;
    }

    generateRoleHierarchy(highlightRole = null) {
        let html = '<div class="permission-hierarchy">';
        
        this.roleHierarchy.forEach(role => {
            const isHighlighted = role.level === highlightRole;
            const highlightClass = isHighlighted ? 'role-highlighted' : '';
            
            html += `
                <div class="role-level ${role.level} ${highlightClass}">
                    <div class="role-icon ${role.level}">
                        <i class="${role.icon}"></i>
                    </div>
                    <div class="role-info">
                        <div class="role-name">${role.name}</div>
                        <div class="role-description">${role.description}</div>
                        <div class="role-permissions">
                            ${role.permissions.slice(0, 4).map(permKey => 
                                `<span class="permission-tag granted">${this.permissions[permKey]?.name || permKey}</span>`
                            ).join('')}
                            ${role.permissions.length > 4 ? `<span class="permission-tag">+${role.permissions.length - 4} more</span>` : ''}
                        </div>
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        return html;
    }

    generateImpactAnalysis(context) {
        const impacts = this.calculateImpacts(context);
        
        let html = '<div class="impact-analysis">';
        impacts.forEach(impact => {
            html += `
                <div class="impact-item">
                    <div class="impact-icon impact-${impact.type}">
                        <i class="${impact.icon}"></i>
                    </div>
                    <div class="impact-text">${impact.text}</div>
                </div>
            `;
        });
        html += '</div>';
        
        return html;
    }

    generatePermissionDiff(currentRole, newRole) {
        const currentRoleData = this.roleHierarchy.find(r => r.level === currentRole);
        const newRoleData = this.roleHierarchy.find(r => r.level === newRole);
        
        const currentPerms = new Set(currentRoleData?.permissions || []);
        const newPerms = new Set(newRoleData?.permissions || []);
        
        const gained = [...newPerms].filter(p => !currentPerms.has(p));
        const lost = [...currentPerms].filter(p => !newPerms.has(p));
        
        let html = '<div class="permission-diff">';
        
        if (gained.length > 0) {
            html += '<div class="permission-changes gained"><h4>Permissions Gained:</h4>';
            gained.forEach(permKey => {
                html += `<span class="permission-tag granted">${this.permissions[permKey]?.name || permKey}</span>`;
            });
            html += '</div>';
        }
        
        if (lost.length > 0) {
            html += '<div class="permission-changes lost"><h4>Permissions Lost:</h4>';
            lost.forEach(permKey => {
                html += `<span class="permission-tag denied">${this.permissions[permKey]?.name || permKey}</span>`;
            });
            html += '</div>';
        }
        
        if (gained.length === 0 && lost.length === 0) {
            html += '<p style="color: rgb(var(--text-secondary));">No permission changes</p>';
        }
        
        html += '</div>';
        return html;
    }

    generateRoleChangeImpact(currentRole, newRole) {
        const impacts = [];
        
        // Determine if it's a promotion or demotion
        const roleOrder = ['guest', 'member', 'moderator', 'admin', 'owner'];
        const currentIndex = roleOrder.indexOf(currentRole);
        const newIndex = roleOrder.indexOf(newRole);
        
        if (newIndex > currentIndex) {
            impacts.push({
                type: 'positive',
                icon: 'fas fa-arrow-up',
                text: `Promotion to ${newRole} grants additional server management capabilities`
            });
            
            if (newRole === 'moderator' || newRole === 'admin') {
                impacts.push({
                    type: 'warning',
                    icon: 'fas fa-exclamation-triangle',
                    text: 'User will be able to moderate other members and manage server content'
                });
            }
        } else if (newIndex < currentIndex) {
            impacts.push({
                type: 'negative',
                icon: 'fas fa-arrow-down',
                text: `Demotion to ${newRole} removes some server permissions`
            });
        }
        
        return this.generateImpactAnalysis({ impacts });
    }

    calculateImpacts(context) {
        const impacts = [];
        
        switch (context.type) {
            case 'server_join':
                impacts.push({
                    type: 'positive',
                    icon: 'fas fa-users',
                    text: 'You can participate in server discussions and voice channels'
                });
                
                if (context.userRole !== 'guest') {
                    impacts.push({
                        type: 'positive',
                        icon: 'fas fa-file-upload',
                        text: 'You can share files and images in channels'
                    });
                }
                
                impacts.push({
                    type: 'warning',
                    icon: 'fas fa-eye',
                    text: 'Server moderators can see your activity and messages'
                });
                break;
                
            default:
                if (context.impacts) {
                    impacts.push(...context.impacts);
                }
        }
        
        return impacts;
    }

    attachActionListeners() {
        // Attach any dynamic event listeners here
        document.querySelectorAll('.role-level').forEach(element => {
            element.addEventListener('click', () => {
                element.classList.toggle('expanded');
            });
        });
    }

    confirmAction() {
        if (this.currentContext && this.currentContext.onConfirm) {
            this.currentContext.onConfirm();
        }
        this.hide();
    }

    // Quick preview for hover effects
    showQuickPreview(element, permissions) {
        const preview = document.createElement('div');
        preview.className = 'permission-quick-preview show';
        preview.innerHTML = `
            <strong>Quick Permission Preview</strong>
            <div class="permission-mini-matrix">
                ${permissions.slice(0, 6).map(perm => 
                    `<div class="permission-mini-item">${this.permissions[perm]?.name || perm}</div>`
                ).join('')}
                ${permissions.length > 6 ? `<div class="permission-mini-item">+${permissions.length - 6} more</div>` : ''}
            </div>
        `;
        
        document.body.appendChild(preview);
        
        const rect = element.getBoundingClientRect();
        preview.style.left = `${rect.left}px`;
        preview.style.top = `${rect.bottom + 10}px`;
        
        const hidePreview = () => {
            preview.remove();
            element.removeEventListener('mouseleave', hidePreview);
        };
        
        element.addEventListener('mouseleave', hidePreview);
        setTimeout(hidePreview, 3000); // Auto-hide after 3 seconds
    }

    // Public methods for external use
    showServerJoinPreview(serverName, userRole, onConfirm) {
        this.show({
            type: 'server_join',
            serverName,
            userRole,
            onConfirm
        });
    }

    showRoleChangePreview(currentRole, newRole, onConfirm) {
        this.show({
            type: 'role_assignment',
            currentRole,
            newRole,
            onConfirm
        });
    }
}

// Initialize the permission preview system
let permissionPreview;
document.addEventListener('DOMContentLoaded', () => {
    permissionPreview = new PermissionPreviewSystem();
    window.permissionPreview = permissionPreview; // Make it globally accessible
});

// Helper functions for easy integration
function previewServerJoin(serverName, role = 'member', callback = null) {
    if (window.permissionPreview) {
        window.permissionPreview.showServerJoinPreview(serverName, role, callback);
    }
}

function previewRoleChange(currentRole, newRole, callback = null) {
    if (window.permissionPreview) {
        window.permissionPreview.showRoleChangePreview(currentRole, newRole, callback);
    }
}

console.log('Permission preview system loaded');