/**
 * Collapsible Sidebar Functionality
 * Handles desktop collapse and mobile slide-out sidebar
 */

class SidebarToggle {
    constructor() {
        this.sidebar = null;
        this.overlay = null;
        this.desktopToggle = null;
        this.mobileToggle = null;
        this.isCollapsed = false;
        this.isMobile = false;
        
        this.init();
    }
    
    init() {
        this.sidebar = document.querySelector('.sidebar');
        if (!this.sidebar) return;
        
        this.checkDevice();
        this.createToggleButtons();
        this.createOverlay();
        this.bindEvents();
        this.loadState();
        
        // Listen for window resize
        window.addEventListener('resize', () => {
            this.checkDevice();
            this.updateSidebar();
        });
    }
    
    checkDevice() {
        this.isMobile = window.innerWidth <= 768;
    }
    
    createToggleButtons() {
        // Desktop toggle button (arrow on sidebar edge)
        if (!this.desktopToggle) {
            this.desktopToggle = document.createElement('button');
            this.desktopToggle.className = 'sidebar-toggle';
            this.desktopToggle.innerHTML = '<i class="fas fa-chevron-left"></i>';
            this.desktopToggle.title = 'Collapse sidebar';
            this.sidebar.appendChild(this.desktopToggle);
        }
        
        // Mobile toggle button (hamburger menu)
        if (!this.mobileToggle) {
            this.mobileToggle = document.createElement('button');
            this.mobileToggle.className = 'mobile-sidebar-toggle';
            this.mobileToggle.innerHTML = '<i class="fas fa-bars"></i>';
            this.mobileToggle.title = 'Open sidebar';
            document.body.appendChild(this.mobileToggle);
        }
    }
    
    createOverlay() {
        if (!this.overlay) {
            this.overlay = document.createElement('div');
            this.overlay.className = 'sidebar-overlay';
            document.body.appendChild(this.overlay);
        }
    }
    
    bindEvents() {
        // Desktop toggle
        this.desktopToggle.addEventListener('click', () => {
            this.toggleDesktopSidebar();
        });
        
        // Mobile toggle
        this.mobileToggle.addEventListener('click', () => {
            this.toggleMobileSidebar();
        });
        
        // Overlay click to close mobile sidebar
        this.overlay.addEventListener('click', () => {
            this.closeMobileSidebar();
        });
        
        // ESC key to close mobile sidebar
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isMobile && this.sidebar.classList.contains('mobile-visible')) {
                this.closeMobileSidebar();
            }
        });
        
        // Swipe gestures for mobile
        this.setupSwipeGestures();
    }
    
    toggleDesktopSidebar() {
        if (this.isMobile) return;
        
        this.isCollapsed = !this.isCollapsed;
        this.updateDesktopSidebar();
        this.saveState();
    }
    
    toggleMobileSidebar() {
        if (!this.isMobile) return;
        
        const isVisible = this.sidebar.classList.contains('mobile-visible');
        if (isVisible) {
            this.closeMobileSidebar();
        } else {
            this.openMobileSidebar();
        }
    }
    
    openMobileSidebar() {
        this.sidebar.classList.add('mobile-visible');
        this.overlay.classList.add('active');
        this.mobileToggle.innerHTML = '<i class="fas fa-times"></i>';
        this.mobileToggle.title = 'Close sidebar';
        
        // Prevent body scroll
        document.body.style.overflow = 'hidden';
    }
    
    closeMobileSidebar() {
        this.sidebar.classList.remove('mobile-visible');
        this.overlay.classList.remove('active');
        this.mobileToggle.innerHTML = '<i class="fas fa-bars"></i>';
        this.mobileToggle.title = 'Open sidebar';
        
        // Restore body scroll
        document.body.style.overflow = '';
    }
    
    updateDesktopSidebar() {
        if (this.isCollapsed) {
            this.sidebar.classList.add('collapsed');
            this.desktopToggle.title = 'Expand sidebar';
        } else {
            this.sidebar.classList.remove('collapsed');
            this.desktopToggle.title = 'Collapse sidebar';
        }
        
        // Trigger custom event for other components
        window.dispatchEvent(new CustomEvent('sidebarToggle', {
            detail: { collapsed: this.isCollapsed }
        }));
    }
    
    updateSidebar() {
        if (this.isMobile) {
            // Mobile: Remove desktop collapsed state
            this.sidebar.classList.remove('collapsed');
            this.desktopToggle.style.display = 'none';
            this.mobileToggle.style.display = 'flex';
            
            // Close mobile sidebar if open
            if (this.sidebar.classList.contains('mobile-visible')) {
                this.closeMobileSidebar();
            }
        } else {
            // Desktop: Remove mobile states
            this.sidebar.classList.remove('mobile-visible');
            this.overlay.classList.remove('active');
            this.desktopToggle.style.display = 'flex';
            this.mobileToggle.style.display = 'none';
            
            // Restore body scroll
            document.body.style.overflow = '';
            
            // Apply saved collapsed state
            if (this.isCollapsed) {
                this.sidebar.classList.add('collapsed');
            }
        }
    }
    
    setupSwipeGestures() {
        let startX = 0;
        let startY = 0;
        let isTouch = false;
        let isDragging = false;
        
        document.addEventListener('touchstart', (e) => {
            startX = e.touches[0].clientX;
            startY = e.touches[0].clientY;
            isTouch = true;
            isDragging = false;
        }, { passive: true });
        
        document.addEventListener('touchmove', (e) => {
            if (!isTouch || !this.isMobile) return;
            
            const currentX = e.touches[0].clientX;
            const currentY = e.touches[0].clientY;
            const deltaX = currentX - startX;
            const deltaY = currentY - startY;
            
            // Only handle horizontal swipes
            if (Math.abs(deltaX) > Math.abs(deltaY) && Math.abs(deltaX) > 10) {
                isDragging = true;
                e.preventDefault();
                
                // Swipe right from left edge to open
                if (startX < 30 && deltaX > 80 && !this.sidebar.classList.contains('mobile-visible')) {
                    this.openMobileSidebar();
                }
                // Swipe left to close when sidebar is open
                else if (deltaX < -80 && this.sidebar.classList.contains('mobile-visible')) {
                    this.closeMobileSidebar();
                }
            }
        }, { passive: false });
        
        document.addEventListener('touchend', (e) => {
            if (isDragging) {
                e.preventDefault();
            }
            isTouch = false;
            isDragging = false;
        }, { passive: false });
    }
    
    saveState() {
        if (!this.isMobile) {
            localStorage.setItem('sidebarCollapsed', this.isCollapsed.toString());
        }
    }
    
    loadState() {
        if (!this.isMobile) {
            const saved = localStorage.getItem('sidebarCollapsed');
            if (saved !== null) {
                this.isCollapsed = saved === 'true';
                this.updateDesktopSidebar();
            }
        }
    }
    
    // Public methods for external use
    collapse() {
        if (!this.isMobile && !this.isCollapsed) {
            this.toggleDesktopSidebar();
        }
    }
    
    expand() {
        if (!this.isMobile && this.isCollapsed) {
            this.toggleDesktopSidebar();
        }
    }
    
    isCollapsedState() {
        return this.isCollapsed;
    }
    
    isMobileState() {
        return this.isMobile;
    }
}

// Initialize sidebar toggle when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.sidebarToggle = new SidebarToggle();
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SidebarToggle;
}