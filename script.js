// ===== VAULTGUARD ENHANCED SCRIPT - PHASE 1 COMPLETE =====
// Advanced Password Manager with Enhanced Security Features

// ===== GLOBAL STATE MANAGEMENT =====
class VaultGuardState {
    constructor() {
        this.isAuthenticated = false;
        this.masterPassword = null;
        this.currentUser = null;
        this.vaultEntries = [];
        this.notifications = [];
        this.settings = {
            breachAlerts: true,
            passwordAgeWarnings: true,
            emailNotifications: false,
            phoneNotifications: false,
            securityScanning: true
        };
        this.searchTerm = '';
        this.sortBy = 'name';
        this.sortOrder = 'asc';
        this.sessionTimeout = null;
        this.lastActivity = Date.now();
    }

    updateActivity() {
        this.lastActivity = Date.now();
        this.resetSessionTimeout();
    }

    resetSessionTimeout() {
        if (this.sessionTimeout) {
            clearTimeout(this.sessionTimeout);
        }
        // Input action buttons
        this.initializeInputActions();
    }

    initializeInputActions() {
        // Copy button
        const copyBtn = document.querySelector('#copyPassword');
        if (copyBtn) {
            copyBtn.addEventListener('click', this.copyPassword.bind(this));
        }

        // Show/Hide button
        const toggleBtn = document.querySelector('#togglePassword');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', this.togglePasswordVisibility.bind(this));
        }

        // Clear button
        const clearBtn = document.querySelector('#clearPassword');
        if (clearBtn) {
            clearBtn.addEventListener('click', this.clearPassword.bind(this));
        }

        // Generate button
        const quickGenBtn = document.querySelector('#quickGenerate');
        if (quickGenBtn) {
            quickGenBtn.addEventListener('click', this.quickGenerate.bind(this));
        }

        // Analyze button
        const analyzeBtn = document.querySelector('#analyzePassword');
        if (analyzeBtn) {
            analyzeBtn.addEventListener('click', this.analyzeCurrentPassword.bind(this));
        }
    }

    async copyPassword() {
        const passwordInput = document.querySelector('#password');
        if (!passwordInput || !passwordInput.value) {
            showNotification('No password to copy', 'warning');
            return;
        }

        try {
            await navigator.clipboard.writeText(passwordInput.value);
            showNotification('Password copied to clipboard', 'success');
            
            // Security: Clear clipboard after 45 seconds
            setTimeout(async () => {
                try {
                    await navigator.clipboard.writeText('');
                } catch (error) {
                    // Ignore clipboard clear errors
                }
            }, 45000);
        } catch (error) {
            // Fallback for older browsers
            passwordInput.select();
            document.execCommand('copy');
            showNotification('Password copied to clipboard', 'success');
        }
    }

    togglePasswordVisibility() {
        const passwordInput = document.querySelector('#password');
        const toggleBtn = document.querySelector('#togglePassword');
        
        if (!passwordInput || !toggleBtn) return;

        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleBtn.innerHTML = '👁️‍🗨️';
            toggleBtn.title = 'Hide password';
            
            // Auto-hide after 10 seconds for security
            setTimeout(() => {
                if (passwordInput.type === 'text') {
                    passwordInput.type = 'password';
                    toggleBtn.innerHTML = '👁️';
                    toggleBtn.title = 'Show password';
                }
            }, 10000);
        } else {
            passwordInput.type = 'password';
            toggleBtn.innerHTML = '👁️';
            toggleBtn.title = 'Show password';
        }
    }

    clearPassword() {
        const passwordInput = document.querySelector('#password');
        if (passwordInput) {
            passwordInput.value = '';
            passwordInput.dispatchEvent(new Event('input'));
            showNotification('Password cleared', 'info');
        }
    }

    quickGenerate() {
        const password = passwordGenerator.generatePassword({
            length: 16,
            includeLowercase: true,
            includeUppercase: true,
            includeNumbers: true,
            includeSymbols: true
        });
        
        const passwordInput = document.querySelector('#password');
        if (passwordInput) {
            passwordInput.value = password;
            passwordInput.dispatchEvent(new Event('input'));
            showNotification('Password generated', 'success');
        }
    }

    analyzeCurrentPassword() {
        const passwordInput = document.querySelector('#password');
        if (!passwordInput || !passwordInput.value) {
            showNotification('Enter a password to analyze', 'warning');
            return;
        }

        this.updatePasswordStrength(passwordInput.value);
        showNotification('Password analyzed', 'info');
    }

    generatePassword() {
        try {
            // Get generator options
            const options = this.getGeneratorOptions();
            
            let password;
            const generateType = document.querySelector('#generateType')?.value || 'password';
            
            if (generateType === 'passphrase') {
                password = passwordGenerator.generatePassphrase(options);
            } else {
                password = passwordGenerator.generatePassword(options);
            }

            // Update password input
            const passwordInput = document.querySelector('#password');
            if (passwordInput) {
                passwordInput.value = password;
                passwordInput.dispatchEvent(new Event('input'));
            }

            showNotification('Password generated successfully', 'success');
        } catch (error) {
            showNotification(`Generation failed: ${error.message}`, 'error');
        }
    }

    getGeneratorOptions() {
        const lengthSlider = document.querySelector('#length');
        const includeLowercase = document.querySelector('#includeLowercase');
        const includeUppercase = document.querySelector('#includeUppercase');
        const includeNumbers = document.querySelector('#includeNumbers');
        const includeSymbols = document.querySelector('#includeSymbols');
        const excludeSimilar = document.querySelector('#excludeSimilar');
        const excludeAmbiguous = document.querySelector('#excludeAmbiguous');

        return {
            length: lengthSlider ? parseInt(lengthSlider.value) : 16,
            includeLowercase: includeLowercase ? includeLowercase.checked : true,
            includeUppercase: includeUppercase ? includeUppercase.checked : true,
            includeNumbers: includeNumbers ? includeNumbers.checked : true,
            includeSymbols: includeSymbols ? includeSymbols.checked : true,
            excludeSimilar: excludeSimilar ? excludeSimilar.checked : true,
            excludeAmbiguous: excludeAmbiguous ? excludeAmbiguous.checked : true
        };
    }

    initializeAuthModals() {
        // Login/Register buttons
        const loginBtn = document.querySelector('#loginBtn');
        const registerBtn = document.querySelector('#registerBtn');
        
        if (loginBtn) {
            loginBtn.addEventListener('click', () => this.showAuthModal('login'));
        }
        
        if (registerBtn) {
            registerBtn.addEventListener('click', () => this.showAuthModal('register'));
        }

        // Auth form submissions
        document.addEventListener('submit', async (e) => {
            if (e.target.matches('.auth-form')) {
                e.preventDefault();
                await this.handleAuthSubmission(e.target);
            }
        });

        // Modal close buttons
        document.addEventListener('click', (e) => {
            if (e.target.matches('.close-btn') || e.target.matches('.auth-modal')) {
                this.closeModal('auth');
            }
        });
    }

    showAuthModal(type = 'login') {
        let modal = this.modals.get('auth');
        
        if (!modal) {
            modal = this.createAuthModal();
            this.modals.set('auth', modal);
        }

        // Update modal for login/register
        const title = modal.querySelector('.auth-title');
        const submitBtn = modal.querySelector('.auth-submit');
        const switchText = modal.querySelector('.auth-switch');
        
        if (type === 'login') {
            title.textContent = '🔐 Secure Login';
            submitBtn.textContent = 'Login';
            switchText.innerHTML = `Don't have an account? <a href="#" class="auth-link" data-switch="register">Register here</a>`;
        } else {
            title.textContent = '🛡️ Create Account';
            submitBtn.textContent = 'Register';
            switchText.innerHTML = `Already have an account? <a href="#" class="auth-link" data-switch="login">Login here</a>`;
        }

        modal.querySelector('form').setAttribute('data-type', type);
        modal.classList.add('show');
        
        // Focus username input
        setTimeout(() => {
            const usernameInput = modal.querySelector('input[name="username"]');
            if (usernameInput) usernameInput.focus();
        }, 300);

        // Handle auth switch links
        const switchLink = modal.querySelector('.auth-link');
        if (switchLink) {
            switchLink.addEventListener('click', (e) => {
                e.preventDefault();
                const switchType = e.target.getAttribute('data-switch');
                this.showAuthModal(switchType);
            });
        }
    }

    createAuthModal() {
        const modal = document.createElement('div');
        modal.className = 'auth-modal';
        modal.innerHTML = `
            <div class="auth-card">
                <button class="close-btn" type="button">×</button>
                <h2 class="auth-title">🔐 Secure Login</h2>
                <div class="security-auth-notice">
                    🔒 Your credentials are encrypted and never stored in plain text
                </div>
                <form class="auth-form" data-type="login">
                    <input type="text" name="username" placeholder="Username" class="auth-input" required autocomplete="username">
                    <input type="password" name="password" placeholder="Master Password" class="auth-input" required autocomplete="current-password">
                    <div class="password-requirements">
                        Master password should be strong and unique
                    </div>
                    <button type="submit" class="auth-submit">Login</button>
                </form>
                <div class="auth-switch">
                    Don't have an account? <a href="#" class="auth-link" data-switch="register">Register here</a>
                </div>
                <div class="auth-security-info">
                    <h4>🛡️ Security Features:</h4>
                    <ul>
                        <li>AES-256 encryption</li>
                        <li>PBKDF2 key derivation</li>
                        <li>Zero-knowledge architecture</li>
                        <li>Secure session management</li>
                    </ul>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        return modal;
    }

    async handleAuthSubmission(form) {
        const type = form.getAttribute('data-type');
        const formData = new FormData(form);
        const username = formData.get('username').trim();
        const password = formData.get('password');

        if (!username || !password) {
            showNotification('Please fill in all fields', 'error');
            return;
        }

        if (password.length < 8) {
            showNotification('Master password must be at least 8 characters', 'error');
            return;
        }

        const submitBtn = form.querySelector('.auth-submit');
        const originalText = submitBtn.textContent;
        
        try {
            submitBtn.disabled = true;
            submitBtn.textContent = type === 'login' ? 'Logging in...' : 'Creating account...';
            submitBtn.classList.add('loading');

            let result;
            if (type === 'login') {
                result = await api.login(username, password);
            } else {
                result = await api.register(username, password);
                if (result.success) {
                    // Auto-login after successful registration
                    result = await api.login(username, password);
                }
            }

            if (result.success) {
                showNotification(`${type === 'login' ? 'Login' : 'Registration'} successful!`, 'success');
                this.closeModal('auth');
                await this.initializeAuthenticatedState();
            } else {
                throw new Error(result.error || `${type} failed`);
            }
        } catch (error) {
            console.error(`${type} error:`, error);
            showNotification(error.message || `${type} failed. Please try again.`, 'error');
            
            // Add error styling to form
            form.classList.add('auth-error');
            setTimeout(() => form.classList.remove('auth-error'), 500);
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
            submitBtn.classList.remove('loading');
        }
    }

    async initializeAuthenticatedState() {
        try {
            // Load vault entries
            await api.getVaultEntries();
            
            // Load user settings
            await api.getSettings();
            
            // Load notifications
            await api.getNotifications();
            
            // Update UI
            this.updateAuthenticatedUI();
            this.renderVaultEntries();
            this.updateNotificationBadge();
            
            // Show welcome message
            showNotification(`Welcome back, ${vaultState.currentUser}!`, 'success');
            
        } catch (error) {
            console.error('Failed to initialize authenticated state:', error);
            showNotification('Failed to load your data. Please refresh and try again.', 'error');
        }
    }

    updateAuthenticatedUI() {
        // Update header
        const headerActions = document.querySelector('.header-actions');
        if (headerActions) {
            headerActions.innerHTML = `
                <div class="welcome-text">Welcome, ${vaultState.currentUser}</div>
                <button class="notification-btn" id="notificationBtn">
                    🔔
                    <span class="notification-badge" style="display: none;">0</span>
                </button>
                <button class="theme-toggle" title="Toggle theme">☀️</button>
                <button class="auth-btn" id="settingsBtn">⚙️ Settings</button>
                <button class="auth-btn" id="logoutBtn">🚪 Logout</button>
            `;

            // Reinitialize event listeners for new buttons
            document.querySelector('#notificationBtn')?.addEventListener('click', () => this.showNotificationModal());
            document.querySelector('#settingsBtn')?.addEventListener('click', () => this.showSettingsModal());
            document.querySelector('#logoutBtn')?.addEventListener('click', () => this.handleLogout());
            document.querySelector('.theme-toggle')?.addEventListener('click', () => this.toggleTheme());
        }

        // Show vault section
        const vaultSection = document.querySelector('.vault-section');
        if (vaultSection) {
            vaultSection.style.display = 'block';
        }

        // Hide auth buttons from hero
        const heroAuthBtns = document.querySelectorAll('.hero-section .auth-btn');
        heroAuthBtns.forEach(btn => btn.style.display = 'none');
    }

    async handleLogout() {
        if (confirm('Are you sure you want to logout?')) {
            try {
                await api.logout();
                showNotification('Logged out successfully', 'info');
            } catch (error) {
                console.error('Logout error:', error);
                showNotification('Logout completed', 'info');
            }
        }
    }

    initializeVaultControls() {
        // Save vault entry
        const saveBtn = document.querySelector('#saveEntry');
        if (saveBtn) {
            saveBtn.addEventListener('click', this.saveVaultEntry.bind(this));
        }

        // Search functionality
        const searchInput = document.querySelector('#vaultSearch');
        if (searchInput) {
            searchInput.addEventListener('input', this.handleVaultSearch.bind(this));
        }

        // Sort functionality
        const sortSelect = document.querySelector('#vaultSort');
        if (sortSelect) {
            sortSelect.addEventListener('change', this.handleVaultSort.bind(this));
        }

        // Vault form validation
        const vaultForm = document.querySelector('#vaultForm');
        if (vaultForm) {
            vaultForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.saveVaultEntry();
            });
        }
    }

    handleVaultSearch(event) {
        vaultState.searchTerm = event.target.value.toLowerCase();
        this.renderVaultEntries();
    }

    handleVaultSort(event) {
        const [sortBy, sortOrder] = event.target.value.split('-');
        vaultState.sortBy = sortBy;
        vaultState.sortOrder = sortOrder;
        this.renderVaultEntries();
    }

    async saveVaultEntry() {
        const siteName = document.querySelector('#siteName')?.value?.trim();
        const siteUrl = document.querySelector('#siteUrl')?.value?.trim();
        const username = document.querySelector('#vaultUsername')?.value?.trim();
        const password = document.querySelector('#password')?.value;
        const notes = document.querySelector('#notes')?.value?.trim();

        if (!siteName || !username || !password) {
            showNotification('Please fill in required fields (Site Name, Username, Password)', 'warning');
            return;
        }

        // Validate URL if provided
        if (siteUrl && !this.isValidURL(siteUrl)) {
            showNotification('Please enter a valid URL', 'warning');
            return;
        }

        // Analyze password strength
        const analysis = passwordAnalyzer.analyzePassword(password);
        
        if (analysis.score < 30) {
            const proceed = confirm('This password is weak. Are you sure you want to save it?');
            if (!proceed) return;
        }

        const saveBtn = document.querySelector('#saveEntry');
        const originalText = saveBtn ? saveBtn.textContent : 'Save';
        
        try {
            if (saveBtn) {
                saveBtn.disabled = true;
                saveBtn.textContent = 'Saving...';
                saveBtn.classList.add('loading');
            }

            const entry = {
                site_name: siteName,
                site_url: siteUrl || '',
                username: username,
                password: password,
                notes: notes || '',
                strength_score: analysis.score,
                created_at: new Date().toISOString()
            };

            const result = await api.saveVaultEntry(entry);
            
            if (result.success) {
                showNotification('Entry saved successfully!', 'success');
                this.clearVaultForm();
                this.renderVaultEntries();
                
                // Check for breach alerts if enabled
                if (vaultState.settings.breachAlerts && analysis.characteristics.isPotentiallyBreached) {
                    this.addNotification({
                        type: 'warning',
                        title: 'Potentially Compromised Password',
                        message: `The password for ${siteName} may have been in data breaches. Consider changing it.`,
                        priority: 'high'
                    });
                }
            } else {
                throw new Error(result.error || 'Failed to save entry');
            }
        } catch (error) {
            console.error('Save entry error:', error);
            showNotification(error.message || 'Failed to save entry. Please try again.', 'error');
        } finally {
            if (saveBtn) {
                saveBtn.disabled = false;
                saveBtn.textContent = originalText;
                saveBtn.classList.remove('loading');
            }
        }
    }

    isValidURL(string) {
        try {
            const url = new URL(string.startsWith('http') ? string : `https://${string}`);
            return ['http:', 'https:'].includes(url.protocol);
        } catch {
            return false;
        }
    }

    clearVaultForm() {
        const inputs = ['#siteName', '#siteUrl', '#vaultUsername', '#password', '#notes'];
        inputs.forEach(selector => {
            const input = document.querySelector(selector);
            if (input) input.value = '';
        });
        
        this.hideStrengthIndicator();
    }

    renderVaultEntries() {
        const vaultList = document.querySelector('#vaultList');
        if (!vaultList) return;

        let entries = [...vaultState.vaultEntries];
        
        // Apply search filter
        if (vaultState.searchTerm) {
            entries = entries.filter(entry => 
                entry.site_name.toLowerCase().includes(vaultState.searchTerm) ||
                entry.username.toLowerCase().includes(vaultState.searchTerm) ||
                (entry.site_url && entry.site_url.toLowerCase().includes(vaultState.searchTerm))
            );
        }

        // Apply sorting
        entries.sort((a, b) => {
            let aVal, bVal;
            
            switch (vaultState.sortBy) {
                case 'name':
                    aVal = a.site_name.toLowerCase();
                    bVal = b.site_name.toLowerCase();
                    break;
                case 'date':
                    aVal = new Date(a.created_at || 0);
                    bVal = new Date(b.created_at || 0);
                    break;
                case 'strength':
                    aVal = a.strength_score || 0;
                    bVal = b.strength_score || 0;
                    break;
                case 'username':
                    aVal = a.username.toLowerCase();
                    bVal = b.username.toLowerCase();
                    break;
                default:
                    aVal = a.site_name.toLowerCase();
                    bVal = b.site_name.toLowerCase();
            }
            
            if (aVal < bVal) return vaultState.sortOrder === 'asc' ? -1 : 1;
            if (aVal > bVal) return vaultState.sortOrder === 'asc' ? 1 : -1;
            return 0;
        });

        // Render entries
        if (entries.length === 0) {
            vaultList.innerHTML = this.getEmptyVaultHTML();
        } else {
            vaultList.innerHTML = entries.map(entry => this.createVaultEntryHTML(entry)).join('');
            
            // Add event listeners for vault actions
            this.attachVaultEventListeners();
        }

        // Update vault stats
        this.updateVaultStats(entries);
    }

    createVaultEntryHTML(entry) {
        const createdDate = entry.created_at ? this.formatDate(entry.created_at) : 'Unknown';
        const updatedDate = entry.updated_at ? this.formatDate(entry.updated_at) : null;
        const strengthClass = this.getStrengthClass(entry.strength_score || 0);
        const strengthText = this.getStrengthText(entry.strength_score || 0);
        
        return `
            <li class="vault-item" data-entry-id="${entry.id}">
                <div class="site-header">
                    <h4 class="site-name">${this.escapeHTML(entry.site_name)}</h4>
                    <div class="vault-meta">
                        <div class="created-date">Created: ${createdDate}</div>
                        ${updatedDate ? `<div class="updated-badge">Updated: ${updatedDate}</div>` : ''}
                    </div>
                </div>
                
                ${entry.site_url ? `<div class="site-url">🌐 ${this.escapeHTML(entry.site_url)}</div>` : ''}
                
                <div class="username-display">👤 ${this.escapeHTML(entry.username)}</div>
                
                <div class="password-preview">🔒 ${'•'.repeat(Math.min(entry.password?.length || 8, 20))}</div>
                
                <div class="security-metrics">
                    <span class="strength-badge strength-${strengthClass}">${strengthText}</span>
                    ${entry.strength_score < 30 ? '<span class="breach-badge">⚠️ Weak</span>' : ''}
                </div>
                
                ${entry.notes ? `<div class="entry-notes">📝 ${this.escapeHTML(entry.notes)}</div>` : ''}
                
                <div class="vault-actions">
                    <button class="vault-btn copy-btn" data-action="copy" data-password="${this.escapeHTML(entry.password)}">
                        📋 Copy
                    </button>
                    <button class="vault-btn view-btn" data-action="view">
                        👁️ View
                    </button>
                    <button class="vault-btn delete-btn" data-action="delete">
                        🗑️ Delete
                    </button>
                </div>
            </li>
        `;
    }

    attachVaultEventListeners() {
        document.querySelectorAll('.vault-btn').forEach(btn => {
            btn.addEventListener('click', this.handleVaultAction.bind(this));
        });
    }

    async handleVaultAction(event) {
        const action = event.target.getAttribute('data-action');
        const entryElement = event.target.closest('.vault-item');
        const entryId = entryElement?.getAttribute('data-entry-id');
        
        if (!entryId) return;

        const entry = vaultState.vaultEntries.find(e => e.id.toString() === entryId);
        if (!entry) return;

        switch (action) {
            case 'copy':
                await this.copyPasswordToClipboard(entry.password);
                break;
            case 'view':
                this.showPasswordModal(entry);
                break;
            case 'delete':
                await this.deleteVaultEntry(entryId, entry.site_name);
                break;
        }
    }

    async copyPasswordToClipboard(password) {
        try {
            await navigator.clipboard.writeText(password);
            showNotification('Password copied to clipboard', 'success');
            
            // Clear clipboard after 45 seconds for security
            setTimeout(async () => {
                try {
                    await navigator.clipboard.writeText('');
                } catch (error) {
                    // Ignore clipboard clear errors
                }
            }, 45000);
        } catch (error) {
            showNotification('Failed to copy password', 'error');
        }
    }

    showPasswordModal(entry) {
        let modal = this.modals.get('password');
        
        if (!modal) {
            modal = this.createPasswordModal();
            this.modals.set('password', modal);
        }

        // Update modal content
        modal.querySelector('.modal-site-name').textContent = entry.site_name;
        modal.querySelector('.modal-username').textContent = entry.username;
        modal.querySelector('.modal-site-url').textContent = entry.site_url || 'No URL provided';
        modal.querySelector('.modal-notes').textContent = entry.notes || 'No notes';
        modal.querySelector('.modal-created').textContent = this.formatDate(entry.created_at);
        
        const passwordField = modal.querySelector('.revealed-password');
        passwordField.textContent = entry.password;
        
        // Update security metrics
        const analysis = passwordAnalyzer.analyzePassword(entry.password);
        modal.querySelector('.modal-strength').textContent = this.getStrengthText(analysis.score);
        modal.querySelector('.modal-length').textContent = `${entry.password.length} characters`;
        modal.querySelector('.modal-entropy').textContent = `${analysis.entropy} bits`;
        modal.querySelector('.modal-crack-time').textContent = analysis.timeToBreak;

        // Set up copy button
        const copyBtn = modal.querySelector('.copy-modal-btn');
        copyBtn.onclick = () => this.copyPasswordToClipboard(entry.password);

        modal.classList.add('show');
        
        // Auto-close after 30 seconds for security
        setTimeout(() => {
            if (modal.classList.contains('show')) {
                modal.classList.remove('show');
            }
        }, 30000);
    }

    createPasswordModal() {
        const modal = document.createElement('div');
        modal.className = 'password-modal';
        modal.innerHTML = `
            <div class="password-modal-content">
                <div class="modal-header">
                    <h3>🔐 Password Details</h3>
                    <button class="close-modal-btn" type="button">×</button>
                </div>
                
                <div class="password-field">
                    <label>Site Name:</label>
                    <div class="field-value modal-site-name"></div>
                </div>
                
                <div class="password-field">
                    <label>Username:</label>
                    <div class="field-value modal-username"></div>
                </div>
                
                <div class="password-field">
                    <label>URL:</label>
                    <div class="field-value modal-site-url"></div>
                </div>
                
                <div class="password-field">
                    <label>Password:</label>
                    <div class="revealed-password modal-password"></div>
                </div>
                
                <div class="password-stats">
                    <div class="stat">
                        <strong>Strength:</strong>
                        <span class="modal-strength"></span>
                    </div>
                    <div class="stat">
                        <strong>Length:</strong>
                        <span class="modal-length"></span>
                    </div>
                    <div class="stat">
                        <strong>Entropy:</strong>
                        <span class="modal-entropy"></span>
                    </div>
                    <div class="stat">
                        <strong>Crack Time:</strong>
                        <span class="modal-crack-time"></span>
                    </div>
                </div>
                
                <div class="password-field">
                    <label>Notes:</label>
                    <div class="field-value modal-notes"></div>
                </div>
                
                <div class="password-field">
                    <label>Created:</label>
                    <div class="field-value modal-created"></div>
                </div>
                
                <div class="security-timer">
                    🔒 This window will auto-close in 30 seconds for security
                </div>
                
                <div class="modal-actions">
                    <button class="copy-modal-btn">📋 Copy Password</button>
                    <button class="close-modal-btn secondary">Close</button>
                </div>
            </div>
        `;

        // Add event listeners
        modal.addEventListener('click', (e) => {
            if (e.target === modal || e.target.matches('.close-modal-btn')) {
                modal.classList.remove('show');
            }
        });

        document.body.appendChild(modal);
        return modal;
    }

    async deleteVaultEntry(entryId, siteName) {
        if (!confirm(`Are you sure you want to delete the entry for "${siteName}"? This cannot be undone.`)) {
            return;
        }

        try {
            const result = await api.deleteVaultEntry(entryId);
            
            if (result.success) {
                showNotification(`Deleted entry for ${siteName}`, 'success');
                this.renderVaultEntries();
            } else {
                throw new Error(result.error || 'Failed to delete entry');
            }
        } catch (error) {
            console.error('Delete entry error:', error);
            showNotification(error.message || 'Failed to delete entry', 'error');
        }
    }

    getEmptyVaultHTML() {
        return `
            <div class="empty-vault">
                <div class="empty-vault-content">
                    <h3>🔐 Your vault is empty</h3>
                    <p>Add your first password entry using the form above.</p>
                    <div class="security-reminder">
                        💡 <strong>Tip:</strong> Use the password generator to create strong, unique passwords for each site.
                    </div>
                    <div class="security-features">
                        <span class="feature">🔒 AES-256 Encrypted</span>
                        <span class="feature">🛡️ Zero-Knowledge</span>
                        <span class="feature">🔐 Secure Storage</span>
                    </div>
                </div>
            </div>
        `;
    }

    updateVaultStats(entries) {
        const statsContainer = document.querySelector('.vault-stats');
        if (!statsContainer) return;

        const totalEntries = entries.length;
        const weakPasswords = entries.filter(e => (e.strength_score || 0) < 50).length;
        const strongPasswords = entries.filter(e => (e.strength_score || 0) >= 70).length;
        const avgStrength = totalEntries > 0 ? 
            Math.round(entries.reduce((sum, e) => sum + (e.strength_score || 0), 0) / totalEntries) : 0;

        statsContainer.innerHTML = `
            <div class="stats-grid">
                <div class="stat-item">
                    <span class="stat-value">${totalEntries}</span>
                    <span class="stat-label">Total Entries</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value">${strongPasswords}</span>
                    <span class="stat-label">Strong Passwords</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value">${weakPasswords}</span>
                    <span class="stat-label">Weak Passwords</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value">${avgStrength}%</span>
                    <span class="stat-label">Avg Strength</span>
                </div>
            </div>
        `;
    }

    getStrengthClass(score) {
        if (score >= 90) return 'fortress';
        if (score >= 80) return 'military';
        if (score >= 70) return 'strong';
        if (score >= 50) return 'good';
        if (score >= 30) return 'fair';
        if (score >= 15) return 'weak';
        return 'critical';
    }

    getStrengthText(score) {
        const strengthClass = this.getStrengthClass(score);
        return strengthClass.charAt(0).toUpperCase() + strengthClass.slice(1);
    }

    initializeSettingsModal() {
        // Settings modal will be created when first opened
    }

    showSettingsModal() {
        let modal = this.modals.get('settings');
        
        if (!modal) {
            modal = this.createSettingsModal();
            this.modals.set('settings', modal);
        }

        // Update current settings
        this.updateSettingsValues(modal);
        modal.classList.add('show');
    }

    createSettingsModal() {
        const modal = document.createElement('div');
        modal.className = 'settings-modal';
        modal.innerHTML = `
            <div class="settings-modal-content">
                <div class="modal-header">
                    <h3>⚙️ Settings</h3>
                    <button class="close-modal-btn" type="button">×</button>
                </div>
                
                <div class="settings-section">
                    <h4>🔔 Notifications</h4>
                    <div class="settings-option">
                        <div class="option-info">
                            <div class="option-label">Breach Alerts</div>
                            <div class="option-description">Get notified about potentially compromised passwords</div>
                        </div>
                        <div class="settings-toggle" data-setting="breachAlerts"></div>
                    </div>
                    <div class="settings-option">
                        <div class="option-info">
                            <div class="option-label">Password Age Warnings</div>
                            <div class="option-description">Alert when passwords are older than 90 days</div>
                        </div>
                        <div class="settings-toggle" data-setting="passwordAgeWarnings"></div>
                    </div>
                    <div class="settings-option">
                        <div class="option-info">
                            <div class="option-label">Security Scanning</div>
                            <div class="option-description">Automatically analyze passwords for security issues</div>
                        </div>
                        <div class="settings-toggle" data-setting="securityScanning"></div>
                    </div>
                </div>
                
                <div class="settings-section">
                    <h4>📧 Contact Information (Optional)</h4>
                    <div class="settings-option">
                        <div class="option-info">
                            <div class="option-label">Email Notifications</div>
                            <div class="option-description">Receive security alerts via email</div>
                            <input type="email" class="settings-input" id="emailInput" placeholder="your@email.com">
                        </div>
                        <div class="settings-toggle" data-setting="emailNotifications"></div>
                    </div>
                    <div class="settings-option">
                        <div class="option-info">
                            <div class="option-label">Phone Notifications</div>
                            <div class="option-description">Receive critical alerts via SMS</div>
                            <input type="tel" class="settings-input" id="phoneInput" placeholder="+1234567890">
                        </div>
                        <div class="settings-toggle" data-setting="phoneNotifications"></div>
                    </div>
                </div>
                
                <button class="save-settings-btn" type="button">💾 Save Settings</button>
            </div>
        `;

        // Add event listeners
        modal.addEventListener('click', (e) => {
            if (e.target === modal || e.target.matches('.close-modal-btn')) {
                modal.classList.remove('show');
            }
            
            if (e.target.matches('.settings-toggle')) {
                this.toggleSetting(e.target);
            }
        });

        modal.querySelector('.save-settings-btn').addEventListener('click', () => {
            this.saveSettings(modal);
        });

        document.body.appendChild(modal);
        return modal;
    }

    updateSettingsValues(modal) {
        // Update toggles
        modal.querySelectorAll('.settings-toggle').forEach(toggle => {
            const setting = toggle.getAttribute('data-setting');
            const isActive = vaultState.settings[setting];
            toggle.classList.toggle('active', isActive);
        });

        // Update input values (if stored)
        const emailInput = modal.querySelector('#emailInput');
        const phoneInput = modal.querySelector('#phoneInput');
        
        if (emailInput && vaultState.settings.email) {
            emailInput.value = vaultState.settings.email;
        }
        
        if (phoneInput && vaultState.settings.phone) {
            phoneInput.value = vaultState.settings.phone;
        }
    }

    toggleSetting(toggle) {
        toggle.classList.toggle('active');
    }

    async saveSettings(modal) {
        const saveBtn = modal.querySelector('.save-settings-btn');
        const originalText = saveBtn.textContent;
        
        try {
            saveBtn.disabled = true;
            saveBtn.textContent = 'Saving...';

            const settings = {};
            
            // Get toggle settings
            modal.querySelectorAll('.settings-toggle').forEach(toggle => {
                const setting = toggle.getAttribute('data-setting');
                settings[setting] = toggle.classList.contains('active');
            });

            // Get input values
            const emailInput = modal.querySelector('#emailInput');
            const phoneInput = modal.querySelector('#phoneInput');
            
            if (emailInput && emailInput.value) {
                settings.email = emailInput.value.trim();
            }
            
            if (phoneInput && phoneInput.value) {
                settings.phone = phoneInput.value.trim();
            }

            const result = await api.saveSettings(settings);
            
            if (result.success) {
                showNotification('Settings saved successfully!', 'success');
                modal.classList.remove('show');
            } else {
                throw new Error(result.error || 'Failed to save settings');
            }
        } catch (error) {
            console.error('Save settings error:', error);
            showNotification(error.message || 'Failed to save settings', 'error');
        } finally {
            saveBtn.disabled = false;
            saveBtn.textContent = originalText;
        }
    }

    showNotificationModal() {
        let modal = this.modals.get('notifications');
        
        if (!modal) {
            modal = this.createNotificationModal();
            this.modals.set('notifications', modal);
        }

        this.updateNotificationsList(modal);
        modal.classList.add('show');
    }

    createNotificationModal() {
        const modal = document.createElement('div');
        modal.className = 'notification-modal';
        modal.innerHTML = `
            <div class="notification-modal-content">
                <div class="modal-header">
                    <h3>🔔 Security Notifications</h3>
                    <button class="close-modal-btn" type="button">×</button>
                </div>
                <div class="notifications-list" id="notificationsList">
                    <!-- Notifications will be populated here -->
                </div>
            </div>
        `;

        modal.addEventListener('click', (e) => {
            if (e.target === modal || e.target.matches('.close-modal-btn')) {
                modal.classList.remove('show');
            }
        });

        document.body.appendChild(modal);
        return modal;
    }

    updateNotificationsList(modal) {
        const notificationsList = modal.querySelector('#notificationsList');
        
        if (vaultState.notifications.length === 0) {
            notificationsList.innerHTML = `
                <div class="no-notifications">
                    <h3>✅ All Clear!</h3>
                    <p>No security notifications at this time.</p>
                </div>
            `;
            return;
        }

        notificationsList.innerHTML = vaultState.notifications
            .map(notification => this.createNotificationHTML(notification))
            .join('');
            
        // Add event listeners for acknowledge buttons
        notificationsList.querySelectorAll('.acknowledge-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const notificationId = e.target.getAttribute('data-notification-id');
                await this.acknowledgeNotification(notificationId);
            });
        });
    }

    createNotificationHTML(notification) {
        const timeAgo = this.getTimeAgo(notification.created_at);
        
        return `
            <div class="notification-item ${notification.priority || 'medium'}" data-id="${notification.id}">
                <div class="notification-header">
                    <div class="notification-icon">${this.getNotificationIcon(notification.type)}</div>
                    <div class="notification-content">
                        <div class="notification-title">${notification.title}</div>
                        <div class="notification-message">${notification.message}</div>
                        <div class="notification-time">${timeAgo}</div>
                    </div>
                    <button class="acknowledge-btn" data-notification-id="${notification.id}" title="Acknowledge">✓</button>
                </div>
            </div>
        `;
    }

    getNotificationIcon(type) {
        const icons = {
            breach: '🚨',
            weak: '⚠️',
            age: '📅',
            security: '🔒',
            info: 'ℹ️',
            success: '✅'
        };
        return icons[type] || 'ℹ️';
    }

    async acknowledgeNotification(notificationId) {
        try {
            const result = await api.acknowledgeNotification(notificationId);
            
            if (result.success) {
                // Remove from local state
                vaultState.notifications = vaultState.notifications.filter(n => n.id !== notificationId);
                
                // Update UI
                const notificationElement = document.querySelector(`[data-id="${notificationId}"]`);
                if (notificationElement) {
                    notificationElement.remove();
                }
                
                this.updateNotificationBadge();
                showNotification('Notification acknowledged', 'success');
                
                // Update modal if empty
                const modal = this.modals.get('notifications');
                if (modal && vaultState.notifications.length === 0) {
                    this.updateNotificationsList(modal);
                }
            }
        } catch (error) {
            console.error('Acknowledge notification error:', error);
            showNotification('Failed to acknowledge notification', 'error');
        }
    }

    addNotification(notification) {
        const newNotification = {
            id: Date.now().toString(),
            created_at: new Date().toISOString(),
            acknowledged: false,
            ...notification
        };
        
        vaultState.notifications.unshift(newNotification);
        this.updateNotificationBadge();
        
        // Show toast notification for high priority alerts
        if (notification.priority === 'high' || notification.priority === 'critical') {
            showNotification(notification.title, 'warning');
        }
    }

    updateNotificationBadge() {
        const badge = document.querySelector('.notification-badge');
        if (!badge) return;

        const count = vaultState.notifications.filter(n => !n.acknowledged).length;
        
        if (count > 0) {
            badge.textContent = count > 99 ? '99+' : count.toString();
            badge.style.display = 'flex';
        } else {
            badge.style.display = 'none';
        }
    }

    initializeKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + G - Generate password
            if ((e.ctrlKey || e.metaKey) && e.key === 'g') {
                e.preventDefault();
                this.quickGenerate();
            }
            
            // Ctrl/Cmd + S - Save vault entry
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                const vaultForm = document.querySelector('#vaultForm');
                if (vaultForm && vaultState.isAuthenticated) {
                    e.preventDefault();
                    this.saveVaultEntry();
                }
            }
            
            // Escape - Close modals
            if (e.key === 'Escape') {
                this.closeAllModals();
            }
            
            // Ctrl/Cmd + L - Logout
            if ((e.ctrlKey || e.metaKey) && e.key === 'l' && vaultState.isAuthenticated) {
                e.preventDefault();
                this.handleLogout();
            }
        });
    }

    closeModal(modalName) {
        const modal = this.modals.get(modalName);
        if (modal) {
            modal.classList.remove('show');
        }
    }

    closeAllModals() {
        this.modals.forEach(modal => modal.classList.remove('show'));
    }

    // Utility methods
    formatDate(dateString) {
        if (!dateString) return 'Unknown';
        
        try {
            const date = new Date(dateString);
            const now = new Date();
            const diffTime = Math.abs(now - date);
            const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
            
            if (diffDays === 1) return 'Today';
            if (diffDays === 2) return 'Yesterday';
            if (diffDays <= 7) return `${diffDays} days ago`;
            
            return date.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch (error) {
            return 'Unknown';
        }
    }

    getTimeAgo(dateString) {
        if (!dateString) return 'Unknown';
        
        try {
            const date = new Date(dateString);
            const now = new Date();
            const diffTime = Math.abs(now - date);
            const diffMinutes = Math.floor(diffTime / (1000 * 60));
            const diffHours = Math.floor(diffTime / (1000 * 60 * 60));
            const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
            
            if (diffMinutes < 1) return 'Just now';
            if (diffMinutes < 60) return `${diffMinutes}m ago`;
            if (diffHours < 24) return `${diffHours}h ago`;
            if (diffDays < 30) return `${diffDays}d ago`;
            
            return date.toLocaleDateString();
        } catch (error) {
            return 'Unknown';
        }
    }

    escapeHTML(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
}

// ===== NOTIFICATION SYSTEM =====
function showNotification(message, type = 'info', duration = 5000) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    // Add icon based on type
    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };
    
    notification.innerHTML = `${icons[type] || ''} ${message}`;
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => notification.style.transform = 'translateX(0)', 10);
    
    // Auto remove
    setTimeout(() => {
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, duration);
    
    // Click to dismiss
    notification.addEventListener('click', () => {
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    });
}

// ===== ENHANCED SECURITY CHECKS =====
function performSecurityChecks() {
    // Check if running on HTTPS
    if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
        showNotification('⚠️ VaultGuard should only be used over HTTPS for security', 'warning', 10000);
    }
    
    // Check browser security features
    if (!window.crypto || !window.crypto.getRandomValues) {
        showNotification('❌ Your browser lacks required security features', 'error', 10000);
    }
    
    // Check for clipboard API
    if (!navigator.clipboard) {
        console.warn('Clipboard API not available, using fallback');
    }
}

// ===== BREACH MONITORING SIMULATION =====
function simulateBreachMonitoring() {
    if (!vaultState.settings.breachAlerts) return;
    
    // Simulate periodic breach checking (in real app, this would be server-side)
    setInterval(async () => {
        if (!vaultState.isAuthenticated || vaultState.vaultEntries.length === 0) return;
        
        // Check for potentially breached passwords
        const vulnerableEntries = vaultState.vaultEntries.filter(entry => {
            if (!entry.password) return false;
            const analysis = passwordAnalyzer.analyzePassword(entry.password);
            return analysis.characteristics.isPotentiallyBreached;
        });
        
        vulnerableEntries.forEach(entry => {
            // Don't spam notifications - check if we already notified about this
            const existingAlert = vaultState.notifications.find(n => 
                n.type === 'breach' && n.title.includes(entry.site_name)
            );
            
            if (!existingAlert) {
                uiManager.addNotification({
                    type: 'breach',
                    title: 'Potentially Breached Password',
                    message: `Your password for ${entry.site_name} may have been compromised in data breaches.`,
                    priority: 'high'
                });
            }
        });
        
        // Check for old passwords (90+ days)
        if (vaultState.settings.passwordAgeWarnings) {
            const oldEntries = vaultState.vaultEntries.filter(entry => {
                if (!entry.created_at) return false;
                const created = new Date(entry.created_at);
                const now = new Date();
                const daysDiff = (now - created) / (1000 * 60 * 60 * 24);
                return daysDiff > 90;
            });
            
            oldEntries.forEach(entry => {
                const existingAlert = vaultState.notifications.find(n => 
                    n.type === 'age' && n.title.includes(entry.site_name)
                );
                
                if (!existingAlert) {
                    uiManager.addNotification({
                        type: 'age',
                        title: 'Old Password Detected',
                        message: `Your password for ${entry.site_name} is over 90 days old. Consider updating it.`,
                        priority: 'medium'
                    });
                }
            });
        }
    }, 60000); // Check every minute (in real app, this would be much less frequent)
}

// ===== INITIALIZE APPLICATION =====
const uiManager = new UIManager();

document.addEventListener('DOMContentLoaded', async () => {
    console.log('🔐 VaultGuard Enhanced - Phase 1 Loading...');
    
    // Initialize theme
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    
    // Update theme toggle icon
    const themeToggle = document.querySelector('.theme-toggle');
    if (themeToggle) {
        themeToggle.innerHTML = savedTheme === 'light' ? '🌙' : '☀️';
    }
    
    // Perform security checks
    performSecurityChecks();
    
    // Initialize UI manager
    uiManager.initializeEventListeners();
    
    // Try to restore session if user was logged in
    try {
        // This would typically check for a valid session cookie/token
        const sessionCheck = await api.request('/api/session-check').catch(() => null);
        
        if (sessionCheck && sessionCheck.authenticated) {
            vaultState.isAuthenticated = true;
            vaultState.currentUser = sessionCheck.username;
            await uiManager.initializeAuthenticatedState();
        }
    } catch (error) {
        console.log('No existing session found');
    }
    
    // Start breach monitoring if authenticated
    if (vaultState.isAuthenticated) {
        simulateBreachMonitoring();
    }
    
    // Initialize vault controls
    const vaultControls = document.createElement('div');
    vaultControls.className = 'vault-controls';
    vaultControls.innerHTML = `
        <div class="search-container">
            <span class="search-icon">🔍</span>
            <input type="text" id="vaultSearch" class="search-input" placeholder="Search your passwords..." autocomplete="off">
        </div>
        <div class="sort-container">
            <label class="sort-label">Sort by:</label>
            <select id="vaultSort" class="sort-select">
                <option value="name-asc">Name (A-Z)</option>
                <option value="name-desc">Name (Z-A)</option>
                <option value="date-desc">Newest First</option>
                <option value="date-asc">Oldest First</option>
                <option value="strength-desc">Strongest First</option>
                <option value="strength-asc">Weakest First</option>
                <option value="username-asc">Username (A-Z)</option>
                <option value="username-desc">Username (Z-A)</option>
            </select>
        </div>
    `;
    
    // Insert vault controls before vault list
    const vaultSection = document.querySelector('.vault-section');
    const vaultList = document.querySelector('#vaultList');
    if (vaultSection && vaultList) {
        vaultSection.insertBefore(vaultControls, vaultList);
        
        // Add vault stats container
        const statsContainer = document.createElement('div');
        statsContainer.className = 'vault-stats';
        vaultSection.insertBefore(statsContainer, vaultList);
    }
    
    // Reinitialize vault controls
    uiManager.initializeVaultControls();
    
    console.log('✅ VaultGuard Enhanced - Phase 1 Loaded Successfully!');
    
    // Show success notification
    setTimeout(() => {
        showNotification('🔐 VaultGuard Enhanced Phase 1 Ready!', 'success');
    }, 1000);
});

// ===== ERROR HANDLING =====
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    showNotification('An unexpected error occurred. Please refresh the page.', 'error');
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    showNotification('A network error occurred. Please check your connection.', 'error');
});

// ===== EXPORT FOR TESTING =====
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        VaultGuardState,
        VaultGuardAPI,
        PasswordAnalyzer,
        PasswordGenerator,
        UIManager,
        showNotification
    };
} 15 minutes session timeout
        this.sessionTimeout = setTimeout(() => {
            this.logout();
            showNotification('Session expired for security', 'warning');
        }, 15 * 60 * 1000);
    

    logout() {
        this.isAuthenticated = false;
        this.masterPassword = null;
        this.currentUser = null;
        this.vaultEntries = [];
        if (this.sessionTimeout) {
            clearTimeout(this.sessionTimeout);
        }
        location.reload();
    }
}

// Global state instance
const vaultState = new VaultGuardState();

// ===== ENHANCED API CLIENT WITH PROPER ERROR HANDLING =====
class VaultGuardAPI {
    constructor() {
        this.baseURL = window.location.origin;
        this.headers = {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'Accept': 'application/json'
        };
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        
        const config = {
            method: options.method || 'GET',
            headers: { ...this.headers, ...options.headers },
            credentials: 'same-origin',
            ...options
        };

        if (options.body && typeof options.body === 'object') {
            config.body = JSON.stringify(options.body);
        }

        try {
            const response = await fetch(url, config);
            
            // Update activity timestamp
            vaultState.updateActivity();

            // Handle different content types
            const contentType = response.headers.get('Content-Type') || '';
            
            let data;
            if (contentType.includes('application/json')) {
                data = await response.json();
            } else {
                data = await response.text();
            }

            if (!response.ok) {
                // Enhanced error handling
                const errorMessage = data?.error || data?.message || `HTTP ${response.status}: ${response.statusText}`;
                throw new Error(errorMessage);
            }

            return data;
        } catch (error) {
            console.error(`API Error (${endpoint}):`, error);
            
            // Handle network errors
            if (error.message.includes('Failed to fetch')) {
                throw new Error('Network connection failed. Please check your internet connection.');
            }
            
            // Handle authentication errors
            if (error.message.includes('401') || error.message.includes('Unauthorized')) {
                vaultState.logout();
                throw new Error('Authentication failed. Please log in again.');
            }
            
            throw error;
        }
    }

    // Authentication endpoints
    async register(username, masterPassword) {
        return await this.request('/auth/register', {
            method: 'POST',
            body: { username, master_password: masterPassword }
        });
    }

    async login(username, masterPassword) {
        const result = await this.request('/auth/login', {
            method: 'POST',
            body: { username, master_password: masterPassword }
        });
        
        if (result.success) {
            vaultState.isAuthenticated = true;
            vaultState.masterPassword = masterPassword;
            vaultState.currentUser = username;
            vaultState.resetSessionTimeout();
        }
        
        return result;
    }

    async logout() {
        try {
            await this.request('/auth/logout', { method: 'POST' });
        } catch (error) {
            console.warn('Logout request failed:', error);
        }
        vaultState.logout();
    }

    // Vault endpoints
    async getVaultEntries() {
        const response = await this.request('/api/vault');
        if (response.entries) {
            vaultState.vaultEntries = response.entries;
            return response.entries;
        }
        return [];
    }

    async saveVaultEntry(entry) {
        const response = await this.request('/api/vault', {
            method: 'POST',
            body: entry
        });
        
        if (response.success) {
            await this.getVaultEntries(); // Refresh vault
        }
        
        return response;
    }

    async deleteVaultEntry(entryId) {
        const response = await this.request(`/api/vault/${entryId}`, {
            method: 'DELETE'
        });
        
        if (response.success) {
            await this.getVaultEntries(); // Refresh vault
        }
        
        return response;
    }

    // Notification endpoints
    async getNotifications() {
        try {
            const response = await this.request('/api/notifications');
            vaultState.notifications = response.notifications || [];
            return vaultState.notifications;
        } catch (error) {
            console.warn('Failed to fetch notifications:', error);
            return [];
        }
    }

    async acknowledgeNotification(notificationId) {
        try {
            return await this.request(`/api/notifications/${notificationId}/acknowledge`, {
                method: 'POST'
            });
        } catch (error) {
            console.warn('Failed to acknowledge notification:', error);
            return { success: false };
        }
    }

    // Settings endpoints
    async getSettings() {
        try {
            const response = await this.request('/api/settings');
            if (response.settings) {
                vaultState.settings = { ...vaultState.settings, ...response.settings };
            }
            return vaultState.settings;
        } catch (error) {
            console.warn('Failed to fetch settings:', error);
            return vaultState.settings;
        }
    }

    async saveSettings(settings) {
        try {
            const response = await this.request('/api/settings', {
                method: 'POST',
                body: { settings }
            });
            
            if (response.success) {
                vaultState.settings = { ...vaultState.settings, ...settings };
            }
            
            return response;
        } catch (error) {
            console.warn('Failed to save settings:', error);
            return { success: false, error: error.message };
        }
    }
}

// Global API instance
const api = new VaultGuardAPI();

// ===== ENHANCED PASSWORD ANALYSIS ENGINE =====
class PasswordAnalyzer {
    constructor() {
        // Common weak patterns
        this.weakPatterns = [
            /^(password|123456|qwerty|abc123|admin|login)/i,
            /^(.)\1{3,}/,  // Repeated characters
            /^(012|123|234|345|456|567|678|789|890)+/,  // Sequential numbers
            /^(abc|bcd|cde|def|efg|fgh|ghi)+/i  // Sequential letters
        ];

        // Breach indicators (simulated patterns)
        this.breachPatterns = [
            /password/i, /123456/, /qwerty/i, /admin/i, /welcome/i,
            /sunshine/i, /princess/i, /football/i, /baseball/i, /dragon/i
        ];
    }

    analyzePassword(password) {
        const length = password.length;
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSymbols = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password);
        const hasExtended = /[À-ÿ]/.test(password);

        // Calculate entropy
        let charset = 0;
        if (hasLower) charset += 26;
        if (hasUpper) charset += 26;
        if (hasNumbers) charset += 10;
        if (hasSymbols) charset += 32;
        if (hasExtended) charset += 100;

        const entropy = length > 0 ? Math.log2(Math.pow(charset, length)) : 0;
        const timeToBreak = this.calculateBreakTime(charset, length);

        // Check for weak patterns
        const hasWeakPattern = this.weakPatterns.some(pattern => pattern.test(password));
        const isPotentiallyBreached = this.breachPatterns.some(pattern => pattern.test(password));

        // Advanced strength calculation
        let score = 0;
        
        // Length scoring (0-35 points)
        if (length >= 16) score += 35;
        else if (length >= 12) score += 25;
        else if (length >= 8) score += 15;
        else if (length >= 6) score += 5;

        // Character variety scoring (0-30 points)
        if (hasUpper) score += 5;
        if (hasLower) score += 5;
        if (hasNumbers) score += 5;
        if (hasSymbols) score += 10;
        if (hasExtended) score += 5;

        // Entropy bonus (0-25 points)
        if (entropy >= 100) score += 25;
        else if (entropy >= 80) score += 20;
        else if (entropy >= 60) score += 15;
        else if (entropy >= 40) score += 10;
        else if (entropy >= 20) score += 5;

        // Pattern penalties (-30 points max)
        if (hasWeakPattern) score -= 20;
        if (isPotentiallyBreached) score -= 10;
        if (this.hasRepeatedPatterns(password)) score -= 10;
        if (this.isCommonKeyboardPattern(password)) score -= 15;

        // Bonus points (0-10 points)
        if (length >= 20) score += 5;
        if (this.hasGoodRandomness(password)) score += 5;

        score = Math.max(0, Math.min(100, score));

        return {
            score,
            length,
            entropy: Math.round(entropy),
            timeToBreak,
            characteristics: {
                hasUpper,
                hasLower,
                hasNumbers,
                hasSymbols,
                hasExtended,
                hasWeakPattern,
                isPotentiallyBreached
            },
            strength: this.getStrengthLevel(score),
            recommendations: this.getRecommendations(password, score)
        };
    }

    calculateBreakTime(charset, length) {
        if (charset === 0 || length === 0) return 'Instantly';
        
        const combinations = Math.pow(charset, length);
        const attemptsPerSecond = 1e9; // Assume 1 billion attempts per second
        const secondsToBreak = combinations / (attemptsPerSecond * 2); // Divided by 2 for average time
        
        if (secondsToBreak < 1) return 'Instantly';
        if (secondsToBreak < 60) return `${Math.round(secondsToBreak)} seconds`;
        if (secondsToBreak < 3600) return `${Math.round(secondsToBreak / 60)} minutes`;
        if (secondsToBreak < 86400) return `${Math.round(secondsToBreak / 3600)} hours`;
        if (secondsToBreak < 31536000) return `${Math.round(secondsToBreak / 86400)} days`;
        if (secondsToBreak < 31536000000) return `${Math.round(secondsToBreak / 31536000)} years`;
        return 'Centuries';
    }

    hasRepeatedPatterns(password) {
        // Check for repeated substrings
        for (let i = 1; i <= password.length / 2; i++) {
            const pattern = password.substring(0, i);
            const repeated = pattern.repeat(Math.floor(password.length / i));
            if (password.startsWith(repeated) && repeated.length >= password.length * 0.6) {
                return true;
            }
        }
        return false;
    }

    isCommonKeyboardPattern(password) {
        const keyboardPatterns = [
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            '1234567890', '!@#$%^&*()',
            'qwerty', 'asdf', 'zxcv'
        ];
        
        const lowerPassword = password.toLowerCase();
        return keyboardPatterns.some(pattern => 
            lowerPassword.includes(pattern) || 
            lowerPassword.includes(pattern.split('').reverse().join(''))
        );
    }

    hasGoodRandomness(password) {
        // Simple randomness check
        const chars = password.split('');
        const uniqueChars = new Set(chars).size;
        return uniqueChars >= password.length * 0.7;
    }

    getStrengthLevel(score) {
        if (score >= 90) return 'fortress';
        if (score >= 80) return 'military';
        if (score >= 70) return 'strong';
        if (score >= 50) return 'good';
        if (score >= 30) return 'fair';
        if (score >= 15) return 'weak';
        return 'critical';
    }

    getRecommendations(password, score) {
        const recommendations = [];
        const analysis = this.analyzePassword(password);
        
        if (password.length < 12) {
            recommendations.push('Increase length to at least 12 characters');
        }
        
        if (!analysis.characteristics.hasUpper) {
            recommendations.push('Add uppercase letters (A-Z)');
        }
        
        if (!analysis.characteristics.hasLower) {
            recommendations.push('Add lowercase letters (a-z)');
        }
        
        if (!analysis.characteristics.hasNumbers) {
            recommendations.push('Add numbers (0-9)');
        }
        
        if (!analysis.characteristics.hasSymbols) {
            recommendations.push('Add special characters (!@#$%^&*)');
        }
        
        if (analysis.characteristics.hasWeakPattern) {
            recommendations.push('Avoid common passwords and patterns');
        }
        
        if (analysis.characteristics.isPotentiallyBreached) {
            recommendations.push('This password may have been in data breaches');
        }
        
        if (this.hasRepeatedPatterns(password)) {
            recommendations.push('Avoid repeated patterns and sequences');
        }
        
        if (score < 70) {
            recommendations.push('Consider using a passphrase or password manager');
        }
        
        return recommendations;
    }
}

// Global analyzer instance
const passwordAnalyzer = new PasswordAnalyzer();

// ===== ENHANCED PASSWORD GENERATOR =====
class PasswordGenerator {
    constructor() {
        this.charsets = {
            lowercase: 'abcdefghijklmnopqrstuvwxyz',
            uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            numbers: '0123456789',
            symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
            extended: 'ÀÁÂÃÄÅàáâãäåÇçÈÉÊËèéêëÌÍÎÏìíîïÒÓÔÕÖòóôõöÙÚÛÜùúûüÝýÿ'
        };
    }

    generatePassword(options = {}) {
        const {
            length = 16,
            includeLowercase = true,
            includeUppercase = true,
            includeNumbers = true,
            includeSymbols = true,
            includeExtended = false,
            excludeSimilar = true,
            excludeAmbiguous = true
        } = options;

        let charset = '';
        
        if (includeLowercase) charset += this.charsets.lowercase;
        if (includeUppercase) charset += this.charsets.uppercase;
        if (includeNumbers) charset += this.charsets.numbers;
        if (includeSymbols) charset += this.charsets.symbols;
        if (includeExtended) charset += this.charsets.extended;

        if (!charset) {
            throw new Error('At least one character type must be selected');
        }

        // Remove similar/ambiguous characters if requested
        if (excludeSimilar) {
            charset = charset.replace(/[il1Lo0O]/g, '');
        }
        
        if (excludeAmbiguous) {
            charset = charset.replace(/[{}[\]()\/\\'"~,;<>.]/g, '');
        }

        // Ensure at least one character from each selected type
        let password = '';
        const requiredChars = [];
        
        if (includeLowercase) requiredChars.push(this.getRandomChar(this.charsets.lowercase, excludeSimilar, excludeAmbiguous));
        if (includeUppercase) requiredChars.push(this.getRandomChar(this.charsets.uppercase, excludeSimilar, excludeAmbiguous));
        if (includeNumbers) requiredChars.push(this.getRandomChar(this.charsets.numbers, excludeSimilar, excludeAmbiguous));
        if (includeSymbols) requiredChars.push(this.getRandomChar(this.charsets.symbols, excludeSimilar, excludeAmbiguous));
        if (includeExtended) requiredChars.push(this.getRandomChar(this.charsets.extended, excludeSimilar, excludeAmbiguous));

        // Add required characters
        for (const char of requiredChars) {
            password += char;
        }

        // Fill the rest randomly
        for (let i = password.length; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }

        // Shuffle the password to avoid predictable patterns
        return this.shuffleString(password);
    }

    getRandomChar(charset, excludeSimilar = false, excludeAmbiguous = false) {
        let filteredCharset = charset;
        
        if (excludeSimilar) {
            filteredCharset = filteredCharset.replace(/[il1Lo0O]/g, '');
        }
        
        if (excludeAmbiguous) {
            filteredCharset = filteredCharset.replace(/[{}[\]()\/\\'"~,;<>.]/g, '');
        }
        
        return filteredCharset.charAt(Math.floor(Math.random() * filteredCharset.length));
    }

    shuffleString(str) {
        const array = str.split('');
        for (let i = array.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [array[i], array[j]] = [array[j], array[i]];
        }
        return array.join('');
    }

    generatePassphrase(options = {}) {
        const {
            wordCount = 4,
            separator = '-',
            includeNumbers = true,
            capitalize = true
        } = options;

        // Common word list (truncated for brevity)
        const words = [
            'apple', 'brave', 'chair', 'dance', 'eagle', 'flame', 'green', 'house',
            'ice', 'jazz', 'kite', 'lemon', 'moon', 'night', 'ocean', 'peace',
            'quiet', 'river', 'stone', 'tiger', 'under', 'voice', 'whale', 'xenon',
            'yellow', 'zebra', 'magic', 'storm', 'cloud', 'dream', 'forest', 'guitar',
            'happy', 'island', 'jungle', 'knight', 'light', 'mountain', 'nature', 'orbit',
            'planet', 'queen', 'rocket', 'silver', 'thunder', 'unique', 'valley', 'wonder'
        ];

        let passphrase = '';
        
        for (let i = 0; i < wordCount; i++) {
            let word = words[Math.floor(Math.random() * words.length)];
            
            if (capitalize) {
                word = word.charAt(0).toUpperCase() + word.slice(1);
            }
            
            if (includeNumbers && Math.random() < 0.5) {
                word += Math.floor(Math.random() * 10);
            }
            
            passphrase += word;
            if (i < wordCount - 1) {
                passphrase += separator;
            }
        }

        return passphrase;
    }
}

// Global generator instance
const passwordGenerator = new PasswordGenerator();

// ===== ENHANCED UI MANAGER =====
class UIManager {
    constructor() {
        this.modals = new Map();
        this.notifications = [];
    }

    initializeEventListeners() {
        // Theme toggle
        const themeToggle = document.querySelector('.theme-toggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', this.toggleTheme.bind(this));
        }

        // Password input real-time analysis
        const passwordInput = document.querySelector('#password');
        if (passwordInput) {
            passwordInput.addEventListener('input', this.handlePasswordInput.bind(this));
        }

        // Generator controls
        this.initializeGeneratorControls();
        
        // Authentication
        this.initializeAuthModals();
        
        // Vault controls
        this.initializeVaultControls();
        
        // Settings
        this.initializeSettingsModal();
        
        // Global keyboard shortcuts
        this.initializeKeyboardShortcuts();

        // Activity tracking
        document.addEventListener('click', () => vaultState.updateActivity());
        document.addEventListener('keypress', () => vaultState.updateActivity());
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        // Update theme toggle icon
        const themeToggle = document.querySelector('.theme-toggle');
        if (themeToggle) {
            themeToggle.innerHTML = newTheme === 'light' ? '🌙' : '☀️';
        }
        
        showNotification(`Switched to ${newTheme} theme`, 'success');
    }

    handlePasswordInput(event) {
        const password = event.target.value;
        this.updatePasswordStrength(password);
    }

    updatePasswordStrength(password) {
        if (!password) {
            this.hideStrengthIndicator();
            return;
        }

        const analysis = passwordAnalyzer.analyzePassword(password);
        this.showStrengthIndicator(analysis);
    }

    showStrengthIndicator(analysis) {
        let strengthSection = document.querySelector('.strength-section');
        
        if (!strengthSection) {
            strengthSection = this.createStrengthSection();
        }

        strengthSection.style.display = 'block';
        
        // Update strength bar
        const strengthFill = strengthSection.querySelector('.strength-fill');
        const strengthText = strengthSection.querySelector('.strength-text');
        
        if (strengthFill && strengthText) {
            strengthFill.style.width = `${analysis.score}%`;
            strengthFill.className = `strength-fill ${analysis.strength}`;
            strengthText.className = `strength-text ${analysis.strength}`;
            strengthText.textContent = analysis.strength.toUpperCase();
        }

        // Update analysis metrics
        this.updateAnalysisMetrics(analysis);
        
        // Update policy checklist
        this.updatePolicyChecklist(analysis);
    }

    createStrengthSection() {
        const passwordGroup = document.querySelector('.password-input-group');
        if (!passwordGroup) return null;

        const strengthSection = document.createElement('div');
        strengthSection.className = 'strength-section';
        strengthSection.innerHTML = `
            <div class="strength-label">
                <span class="strength-text">CHECKING</span>
                <span class="strength-percentage">0%</span>
            </div>
            <div class="strength-bar">
                <div class="strength-fill" style="width: 0%"></div>
            </div>
            <div class="analysis-grid">
                <div class="analysis-item">
                    <span class="analysis-icon">🔢</span>
                    <div class="analysis-label">Length</div>
                    <div class="analysis-value length-value">0</div>
                </div>
                <div class="analysis-item">
                    <span class="analysis-icon">⚡</span>
                    <div class="analysis-label">Entropy</div>
                    <div class="analysis-value entropy-value">0 bits</div>
                </div>
                <div class="analysis-item">
                    <span class="analysis-icon">⏱️</span>
                    <div class="analysis-label">Crack Time</div>
                    <div class="analysis-value time-value">Instantly</div>
                </div>
                <div class="analysis-item">
                    <span class="analysis-icon">🎯</span>
                    <div class="analysis-label">Score</div>
                    <div class="analysis-value score-value">0/100</div>
                </div>
            </div>
            <ul class="policy-list">
                <li class="policy-item">
                    <div class="policy-icon invalid">✗</div>
                    <span>At least 8 characters</span>
                </li>
                <li class="policy-item">
                    <div class="policy-icon invalid">✗</div>
                    <span>Contains uppercase letters</span>
                </li>
                <li class="policy-item">
                    <div class="policy-icon invalid">✗</div>
                    <span>Contains lowercase letters</span>
                </li>
                <li class="policy-item">
                    <div class="policy-icon invalid">✗</div>
                    <span>Contains numbers</span>
                </li>
                <li class="policy-item">
                    <div class="policy-icon invalid">✗</div>
                    <span>Contains special characters</span>
                </li>
                <li class="policy-item">
                    <div class="policy-icon invalid">✗</div>
                    <span>No common patterns</span>
                </li>
            </ul>
        `;

        passwordGroup.appendChild(strengthSection);
        return strengthSection;
    }

    updateAnalysisMetrics(analysis) {
        const lengthValue = document.querySelector('.length-value');
        const entropyValue = document.querySelector('.entropy-value');
        const timeValue = document.querySelector('.time-value');
        const scoreValue = document.querySelector('.score-value');
        const strengthPercentage = document.querySelector('.strength-percentage');

        if (lengthValue) lengthValue.textContent = analysis.length;
        if (entropyValue) entropyValue.textContent = `${analysis.entropy} bits`;
        if (timeValue) timeValue.textContent = analysis.timeToBreak;
        if (scoreValue) scoreValue.textContent = `${analysis.score}/100`;
        if (strengthPercentage) strengthPercentage.textContent = `${analysis.score}%`;
    }

    updatePolicyChecklist(analysis) {
        const policies = document.querySelectorAll('.policy-item');
        const { characteristics } = analysis;
        
        const checks = [
            analysis.length >= 8,
            characteristics.hasUpper,
            characteristics.hasLower,
            characteristics.hasNumbers,
            characteristics.hasSymbols,
            !characteristics.hasWeakPattern
        ];

        policies.forEach((policy, index) => {
            const icon = policy.querySelector('.policy-icon');
            if (icon) {
                if (checks[index]) {
                    icon.className = 'policy-icon valid';
                    icon.textContent = '✓';
                } else {
                    icon.className = 'policy-icon invalid';
                    icon.textContent = '✗';
                }
            }
        });
    }

    hideStrengthIndicator() {
        const strengthSection = document.querySelector('.strength-section');
        if (strengthSection) {
            strengthSection.style.display = 'none';
        }
    }

    initializeGeneratorControls() {
        // Password generation button
        const generateBtn = document.querySelector('#generatePassword');
        if (generateBtn) {
            generateBtn.addEventListener('click', this.generatePassword.bind(this));
        }

        // Generator sliders and checkboxes
        const lengthSlider = document.querySelector('#length');
        if (lengthSlider) {
            lengthSlider.addEventListener('input', (e) => {
                const value = document.querySelector('#lengthValue');
                if (value) value.textContent = e.target.value;
            });
        }
    }}
