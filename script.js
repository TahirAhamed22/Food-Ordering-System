// ===== ENHANCED VAULTGUARD SCRIPT - PHASE 1 COMPLETE =====
// Fixed errors, added Phase 1 features, proper integration

// Global Variables
let analysisEnabled = true;
let currentUserSalt = null;
let masterPasswordCache = null;
let securityMode = true;
let themePreference = localStorage.getItem('theme') || 'dark';
let isLoginMode = true;
let vaultData = [];
let vaultFilter = '';
let vaultSortBy = 'updated_at';
let currentPage = 'analyzer';

// Phase 1: Enhanced password generator settings
let passwordGeneratorSettings = {
    length: 16,
    includeUpper: true,
    includeLower: true,
    includeNumbers: true,
    includeSymbols: true,
    excludeAmbiguous: false
};

// Performance tracking
let performanceMetrics = {
    pageLoadTime: 0,
    analysisCount: 0,
    apiCallCount: 0
};

// DOM Elements Cache
let elements = {};

// ===== INITIALIZATION =====
function initializeElements() {
    elements = {
        // Main interface
        themeToggle: document.getElementById('themeToggle'),
        passwordInput: document.getElementById('passwordInput'),
        strengthSection: document.getElementById('strengthSection'),
        analysisResults: document.getElementById('analysisResults'),
        policySection: document.getElementById('policySection'),
        strengthFill: document.getElementById('strengthFill'),
        strengthText: document.getElementById('strengthText'),
        crackTime: document.getElementById('crackTime'),
        breachStatus: document.getElementById('breachStatus'),
        
        // Policy icons
        lengthIcon: document.getElementById('lengthIcon'),
        lowerIcon: document.getElementById('lowerIcon'),
        upperIcon: document.getElementById('upperIcon'),
        digitIcon: document.getElementById('digitIcon'),
        symbolIcon: document.getElementById('symbolIcon'),
        
        // Controls
        toggleVisibility: document.getElementById('toggleVisibility'),
        copyPassword: document.getElementById('copyPassword'),
        clearPassword: document.getElementById('clearPassword'),
        generatePassword: document.getElementById('generatePassword'),
        pauseBtn: document.getElementById('pauseBtn'),
        
        // Generator page
        lengthSlider: document.getElementById('lengthSlider'),
        lengthValue: document.getElementById('lengthValue'),
        generateBtn: document.getElementById('generateBtn'),
        generatedPassword: document.getElementById('generatedPassword'),
        copyGenerated: document.getElementById('copyGenerated'),
        useGenerated: document.getElementById('useGenerated'),
        includeUpper: document.getElementById('includeUpper'),
        includeLower: document.getElementById('includeLower'),
        includeNumbers: document.getElementById('includeNumbers'),
        includeSymbols: document.getElementById('includeSymbols'),
        excludeAmbiguous: document.getElementById('excludeAmbiguous'),
        
        // Authentication
        authModal: document.getElementById('authModal'),
        authForm: document.getElementById('authForm'),
        authTitle: document.getElementById('authTitle'),
        authSubmit: document.getElementById('authSubmit'),
        authUsername: document.getElementById('authUsername'),
        authPassword: document.getElementById('authPassword'),
        authEmail: document.getElementById('authEmail'),
        authPhone: document.getElementById('authPhone'),
        loginBtn: document.getElementById('loginBtn'),
        closeModal: document.getElementById('closeModal'),
        
        // Vault management
        vaultList: document.getElementById('vaultList'),
        savePasswordBtn: document.getElementById('save-password-btn'),
        vaultTitle: document.getElementById('vault-title'),
        siteName: document.getElementById('site-name'),
        vaultUsername: document.getElementById('vault-username'),
        vaultPassword: document.getElementById('vault-password'),
        vaultCategory: document.getElementById('vault-category'),
        vaultNotes: document.getElementById('vault-notes'),
        vaultTags: document.getElementById('vault-tags'),
        
        // Phase 1: Enhanced search and filters
        vaultSearch: document.getElementById('vault-search'),
        vaultSort: document.getElementById('vault-sort'),
        categoryFilter: document.getElementById('category-filter'),
        favoritesFilter: document.getElementById('favorites-filter'),
        
        // Phase 1: Notification system
        notificationsBtn: document.getElementById('notificationsBtn'),
        notificationModal: document.getElementById('notificationModal'),
        notificationsList: document.getElementById('notificationsList'),
        notificationBadge: document.getElementById('notificationBadge'),
        
        // Phase 1: Settings
        settingsBtn: document.getElementById('settingsBtn'),
        settingsModal: document.getElementById('settingsModal'),
        notificationSettings: document.getElementById('notificationSettings')
    };
}

async function initialize() {
    try {
        const startTime = performance.now();
        
        initializeElements();
        initializeTheme();
        initializeEventListeners();
        
        // Check authentication status
        await checkAuthenticationStatus();
        
        // Load user data if authenticated
        if (currentUserSalt) {
            await loadVaultData();
            await loadUserNotifications();
        }
        
        // Initialize current page features
        initializeCurrentPage();
        
        const loadTime = performance.now() - startTime;
        performanceMetrics.pageLoadTime = loadTime;
        
        console.log(`VaultGuard initialized in ${loadTime.toFixed(2)}ms`);
        showNotification('VaultGuard loaded successfully', 'success');
        
    } catch (error) {
        console.error('Initialization error:', error);
        showNotification('Failed to initialize VaultGuard', 'error');
    }
}

// ===== THEME MANAGEMENT =====
function initializeTheme() {
    document.body.setAttribute('data-theme', themePreference);
    updateThemeToggle();
    
    if (elements.themeToggle) {
        elements.themeToggle.addEventListener('click', toggleTheme);
    }
}

function toggleTheme() {
    themePreference = themePreference === 'dark' ? 'light' : 'dark';
    localStorage.setItem('theme', themePreference);
    document.body.setAttribute('data-theme', themePreference);
    updateThemeToggle();
    showNotification(`Switched to ${themePreference} theme`, 'info');
}

function updateThemeToggle() {
    if (elements.themeToggle) {
        elements.themeToggle.textContent = themePreference === 'dark' ? '🌙' : '☀️';
        elements.themeToggle.title = `Switch to ${themePreference === 'dark' ? 'light' : 'dark'} theme`;
    }
}

// ===== EVENT LISTENERS =====
function initializeEventListeners() {
    // Password analyzer
    if (elements.passwordInput) {
        elements.passwordInput.addEventListener('input', debounce((e) => {
            analyzePassword(e.target.value);
        }, 300));
        
        elements.passwordInput.addEventListener('paste', (e) => {
            setTimeout(() => analyzePassword(e.target.value), 10);
        });
    }

    // Password controls
    if (elements.toggleVisibility) {
        elements.toggleVisibility.addEventListener('click', togglePasswordVisibility);
    }
    if (elements.copyPassword) {
        elements.copyPassword.addEventListener('click', copyPasswordToClipboard);
    }
    if (elements.clearPassword) {
        elements.clearPassword.addEventListener('click', clearPasswordInput);
    }
    if (elements.generatePassword) {
        elements.generatePassword.addEventListener('click', generateAndAnalyzePassword);
    }
    if (elements.pauseBtn) {
        elements.pauseBtn.addEventListener('click', toggleAnalysis);
    }

    // Generator controls
    if (elements.lengthSlider) {
        elements.lengthSlider.addEventListener('input', (e) => {
            updateLengthDisplay(parseInt(e.target.value));
        });
    }
    if (elements.generateBtn) {
        elements.generateBtn.addEventListener('click', generateNewPassword);
    }
    if (elements.copyGenerated) {
        elements.copyGenerated.addEventListener('click', copyGeneratedPassword);
    }
    if (elements.useGenerated) {
        elements.useGenerated.addEventListener('click', useGeneratedPassword);
    }

    // Generator checkboxes
    ['includeUpper', 'includeLower', 'includeNumbers', 'includeSymbols', 'excludeAmbiguous'].forEach(id => {
        const element = elements[id];
        if (element) {
            element.addEventListener('change', updatePasswordGeneratorSettings);
        }
    });

    // Authentication
    if (elements.loginBtn) {
        elements.loginBtn.addEventListener('click', openAuthModal);
    }
    if (elements.closeModal) {
        elements.closeModal.addEventListener('click', closeAuthModal);
    }
    if (elements.authForm) {
        elements.authForm.addEventListener('submit', handleAuth);
    }

    // Vault management
    if (elements.savePasswordBtn) {
        elements.savePasswordBtn.addEventListener('click', savePassword);
    }

    // Phase 1: Enhanced search and filters
    if (elements.vaultSearch) {
        elements.vaultSearch.addEventListener('input', debounce((e) => {
            filterVaultEntries(e.target.value);
        }, 300));
    }
    if (elements.vaultSort) {
        elements.vaultSort.addEventListener('change', (e) => {
            sortVaultEntries(e.target.value);
        });
    }
    if (elements.categoryFilter) {
        elements.categoryFilter.addEventListener('change', filterByCategory);
    }
    if (elements.favoritesFilter) {
        elements.favoritesFilter.addEventListener('change', filterByFavorites);
    }

    // Phase 1: Notifications
    if (elements.notificationsBtn) {
        elements.notificationsBtn.addEventListener('click', toggleNotifications);
    }

    // Phase 1: Settings
    if (elements.settingsBtn) {
        elements.settingsBtn.addEventListener('click', toggleSettings);
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);
    
    // Page visibility handling
    document.addEventListener('visibilitychange', handleVisibilityChange);
}

// ===== AUTHENTICATION =====
async function checkAuthenticationStatus() {
    try {
        const response = await fetch('/api/me');
        const data = await response.json();
        
        if (data.success && data.authenticated) {
            currentUserSalt = data.salt;
            updateUIForAuthenticatedUser(data);
        } else {
            updateUIForUnauthenticatedUser();
        }
    } catch (error) {
        console.error('Auth status check failed:', error);
        updateUIForUnauthenticatedUser();
    }
}

function updateUIForAuthenticatedUser(userData) {
    // Update UI elements for authenticated users
    const usernameElements = document.querySelectorAll('.current-username');
    usernameElements.forEach(el => el.textContent = userData.username);
    
    // Update notification badge
    if (userData.alerts && userData.alerts.length > 0) {
        updateNotificationBadge(userData.alerts.length);
    }
    
    // Show authenticated sections
    const authSections = document.querySelectorAll('.auth-required');
    authSections.forEach(section => section.style.display = 'block');
    
    const loginBtns = document.querySelectorAll('.login-btn');
    loginBtns.forEach(btn => btn.style.display = 'none');
}

function updateUIForUnauthenticatedUser() {
    currentUserSalt = null;
    masterPasswordCache = null;
    
    const authSections = document.querySelectorAll('.auth-required');
    authSections.forEach(section => section.style.display = 'none');
    
    const loginBtns = document.querySelectorAll('.login-btn');
    loginBtns.forEach(btn => btn.style.display = 'block');
}

function openAuthModal() {
    if (elements.authModal) {
        elements.authModal.classList.add('show');
        setAuthMode(isLoginMode);
        
        setTimeout(() => {
            if (elements.authUsername) {
                elements.authUsername.focus();
            }
        }, 100);
    }
}

function closeAuthModal() {
    if (elements.authModal) {
        elements.authModal.classList.remove('show');
        if (elements.authForm) {
            elements.authForm.reset();
        }
    }
}

function setAuthMode(loginMode) {
    isLoginMode = loginMode;
    
    if (elements.authTitle && elements.authSubmit) {
        if (isLoginMode) {
            elements.authTitle.textContent = '🔐 VaultGuard Login';
            elements.authSubmit.textContent = 'Login';
            
            // Hide registration fields
            if (elements.authEmail) elements.authEmail.parentElement.style.display = 'none';
            if (elements.authPhone) elements.authPhone.parentElement.style.display = 'none';
        } else {
            elements.authTitle.textContent = '🛡️ Create Account';
            elements.authSubmit.textContent = 'Register';
            
            // Show registration fields
            if (elements.authEmail) elements.authEmail.parentElement.style.display = 'block';
            if (elements.authPhone) elements.authPhone.parentElement.style.display = 'block';
        }
    }
}

async function handleAuth(event) {
    event.preventDefault();
    
    const username = elements.authUsername?.value.trim();
    const password = elements.authPassword?.value;
    const email = elements.authEmail?.value.trim();
    const phone = elements.authPhone?.value.trim();
    
    if (!username || !password) {
        showNotification('Please fill in all required fields', 'error');
        return;
    }
    
    const endpoint = isLoginMode ? '/api/login' : '/api/register';
    const payload = { username, password };
    
    if (!isLoginMode) {
        if (email) payload.email = email;
        if (phone) payload.phone = phone;
    }
    
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUserSalt = data.salt;
            masterPasswordCache = password;
            showNotification(data.message, 'success');
            closeAuthModal();
            
            setTimeout(() => {
                window.location.reload();
            }, 1500);
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Auth error:', error);
        showNotification('Authentication failed', 'error');
    }
}

// ===== PASSWORD ANALYSIS =====
function analyzePassword(password) {
    performanceMetrics.analysisCount++;
    
    if (!password || !analysisEnabled) {
        hideAnalysisSection();
        return;
    }

    showAnalysisSection();
    
    // Calculate strength
    const strength = calculatePasswordStrength(password);
    updateStrengthMeter(strength);
    updatePasswordPolicyIcons(password);
    
    // Check against breach database
    checkPasswordBreach(password);
}

function calculatePasswordStrength(password) {
    if (!password) return { score: 0, level: 'None', color: '#6c757d' };
    
    let score = 0;
    let bonuses = [];
    let penalties = [];
    
    // Length scoring
    if (password.length >= 8) { score += 20; bonuses.push('Minimum length'); }
    if (password.length >= 12) { score += 15; bonuses.push('Good length'); }
    if (password.length >= 16) { score += 15; bonuses.push('Excellent length'); }
    
    // Character variety
    if (/[a-z]/.test(password)) { score += 10; bonuses.push('Lowercase'); }
    if (/[A-Z]/.test(password)) { score += 10; bonuses.push('Uppercase'); }
    if (/[0-9]/.test(password)) { score += 10; bonuses.push('Numbers'); }
    if (/[^A-Za-z0-9]/.test(password)) { score += 20; bonuses.push('Symbols'); }
    
    // Penalty checks
    if (password.length < 8) {
        score -= 30;
        penalties.push('Too short');
    }
    if (/^[a-zA-Z]+$/.test(password)) {
        score -= 20;
        penalties.push('Only letters');
    }
    if (/(.)\1{2,}/.test(password)) {
        score -= 15;
        penalties.push('Repeated characters');
    }
    if (/123|abc|qwe/i.test(password)) {
        score -= 20;
        penalties.push('Common patterns');
    }
    
    score = Math.max(0, Math.min(100, score));
    
    // Determine level and color
    let level, color;
    if (score >= 90) { level = 'Fortress'; color = '#2ed573'; }
    else if (score >= 75) { level = 'Very Strong'; color = '#26d0ce'; }
    else if (score >= 60) { level = 'Strong'; color = '#3742fa'; }
    else if (score >= 40) { level = 'Good'; color = '#ffa502'; }
    else if (score >= 20) { level = 'Weak'; color = '#ff6348'; }
    else { level = 'Very Weak'; color = '#ff4757'; }
    
    return { score, level, color, bonuses, penalties };
}

function updateStrengthMeter(strength) {
    if (elements.strengthFill) {
        elements.strengthFill.style.width = strength.score + '%';
        elements.strengthFill.style.backgroundColor = strength.color;
    }
    
    if (elements.strengthText) {
        elements.strengthText.textContent = `${strength.level} (${strength.score}%)`;
        elements.strengthText.style.color = strength.color;
    }
}

function updatePasswordPolicyIcons(password) {
    const checks = [
        { element: elements.lengthIcon, valid: password.length >= 12, label: '12+ characters' },
        { element: elements.lowerIcon, valid: /[a-z]/.test(password), label: 'Lowercase' },
        { element: elements.upperIcon, valid: /[A-Z]/.test(password), label: 'Uppercase' },
        { element: elements.digitIcon, valid: /[0-9]/.test(password), label: 'Numbers' },
        { element: elements.symbolIcon, valid: /[^A-Za-z0-9]/.test(password), label: 'Symbols' }
    ];
    
    checks.forEach(check => {
        if (check.element) {
            check.element.className = check.valid ? 'policy-icon valid' : 'policy-icon invalid';
            check.element.textContent = check.valid ? '✓' : '✗';
            check.element.title = `${check.label}: ${check.valid ? 'Yes' : 'No'}`;
        }
    });
}

async function checkPasswordBreach(password) {
    if (!password) return;
    
    try {
        performanceMetrics.apiCallCount++;
        
        const response = await fetch('/api/check_password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        
        const data = await response.json();
        
        if (data.success && elements.breachStatus) {
            if (data.breached) {
                elements.breachStatus.innerHTML = `
                    <span class="breach-warning">
                        🚨 BREACHED: Found in ${data.count.toLocaleString()} breaches!
                    </span>
                `;
                elements.breachStatus.className = 'breach-status breached';
            } else {
                elements.breachStatus.innerHTML = `
                    <span class="breach-safe">
                        ✅ SECURE: Not found in known breaches
                    </span>
                `;
                elements.breachStatus.className = 'breach-status safe';
            }
            
            // Update crack time
            if (elements.crackTime && data.crack_time) {
                elements.crackTime.textContent = `Crack time: ${data.crack_time}`;
            }
        }
    } catch (error) {
        console.error('Breach check failed:', error);
        if (elements.breachStatus) {
            elements.breachStatus.innerHTML = '<span class="breach-unknown">⚠️ Breach check unavailable</span>';
        }
    }
}

function showAnalysisSection() {
    [elements.strengthSection, elements.analysisResults, elements.policySection].forEach(section => {
        if (section) {
            section.style.display = 'block';
        }
    });
}

function hideAnalysisSection() {
    [elements.strengthSection, elements.analysisResults, elements.policySection].forEach(section => {
        if (section) {
            section.style.display = 'none';
        }
    });
}

// ===== PASSWORD CONTROLS =====
function togglePasswordVisibility() {
    if (!elements.passwordInput || !elements.toggleVisibility) return;
    
    const isPassword = elements.passwordInput.type === 'password';
    elements.passwordInput.type = isPassword ? 'text' : 'password';
    elements.toggleVisibility.textContent = isPassword ? '🙈' : '👁️';
    elements.toggleVisibility.title = isPassword ? 'Hide password' : 'Show password';
}

async function copyPasswordToClipboard() {
    if (!elements.passwordInput?.value) {
        showNotification('No password to copy', 'warning');
        return;
    }
    
    try {
        await navigator.clipboard.writeText(elements.passwordInput.value);
        showNotification('Password copied to clipboard!', 'success');
        
        // Security: Clear clipboard after 30 seconds
        setTimeout(() => {
            navigator.clipboard.writeText('').catch(() => {});
        }, 30000);
    } catch (error) {
        console.error('Clipboard error:', error);
        showNotification('Failed to copy password', 'error');
    }
}

function clearPasswordInput() {
    if (elements.passwordInput) {
        elements.passwordInput.value = '';
        analyzePassword('');
        elements.passwordInput.focus();
        showNotification('Password cleared', 'info');
    }
}

function generateAndAnalyzePassword() {
    const password = generateRandomPassword();
    if (elements.passwordInput) {
        elements.passwordInput.value = password;
        analyzePassword(password);
        showNotification('Secure password generated!', 'success');
    }
}

function toggleAnalysis() {
    analysisEnabled = !analysisEnabled;
    
    if (elements.pauseBtn) {
        elements.pauseBtn.textContent = analysisEnabled ? '⏸️' : '▶️';
        elements.pauseBtn.title = analysisEnabled ? 'Pause analysis' : 'Resume analysis';
    }
    
    if (!analysisEnabled) {
        hideAnalysisSection();
    } else {
        analyzePassword(elements.passwordInput?.value || '');
    }
    
    showNotification(`Analysis ${analysisEnabled ? 'resumed' : 'paused'}`, 'info');
}

// ===== PASSWORD GENERATOR =====
function updateLengthDisplay(length) {
    if (elements.lengthValue) {
        elements.lengthValue.textContent = length;
    }
    passwordGeneratorSettings.length = length;
}

function updatePasswordGeneratorSettings() {
    passwordGeneratorSettings = {
        length: parseInt(elements.lengthSlider?.value || 16),
        includeUpper: elements.includeUpper?.checked ?? true,
        includeLower: elements.includeLower?.checked ?? true,
        includeNumbers: elements.includeNumbers?.checked ?? true,
        includeSymbols: elements.includeSymbols?.checked ?? true,
        excludeAmbiguous: elements.excludeAmbiguous?.checked ?? false
    };
    
    // Ensure at least one character type is selected
    if (!passwordGeneratorSettings.includeUpper && !passwordGeneratorSettings.includeLower && 
        !passwordGeneratorSettings.includeNumbers && !passwordGeneratorSettings.includeSymbols) {
        passwordGeneratorSettings.includeLower = true;
        if (elements.includeLower) elements.includeLower.checked = true;
        showNotification('At least one character type must be selected', 'warning');
    }
}

function generateNewPassword() {
    if (elements.generateBtn) {
        const originalText = elements.generateBtn.textContent;
        elements.generateBtn.textContent = 'Generating...';
        elements.generateBtn.disabled = true;
        
        setTimeout(() => {
            const password = generateRandomPassword();
            if (elements.generatedPassword) {
                elements.generatedPassword.value = password;
            }
            
            elements.generateBtn.textContent = originalText;
            elements.generateBtn.disabled = false;
            showNotification('Cryptographically secure password generated!', 'success');
        }, 500);
    }
}

function generateRandomPassword() {
    updatePasswordGeneratorSettings();
    
    let charset = '';
    if (passwordGeneratorSettings.includeUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (passwordGeneratorSettings.includeLower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (passwordGeneratorSettings.includeNumbers) charset += '0123456789';
    if (passwordGeneratorSettings.includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    if (passwordGeneratorSettings.excludeAmbiguous) {
        charset = charset.replace(/[0O1lI]/g, '');
    }
    
    if (!charset) {
        charset = 'abcdefghijklmnopqrstuvwxyz';
        showNotification('Using default character set', 'warning');
    }
    
    // Generate secure random password
    const array = new Uint8Array(passwordGeneratorSettings.length);
    crypto.getRandomValues(array);
    
    let password = '';
    for (let i = 0; i < passwordGeneratorSettings.length; i++) {
        password += charset.charAt(array[i] % charset.length);
    }
    
    return password;
}

async function copyGeneratedPassword() {
    if (!elements.generatedPassword?.value) {
        showNotification('No generated password to copy', 'warning');
        return;
    }
    
    try {
        await navigator.clipboard.writeText(elements.generatedPassword.value);
        showNotification('Generated password copied!', 'success');
    } catch (error) {
        showNotification('Failed to copy password', 'error');
    }
}

function useGeneratedPassword() {
    if (elements.generatedPassword?.value && elements.passwordInput) {
        elements.passwordInput.value = elements.generatedPassword.value;
        analyzePassword(elements.generatedPassword.value);
        showNotification('Password moved to analyzer!', 'success');
    }
}

// ===== VAULT MANAGEMENT =====
async function loadVaultData() {
    try {
        const response = await fetch('/api/vault');
        const data = await response.json();
        
        if (data.success) {
            vaultData = data.vault_entries;
            updateVaultDisplay();
            showNotification(`Loaded ${vaultData.length} encrypted passwords`, 'info');
        } else {
            throw new Error(data.message);
        }
    } catch (error) {
        console.error('Failed to load vault:', error);
        showNotification('Failed to load vault data', 'error');
    }
}

function updateVaultDisplay() {
    if (!elements.vaultList) return;
    
    let filteredData = [...vaultData];
    
    // Apply filters
    if (vaultFilter) {
        filteredData = filteredData.filter(item => 
            item.title.toLowerCase().includes(vaultFilter) ||
            item.site.toLowerCase().includes(vaultFilter) ||
            item.username.toLowerCase().includes(vaultFilter)
        );
    }
    
    // Apply sorting
    filteredData.sort((a, b) => {
        switch (vaultSortBy) {
            case 'title':
                return a.title.localeCompare(b.title);
            case 'site':
                return a.site.localeCompare(b.site);
            case 'category':
                return (a.category || 'General').localeCompare(b.category || 'General');
            case 'created_at':
                return new Date(b.created_at) - new Date(a.created_at);
            default:
                return new Date(b.updated_at) - new Date(a.updated_at);
        }
    });
    
    if (filteredData.length === 0) {
        elements.vaultList.innerHTML = `
            <div class="empty-vault">
                <div class="empty-vault-icon">🔐</div>
                <h3>No passwords found</h3>
                <p>Your secure vault is empty or no matches found.</p>
            </div>
        `;
        return;
    }
    
    elements.vaultList.innerHTML = filteredData.map(item => `
        <div class="vault-item" data-id="${item.id}">
            <div class="vault-header">
                <div class="vault-title">${escapeHtml(item.title || item.site)}</div>
                <div class="vault-actions">
                    ${item.favorite ? '<span class="favorite-star">⭐</span>' : ''}
                    <button onclick="toggleFavorite(${item.id})" class="vault-btn favorite-btn" title="Toggle favorite">
                        ${item.favorite ? '⭐' : '☆'}
                    </button>
                    <button onclick="copyVaultPassword(${item.id})" class="vault-btn copy-btn" title="Copy password">
                        📋
                    </button>
                    <button onclick="viewVaultPassword(${item.id})" class="vault-btn view-btn" title="View password">
                        👁️
                    </button>
                    <button onclick="deleteVaultPassword(${item.id})" class="vault-btn delete-btn" title="Delete password">
                        🗑️
                    </button>
                </div>
            </div>
            <div class="vault-details">
                <div class="vault-site">🌐 ${escapeHtml(item.site)}</div>
                <div class="vault-username">👤 ${escapeHtml(item.username)}</div>
                <div class="vault-category">📁 ${escapeHtml(item.category || 'General')}</div>
                ${item.notes ? `<div class="vault-notes">📝 ${escapeHtml(item.notes)}</div>` : ''}
            </div>
            <div class="vault-meta">
                <div class="vault-dates">
                    <span class="created-date">Created: ${item.created_at}</span>
                    ${item.updated_at !== item.created_at ? `<span class="updated-date">Updated: ${item.updated_at}</span>` : ''}
                    ${item.last_accessed ? `<span class="accessed-date">Last accessed: ${item.last_accessed}</span>` : ''}
                </div>
                <div class="vault-security">
                    <span class="strength-indicator strength-${getStrengthClass(item.password_strength)}">
                        Strength: ${getStrengthLabel(item.password_strength)}%
                    </span>
                    ${item.breach_detected ? '<span class="breach-warning">⚠️ Breach detected</span>' : ''}
                    ${item.access_count ? `<span class="access-count">Accessed ${item.access_count} times</span>` : ''}
                </div>
            </div>
        </div>
    `).join('');
}

function getStrengthClass(strength) {
    if (strength >= 80) return 'strong';
    if (strength >= 60) return 'good';
    if (strength >= 40) return 'medium';
    return 'weak';
}

function getStrengthLabel(strength) {
    return strength || 0;
}

function filterVaultEntries(searchTerm) {
    vaultFilter = searchTerm.toLowerCase();
    updateVaultDisplay();
}

function sortVaultEntries(sortBy) {
    vaultSortBy = sortBy;
    updateVaultDisplay();
}

function filterByCategory() {
    const category = elements.categoryFilter?.value;
    if (category && category !== 'all') {
        vaultData = vaultData.filter(item => (item.category || 'General') === category);
    }
    updateVaultDisplay();
}

function filterByFavorites() {
    const showFavoritesOnly = elements.favoritesFilter?.checked;
    if (showFavoritesOnly) {
        vaultData = vaultData.filter(item => item.favorite);
    }
    updateVaultDisplay();
}

async function savePassword() {
    const title = elements.vaultTitle?.value.trim();
    const site = elements.siteName?.value.trim();
    const username = elements.vaultUsername?.value.trim();
    const password = elements.vaultPassword?.value;
    const category = elements.vaultCategory?.value || 'General';
    const notes = elements.vaultNotes?.value.trim();
    const tags = elements.vaultTags?.value.trim();
    
    if (!title || !site || !username || !password) {
        showNotification('Please fill in all required fields', 'error');
        return;
    }
    
    const masterPassword = await getMasterPassword();
    if (!masterPassword) return;
    
    try {
        const response = await fetch('/api/vault', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                title,
                site,
                username,
                password,
                category,
                notes,
                tags,
                master_password: masterPassword
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(data.message, 'success');
            
            // Clear form
            [elements.vaultTitle, elements.siteName, elements.vaultUsername, 
             elements.vaultPassword, elements.vaultNotes, elements.vaultTags].forEach(el => {
                if (el) el.value = '';
            });
            if (elements.vaultCategory) elements.vaultCategory.value = 'General';
            
            await loadVaultData();
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Save password error:', error);
        showNotification('Failed to save password', 'error');
    }
}

async function copyVaultPassword(id) {
    const masterPassword = await getMasterPassword();
    if (!masterPassword) return;
    
    try {
        const response = await fetch(`/api/vault/${id}/password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ master_password: masterPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
            await navigator.clipboard.writeText(data.password);
            showNotification('Password copied securely!', 'success');
            
            // Security: Clear clipboard after 30 seconds
            setTimeout(() => {
                navigator.clipboard.writeText('').catch(() => {});
            }, 30000);
            
            await loadVaultData(); // Refresh to update access count
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Copy password error:', error);
        showNotification('Failed to copy password', 'error');
    }
}

async function viewVaultPassword(id) {
    const masterPassword = await getMasterPassword();
    if (!masterPassword) return;
    
    try {
        const response = await fetch(`/api/vault/${id}/password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ master_password: masterPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
            const item = vaultData.find(i => i.id === id);
            showPasswordModal(item, data.password);
            await loadVaultData(); // Refresh to update access count
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('View password error:', error);
        showNotification('Failed to decrypt password', 'error');
    }
}

async function deleteVaultPassword(id) {
    const item = vaultData.find(i => i.id === id);
    if (!item) return;
    
    if (!confirm(`⚠️ Delete password for "${item.title || item.site}"?\n\nThis action cannot be undone.`)) {
        return;
    }
    
    try {
        const response = await fetch(`/api/vault/${id}`, { method: 'DELETE' });
        const data = await response.json();
        
        if (data.success) {
            showNotification(data.message, 'success');
            await loadVaultData();
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Delete password error:', error);
        showNotification('Failed to delete password', 'error');
    }
}

async function toggleFavorite(id) {
    try {
        const response = await fetch(`/api/vault/${id}/favorite`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(data.message, 'success');
            await loadVaultData();
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Toggle favorite error:', error);
        showNotification('Failed to update favorite', 'error');
    }
}

async function getMasterPassword() {
    if (masterPasswordCache) {
        return masterPasswordCache;
    }
    
    const password = prompt('🔐 Enter your master password to access vault:');
    if (!password) {
        showNotification('Master password required', 'warning');
        return null;
    }
    
    // Cache for 5 minutes
    masterPasswordCache = password;
    setTimeout(() => {
        masterPasswordCache = null;
        showNotification('Master password session expired', 'info');
    }, 5 * 60 * 1000);
    
    return password;
}

function showPasswordModal(item, password) {
    const modal = document.createElement('div');
    modal.className = 'password-modal-overlay';
    modal.innerHTML = `
        <div class="password-modal">
            <div class="modal-header">
                <h3>🔓 ${escapeHtml(item.title || item.site)}</h3>
                <button class="close-btn" onclick="this.closest('.password-modal-overlay').remove()">×</button>
            </div>
            <div class="modal-content">
                <div class="password-field">
                    <label>Site:</label>
                    <span>${escapeHtml(item.site)}</span>
                </div>
                <div class="password-field">
                    <label>Username:</label>
                    <span>${escapeHtml(item.username)}</span>
                </div>
                <div class="password-field">
                    <label>Password:</label>
                    <div class="password-reveal">
                        <span class="password-text" style="font-family: monospace;">${escapeHtml(password)}</span>
                        <button class="copy-btn" onclick="copyToClipboard('${password.replace(/'/g, "\\'")}')">📋</button>
                    </div>
                </div>
                ${item.notes ? `
                <div class="password-field">
                    <label>Notes:</label>
                    <span>${escapeHtml(item.notes)}</span>
                </div>
                ` : ''}
                <div class="password-meta">
                    <small>Created: ${item.created_at}</small>
                    <small>Category: ${item.category || 'General'}</small>
                    ${item.access_count ? `<small>Accessed: ${item.access_count} times</small>` : ''}
                </div>
            </div>
            <div class="modal-footer">
                <button onclick="this.closest('.password-modal-overlay').remove()" class="btn-secondary">Close</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Auto-close after 15 seconds for security
    setTimeout(() => {
        if (modal.parentNode) {
            modal.remove();
        }
    }, 15000);
    
    // Close on background click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showNotification('Copied to clipboard!', 'success');
    } catch (error) {
        showNotification('Failed to copy', 'error');
    }
}

// ===== PHASE 1: NOTIFICATION SYSTEM =====
async function loadUserNotifications() {
    try {
        const response = await fetch('/api/me');
        const data = await response.json();
        
        if (data.success && data.alerts) {
            updateNotificationBadge(data.alerts.length);
            if (data.alerts.length > 0) {
                showNotification(`You have ${data.alerts.length} security alert${data.alerts.length > 1 ? 's' : ''}`, 'info');
            }
        }
    } catch (error) {
        console.error('Failed to load notifications:', error);
    }
}

function updateNotificationBadge(count) {
    if (!elements.notificationBadge) return;
    
    if (count > 0) {
        elements.notificationBadge.textContent = count > 99 ? '99+' : count;
        elements.notificationBadge.style.display = 'inline';
        elements.notificationBadge.className = 'notification-badge active';
    } else {
        elements.notificationBadge.style.display = 'none';
    }
}

function toggleNotifications() {
    if (elements.notificationModal) {
        const isVisible = elements.notificationModal.style.display === 'block';
        elements.notificationModal.style.display = isVisible ? 'none' : 'block';
        
        if (!isVisible) {
            loadNotificationContent();
        }
    }
}

async function loadNotificationContent() {
    if (!elements.notificationsList) return;
    
    try {
        const response = await fetch('/api/me');
        const data = await response.json();
        
        if (data.success && data.alerts) {
            if (data.alerts.length === 0) {
                elements.notificationsList.innerHTML = `
                    <div class="no-notifications">
                        <div class="no-notifications-icon">🔔</div>
                        <p>No active alerts</p>
                        <small>Your security status is all clear!</small>
                    </div>
                `;
            } else {
                elements.notificationsList.innerHTML = data.alerts.map(alert => `
                    <div class="notification-item ${alert.severity}">
                        <div class="notification-header">
                            <span class="notification-type">${getAlertIcon(alert.type)} ${alert.type.replace('_', ' ').toUpperCase()}</span>
                            <span class="notification-time">${alert.created_at}</span>
                        </div>
                        <div class="notification-message">${escapeHtml(alert.message)}</div>
                        <button class="acknowledge-btn" onclick="acknowledgeAlert(${alert.id})">
                            Acknowledge
                        </button>
                    </div>
                `).join('');
            }
        }
    } catch (error) {
        console.error('Failed to load notifications:', error);
        elements.notificationsList.innerHTML = '<div class="error">Failed to load notifications</div>';
    }
}

function getAlertIcon(type) {
    const icons = {
        'breach': '🚨',
        'weak_password': '🔓',
        'old_password': '⏰',
        'suspicious_activity': '🔍'
    };
    return icons[type] || '⚠️';
}

async function acknowledgeAlert(alertId) {
    try {
        const response = await fetch(`/api/alerts/${alertId}/acknowledge`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Alert acknowledged', 'success');
            loadNotificationContent();
            loadUserNotifications(); // Refresh badge
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Failed to acknowledge alert:', error);
        showNotification('Failed to acknowledge alert', 'error');
    }
}

// ===== PHASE 1: SETTINGS SYSTEM =====
function toggleSettings() {
    if (elements.settingsModal) {
        const isVisible = elements.settingsModal.style.display === 'block';
        elements.settingsModal.style.display = isVisible ? 'none' : 'block';
        
        if (!isVisible) {
            loadSettingsContent();
        }
    }
}

async function loadSettingsContent() {
    try {
        const response = await fetch('/api/notifications/preferences');
        const data = await response.json();
        
        if (data.success && elements.notificationSettings) {
            const prefs = data.preferences;
            elements.notificationSettings.innerHTML = `
                <div class="settings-section">
                    <h4>🔔 Notification Preferences</h4>
                    <label class="setting-item">
                        <input type="checkbox" id="breach-alerts" ${prefs.breach_alerts ? 'checked' : ''}>
                        <span>Data breach alerts</span>
                    </label>
                    <label class="setting-item">
                        <input type="checkbox" id="password-age-warnings" ${prefs.password_age_warnings ? 'checked' : ''}>
                        <span>Password aging warnings</span>
                    </label>
                    <label class="setting-item">
                        <input type="checkbox" id="suspicious-activity" ${prefs.suspicious_activity ? 'checked' : ''}>
                        <span>Suspicious activity alerts</span>
                    </label>
                    <label class="setting-item">
                        <input type="checkbox" id="email-notifications" ${prefs.email_notifications ? 'checked' : ''}>
                        <span>Email notifications</span>
                    </label>
                    <label class="setting-item">
                        <input type="checkbox" id="sms-notifications" ${prefs.sms_notifications ? 'checked' : ''}>
                        <span>SMS notifications</span>
                    </label>
                </div>
                
                <div class="settings-section">
                    <h4>📧 Contact Information</h4>
                    <div class="setting-item">
                        <label for="settings-email">Email:</label>
                        <input type="email" id="settings-email" value="${data.email || ''}" placeholder="your@email.com">
                    </div>
                    <div class="setting-item">
                        <label for="settings-phone">Phone:</label>
                        <input type="tel" id="settings-phone" value="${data.phone || ''}" placeholder="+1234567890">
                    </div>
                </div>
                
                <div class="settings-actions">
                    <button onclick="saveSettings()" class="btn-primary">Save Settings</button>
                    <button onclick="toggleSettings()" class="btn-secondary">Cancel</button>
                </div>
            `;
        }
    } catch (error) {
        console.error('Failed to load settings:', error);
        if (elements.notificationSettings) {
            elements.notificationSettings.innerHTML = '<div class="error">Failed to load settings</div>';
        }
    }
}

async function saveSettings() {
    try {
        const preferences = {
            breach_alerts: document.getElementById('breach-alerts')?.checked || false,
            password_age_warnings: document.getElementById('password-age-warnings')?.checked || false,
            suspicious_activity: document.getElementById('suspicious-activity')?.checked || false,
            email_notifications: document.getElementById('email-notifications')?.checked || false,
            sms_notifications: document.getElementById('sms-notifications')?.checked || false,
            email: document.getElementById('settings-email')?.value.trim() || '',
            phone: document.getElementById('settings-phone')?.value.trim() || ''
        };
        
        const response = await fetch('/api/notifications/preferences', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(preferences)
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Settings saved successfully!', 'success');
            toggleSettings();
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Failed to save settings:', error);
        showNotification('Failed to save settings', 'error');
    }
}

// ===== PAGE INITIALIZATION =====
function initializeCurrentPage() {
    const path = window.location.pathname;
    
    if (path.includes('generator') || document.getElementById('generatedPassword')) {
        initializePasswordGenerator();
    }
    
    if (path === '/' || document.getElementById('passwordInput')) {
        initializePasswordAnalyzer();
    }
    
    if (currentUserSalt && elements.vaultList) {
        loadVaultData();
    }
}

function initializePasswordGenerator() {
    if (elements.lengthSlider && elements.lengthValue) {
        updateLengthDisplay(parseInt(elements.lengthSlider.value));
    }
    
    // Generate initial password
    if (elements.generateBtn && elements.generatedPassword) {
        setTimeout(() => generateNewPassword(), 500);
    }
}

function initializePasswordAnalyzer() {
    if (elements.passwordInput && elements.passwordInput.value) {
        analyzePassword(elements.passwordInput.value);
    }
}

// ===== UTILITY FUNCTIONS =====
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function handleKeyboardShortcuts(event) {
    // Ctrl+G: Generate password
    if (event.ctrlKey && event.key === 'g') {
        event.preventDefault();
        if (elements.passwordInput) {
            generateAndAnalyzePassword();
        } else if (elements.generateBtn) {
            generateNewPassword();
        }
    }
    
    // Ctrl+L: Open login modal
    if (event.ctrlKey && event.key === 'l') {
        event.preventDefault();
        if (!currentUserSalt) {
            openAuthModal();
        }
    }
    
    // Escape: Close modals
    if (event.key === 'Escape') {
        // Close any open modals
        const modals = document.querySelectorAll('.modal-overlay, .password-modal-overlay');
        modals.forEach(modal => modal.remove());
        
        if (elements.authModal) {
            closeAuthModal();
        }
        
        if (elements.notificationModal) {
            elements.notificationModal.style.display = 'none';
        }
        
        if (elements.settingsModal) {
            elements.settingsModal.style.display = 'none';
        }
    }
}

function handleVisibilityChange() {
    if (document.hidden) {
        // Clear sensitive data when tab is hidden
        setTimeout(() => {
            if (masterPasswordCache) {
                masterPasswordCache = null;
                console.log('Master password cleared for security');
            }
        }, 30000); // 30 seconds
    }
}

// ===== NOTIFICATION SYSTEM =====
function showNotification(message, type = 'info') {
    // Remove existing notifications of same type
    const existing = document.querySelectorAll(`.notification-toast.${type}`);
    existing.forEach(n => n.remove());
    
    const notification = document.createElement('div');
    notification.className = `notification-toast ${type}`;
    
    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };
    
    const colors = {
        success: '#2ed573',
        error: '#ff4757',
        warning: '#ffa502',
        info: '#3742fa'
    };
    
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${colors[type]};
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        z-index: 10000;
        font-weight: 600;
        font-size: 14px;
        max-width: 350px;
        animation: slideInRight 0.3s ease;
        cursor: pointer;
    `;
    
    notification.innerHTML = `${icons[type]} ${message}`;
    
    // Click to dismiss
    notification.addEventListener('click', () => {
        notification.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    });
    
    document.body.appendChild(notification);
    
    // Auto-dismiss
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideOutRight 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }
    }, 4000);
}

// Add required CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOutRight {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// ===== GLOBAL ERROR HANDLING =====
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    showNotification('An unexpected error occurred', 'error');
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    showNotification('Network error occurred', 'error');
    event.preventDefault();
});

// ===== SECURITY CLEANUP =====
window.addEventListener('beforeunload', () => {
    masterPasswordCache = null;
    
    // Clear any displayed passwords
    const passwordFields = document.querySelectorAll('.password-text');
    passwordFields.forEach(field => {
        field.textContent = '••••••••••';
    });
    
    // Clear clipboard
    if (navigator.clipboard) {
        navigator.clipboard.writeText('').catch(() => {});
    }
});

// ===== EXPOSE GLOBAL FUNCTIONS =====
// Functions that need to be called from HTML onclick attributes
window.copyVaultPassword = copyVaultPassword;
window.viewVaultPassword = viewVaultPassword;
window.deleteVaultPassword = deleteVaultPassword;
window.toggleFavorite = toggleFavorite;
window.acknowledgeAlert = acknowledgeAlert;
window.copyToClipboard = copyToClipboard;
window.saveSettings = saveSettings;

// ===== MAIN INITIALIZATION =====
// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}

// Performance monitoring
setTimeout(() => {
    console.log('VaultGuard Performance Metrics:', performanceMetrics);
}, 5000);
