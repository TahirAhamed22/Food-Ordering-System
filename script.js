// ===== GLOBAL VARIABLES =====
let analysisEnabled = true;
let currentUserSalt = null;
let masterPasswordCache = null;
let securityMode = true;
let themePreference = 'dark';
let isLoginMode = true;
let vaultData = [];
let vaultFilter = '';
let vaultSortBy = 'updated_at';

let passwordGeneratorSettings = {
    length: 16,
    includeUpper: true,
    includeLower: true,
    includeNumbers: true,
    includeSymbols: true
};

let performanceMetrics = {
    pageLoadTime: 0,
    analysisCount: 0,
    apiCallCount: 0
};

// DOM Elements Storage - Consolidated
let elements = {};

// ===== INITIALIZATION FUNCTIONS =====
function initializeElements() {
    const elementIds = [
        // Main interface elements
        'themeToggle', 'passwordInput', 'strengthSection', 'analysisResults', 
        'policySection', 'strengthFill', 'strengthText', 'crackTime', 'breachStatus',
        
        // Policy icons
        'lengthIcon', 'lowerIcon', 'upperIcon', 'digitIcon', 'symbolIcon',
        
        // Input controls
        'toggleVisibility', 'copyPassword', 'clearPassword', 'generatePassword', 'pauseBtn',
        
        // Generator controls
        'lengthSlider', 'lengthValue', 'generateBtn', 'generatedPassword',
        'copyGenerated', 'useGenerated', 'includeUpper', 'includeLower',
        'includeNumbers', 'includeSymbols',
        
        // Authentication elements
        'authModal', 'authForm', 'authTitle', 'authSubmit', 'authSwitchText',
        'authSwitchLink', 'authUsername', 'authPassword', 'loginBtn',
        'loginPromptBtn', 'closeModal',
        
        // Vault elements
        'vaultList', 'savePasswordBtn', 'siteName', 'vaultUsername', 'vaultPassword',
        'vaultSearch', 'vaultSort',
        
        // Notification elements
        'notificationsBtn', 'notificationModal', 'notificationsList', 'closeNotifications',
        
        // Settings elements
        'settingsBtn', 'settingsModal', 'breachAlertsToggle', 'passwordAgeWarningsToggle',
        'suspiciousActivityToggle', 'notificationEmail', 'notificationPhone',
        'saveSettingsBtn', 'closeSettings'
    ];
    
    elements = {};
    elementIds.forEach(id => {
        elements[id] = document.getElementById(id);
    });
}

async function initialize() {
    try {
        const pageLoadStart = performance.now();
        
        initializeElements();
        checkSecureContext();
        initializeTheme();
        addEnhancedStyles();
        initializeEventListeners();
        
        await checkAuthenticationStatus();
        
        if (currentUserSalt) {
            await Promise.all([
                loadVaultData(),
                loadUserNotifications(),
                loadUserSettings()
            ]);
        }
        
        initializePasswordGenerator();
        showSecurityStatus();
        
        const pageLoadTime = performance.now() - pageLoadStart;
        recordPerformanceMetric('pageLoadTime', pageLoadTime);
        
        console.log(`VaultGuard initialized in ${pageLoadTime.toFixed(2)}ms`);
        
    } catch (error) {
        console.error('Initialization error:', error);
        showNotification('Application failed to initialize properly', 'error');
    }
}

// ===== THEME MANAGEMENT =====
function initializeTheme() {
    document.body.setAttribute('data-theme', themePreference);
    
    if (elements.themeToggle) {
        updateThemeToggleIcon();
        elements.themeToggle.addEventListener('click', toggleTheme);
    }
}

function toggleTheme() {
    themePreference = themePreference === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', themePreference);
    updateThemeToggleIcon();
    
    document.body.style.transition = 'all 0.3s ease';
    setTimeout(() => { document.body.style.transition = ''; }, 300);
    
    showNotification(`Switched to ${themePreference} theme`, 'info');
}

function updateThemeToggleIcon() {
    if (elements.themeToggle) {
        elements.themeToggle.textContent = themePreference === 'dark' ? '🌙' : '☀️';
        animateElement(elements.themeToggle, 'scale(1.2)', 200);
    }
}

// ===== EVENT LISTENERS SETUP =====
function initializeEventListeners() {
    const eventMappings = [
        // Password input analyzer
        { element: 'passwordInput', event: 'input', handler: debounce(e => analyzePassword(e.target.value), 300) },
        { element: 'passwordInput', event: 'focus', handler: e => e.target.value && analyzePassword(e.target.value) },
        { element: 'passwordInput', event: 'paste', handler: () => setTimeout(() => analyzePassword(elements.passwordInput.value), 10) },
        
        // Password controls
        { element: 'toggleVisibility', event: 'click', handler: togglePasswordVisibility },
        { element: 'copyPassword', event: 'click', handler: copyPasswordToClipboard },
        { element: 'clearPassword', event: 'click', handler: clearPasswordInput },
        { element: 'generatePassword', event: 'click', handler: generateAndAnalyzePassword },
        { element: 'pauseBtn', event: 'click', handler: toggleAnalysis },
        
        // Generator controls
        { element: 'lengthSlider', event: 'input', handler: e => updateLengthDisplay(parseInt(e.target.value)) },
        { element: 'generateBtn', event: 'click', handler: generateNewPassword },
        { element: 'copyGenerated', event: 'click', handler: copyGeneratedPassword },
        { element: 'useGenerated', event: 'click', handler: useGeneratedPassword },
        
        // Authentication
        { element: 'loginBtn', event: 'click', handler: e => { e.preventDefault(); openAuthModal(); } },
        { element: 'loginPromptBtn', event: 'click', handler: openAuthModal },
        { element: 'closeModal', event: 'click', handler: closeAuthModal },
        { element: 'authSwitchLink', event: 'click', handler: e => { e.preventDefault(); setAuthMode(!isLoginMode); } },
        { element: 'authForm', event: 'submit', handler: handleAuth },
        
        // Vault management
        { element: 'savePasswordBtn', event: 'click', handler: savePassword },
        { element: 'vaultSearch', event: 'input', handler: debounce(e => filterVaultEntries(e.target.value), 300) },
        { element: 'vaultSort', event: 'change', handler: e => sortVaultEntries(e.target.value) },
        
        // Notifications
        { element: 'notificationsBtn', event: 'click', handler: openNotificationModal },
        { element: 'closeNotifications', event: 'click', handler: closeNotificationModal },
        
        // Settings
        { element: 'settingsBtn', event: 'click', handler: openSettingsModal },
        { element: 'closeSettings', event: 'click', handler: closeSettingsModal },
        { element: 'saveSettingsBtn', event: 'click', handler: saveNotificationSettings }
    ];
    
    eventMappings.forEach(({ element, event, handler }) => {
        if (elements[element]) {
            elements[element].addEventListener(event, handler);
        }
    });
    
    // Generator checkboxes
    ['includeUpper', 'includeLower', 'includeNumbers', 'includeSymbols'].forEach(checkbox => {
        if (elements[checkbox]) {
            elements[checkbox].addEventListener('change', () => {
                updatePasswordGeneratorSettings();
                validateGeneratorSettings();
            });
        }
    });
    
    // Modal click-outside handlers
    const modalMappings = [
        { modal: 'authModal', closeHandler: closeAuthModal },
        { modal: 'notificationModal', closeHandler: closeNotificationModal },
        { modal: 'settingsModal', closeHandler: closeSettingsModal }
    ];
    
    modalMappings.forEach(({ modal, closeHandler }) => {
        if (elements[modal]) {
            elements[modal].addEventListener('click', e => {
                if (e.target === elements[modal]) closeHandler();
            });
        }
    });
    
    // Security monitoring
    document.addEventListener('visibilitychange', handleVisibilityChange);
    document.addEventListener('keydown', handleKeyboardShortcuts);
}

// ===== PASSWORD ANALYSIS FUNCTIONS =====
function analyzePassword(password) {
    if (!password || !analysisEnabled) {
        hideAnalysisSection();
        resetPasswordPolicyIcons();
        resetStrengthMeter();
        return;
    }

    showAnalysisSection();
    
    const analysis = performPasswordAnalysis(password);
    
    updateStrengthMeter(analysis.score, analysis.strengthClass, analysis.strength);
    updateCrackTimeEstimate(analysis.score);
    updatePasswordPolicyIcons(
        analysis.hasLength, analysis.hasLower, analysis.hasUpper, 
        analysis.hasDigit, analysis.hasSymbol
    );
    
    checkPasswordStrength(password);
    displayPasswordRecommendations(analysis.recommendations);
}

function performPasswordAnalysis(password) {
    // Character type checks
    const hasLength = password.length >= 12;
    const hasMinLength = password.length >= 8;
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);
    const hasLongLength = password.length >= 16;
    const hasExtraLength = password.length >= 20;
    const hasFortressLength = password.length >= 32;

    // Base scoring
    let score = 0;
    if (hasMinLength) score += 10;
    if (hasLength) score += 15;
    if (hasLower) score += 10;
    if (hasUpper) score += 10;
    if (hasDigit) score += 10;
    if (hasSymbol) score += 20;
    if (hasLongLength) score += 15;
    if (hasExtraLength) score += 15;
    if (hasFortressLength) score += 20;

    // Advanced pattern analysis
    const advancedAnalysis = performAdvancedPasswordAnalysis(password);
    score += advancedAnalysis.bonusPoints;
    score -= advancedAnalysis.penaltyPoints;
    
    score = Math.max(0, Math.min(100, score));
    
    // Determine strength level
    const strengthLevels = [
        { min: 95, label: 'Fortress Grade', class: 'fortress' },
        { min: 85, label: 'Military Grade', class: 'military' },
        { min: 70, label: 'Strong', class: 'strong' },
        { min: 55, label: 'Good', class: 'good' },
        { min: 40, label: 'Fair', class: 'fair' },
        { min: 25, label: 'Weak', class: 'weak' },
        { min: 0, label: 'Critical Vulnerability', class: 'critical' }
    ];
    
    const strengthInfo = strengthLevels.find(level => score >= level.min);
    
    return {
        score,
        strength: strengthInfo.label,
        strengthClass: strengthInfo.class,
        recommendations: advancedAnalysis.recommendations,
        hasLength, hasLower, hasUpper, hasDigit, hasSymbol
    };
}

function performAdvancedPasswordAnalysis(password) {
    let bonusPoints = 0;
    let penaltyPoints = 0;
    let recommendations = [];
    
    const lowerPassword = password.toLowerCase();
    
    // Common patterns that reduce security
    const securityChecks = [
        {
            patterns: ['123', 'abc', 'qwe', 'pass', 'admin', 'user', 'login', 'welcome'],
            penalty: 25,
            message: 'Avoid common words like "password", "admin", "123"'
        },
        {
            patterns: ['qwert', 'asdf', 'zxcv', 'yuiop', 'hjkl', 'bnm'],
            penalty: 30,
            message: 'Avoid keyboard patterns like "qwerty" or "asdf"'
        },
        {
            patterns: ['1234', '4321', 'abcd', 'dcba'],
            penalty: 20,
            message: 'Avoid sequential characters like "1234" or "abcd"'
        }
    ];
    
    securityChecks.forEach(check => {
        if (check.patterns.some(pattern => lowerPassword.includes(pattern))) {
            penaltyPoints += check.penalty;
            recommendations.push(check.message);
        }
    });
    
    // Additional checks
    if (/(.)\1{2,}/.test(password)) {
        penaltyPoints += 20;
        recommendations.push('Avoid repeating the same character multiple times');
    }
    
    // Character diversity bonus
    const uniqueChars = new Set(password).size;
    const charsetDiversity = uniqueChars / password.length;
    
    if (charsetDiversity >= 0.8) bonusPoints += 15;
    else if (charsetDiversity >= 0.7) bonusPoints += 10;
    else if (charsetDiversity < 0.5) {
        penaltyPoints += 10;
        recommendations.push('Use more diverse characters');
    }
    
    // Date pattern detection
    const currentYear = new Date().getFullYear();
    const yearPattern = new RegExp(`(${currentYear}|${currentYear-1}|${currentYear-2}|19\\d\\d|20\\d\\d)`);
    if (yearPattern.test(password)) {
        penaltyPoints += 15;
        recommendations.push('Avoid using years or dates in passwords');
    }
    
    // Length bonuses
    if (password.length >= 24) bonusPoints += 10;
    if (password.length >= 28) bonusPoints += 10;
    if (password.length >= 40) bonusPoints += 15;
    
    return {
        bonusPoints,
        penaltyPoints,
        recommendations: recommendations.slice(0, 3)
    };
}

// ===== UI UPDATE FUNCTIONS - Consolidated =====
function updateStrengthMeter(score, strengthClass, strength) {
    if (elements.strengthFill) {
        elements.strengthFill.style.width = score + '%';
        
        const strengthClasses = ['critical', 'weak', 'fair', 'good', 'strong', 'military', 'fortress'];
        elements.strengthFill.classList.remove(...strengthClasses);
        elements.strengthFill.classList.add(strengthClass);
        
        elements.strengthFill.style.animation = score >= 85 ? 'strengthPulse 2s ease-in-out infinite' : '';
    }
    
    if (elements.strengthText) {
        elements.strengthText.textContent = strength;
        elements.strengthText.className = `strength-text ${strengthClass}`;
        elements.strengthText.style.animation = 'fadeIn 0.3s ease-out';
    }
}

function updateCrackTimeEstimate(score) {
    const crackTimes = [
        'instantly', 'milliseconds', 'seconds', 'minutes', 
        'hours', 'days', 'weeks', 'months', 'years', 
        'decades', 'centuries', 'millennia', 'geological ages'
    ];
    
    if (elements.crackTime) {
        const timeIndex = Math.min(Math.floor(score / 8), crackTimes.length - 1);
        elements.crackTime.textContent = crackTimes[timeIndex];
        elements.crackTime.style.animation = 'fadeIn 0.4s ease-out';
    }
}

function updatePasswordPolicyIcons(hasLength, hasLower, hasUpper, hasDigit, hasSymbol) {
    const iconMappings = [
        { element: elements.lengthIcon, isValid: hasLength },
        { element: elements.lowerIcon, isValid: hasLower },
        { element: elements.upperIcon, isValid: hasUpper },
        { element: elements.digitIcon, isValid: hasDigit },
        { element: elements.symbolIcon, isValid: hasSymbol }
    ];
    
    iconMappings.forEach(({ element, isValid }) => updatePolicyIcon(element, isValid));
}

function updatePolicyIcon(icon, isValid) {
    if (!icon) return;
    
    icon.style.transition = 'all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275)';
    
    if (isValid) {
        Object.assign(icon, {
            className: 'policy-icon valid',
            textContent: '✓'
        });
        Object.assign(icon.style, {
            color: '#2ed573',
            backgroundColor: 'rgba(46, 213, 115, 0.15)',
            border: '2px solid rgba(46, 213, 115, 0.3)',
            transform: 'scale(1.1)'
        });
        
        setTimeout(() => { icon.style.transform = 'scale(1)'; }, 200);
    } else {
        Object.assign(icon, {
            className: 'policy-icon invalid',
            textContent: '✗'
        });
        Object.assign(icon.style, {
            color: '#ff4757',
            backgroundColor: 'rgba(255, 71, 87, 0.15)',
            border: '2px solid rgba(255, 71, 87, 0.3)'
        });
    }
}

function resetPasswordPolicyIcons() {
    [elements.lengthIcon, elements.lowerIcon, elements.upperIcon, elements.digitIcon, elements.symbolIcon]
        .forEach(icon => {
            if (icon) {
                Object.assign(icon, {
                    className: 'policy-icon',
                    textContent: '◯'
                });
                Object.assign(icon.style, {
                    color: '#6c757d',
                    backgroundColor: 'rgba(108, 117, 125, 0.1)'
                });
            }
        });
}

function resetStrengthMeter() {
    if (elements.strengthFill) {
        Object.assign(elements.strengthFill.style, {
            width: '0%',
            animation: '',
            boxShadow: ''
        });
        elements.strengthFill.className = 'strength-fill';
    }
    
    if (elements.strengthText) {
        elements.strengthText.textContent = '-';
        elements.strengthText.className = 'strength-text';
    }
    
    if (elements.crackTime) elements.crackTime.textContent = '-';
    if (elements.breachStatus) elements.breachStatus.innerHTML = '-';
}

// ===== SECTION VISIBILITY FUNCTIONS =====
function showAnalysisSection() {
    [elements.strengthSection, elements.analysisResults, elements.policySection].forEach(section => {
        if (section) {
            section.style.display = section === elements.analysisResults ? 'grid' : 'block';
            section.style.animation = 'fadeIn 0.3s ease-out';
        }
    });
}

function hideAnalysisSection() {
    [elements.strengthSection, elements.analysisResults, elements.policySection].forEach(section => {
        if (section) {
            section.style.display = 'none';
            section.style.animation = '';
        }
    });
    
    const recommendationsElement = document.getElementById('passwordRecommendations');
    if (recommendationsElement) {
        recommendationsElement.style.display = 'none';
    }
}

function displayPasswordRecommendations(recommendations) {
    const recommendationsElement = document.getElementById('passwordRecommendations');
    if (recommendationsElement && recommendations.length > 0) {
        recommendationsElement.innerHTML = `
            <div class="recommendations-header">💡 Security Recommendations:</div>
            <ul class="recommendations-list">
                ${recommendations.map(rec => `<li>${rec}</li>`).join('')}
            </ul>
        `;
        recommendationsElement.style.display = 'block';
        recommendationsElement.style.animation = 'fadeIn 0.5s ease-out';
    } else if (recommendationsElement) {
        recommendationsElement.style.display = 'none';
    }
}

// ===== PASSWORD CONTROL FUNCTIONS =====
function togglePasswordVisibility() {
    if (!elements.passwordInput || !elements.toggleVisibility) return;
    
    const type = elements.passwordInput.type === 'password' ? 'text' : 'password';
    elements.passwordInput.type = type;
    elements.toggleVisibility.textContent = type === 'password' ? '👁️' : '🙈';
    animateElement(elements.toggleVisibility, 'scale(1.1)', 150);
}

async function copyPasswordToClipboard() {
    if (!elements.passwordInput?.value) {
        showNotification('No password to copy', 'warning');
        return;
    }
    
    try {
        await navigator.clipboard.writeText(elements.passwordInput.value);
        showNotification('Password copied securely!', 'success');
        
        setTimeout(() => {
            navigator.clipboard.writeText('').catch(() => {});
        }, 30000);
    } catch (err) {
        console.error('Clipboard error:', err);
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
    const generatedPwd = generateRandomPassword();
    if (elements.passwordInput) {
        elements.passwordInput.value = generatedPwd;
        analyzePassword(generatedPwd);
        showNotification('Secure password generated and analyzed!', 'success');
    }
}

function toggleAnalysis() {
    analysisEnabled = !analysisEnabled;
    
    if (elements.pauseBtn) {
        elements.pauseBtn.textContent = analysisEnabled ? '⏸️' : '▶️';
        elements.pauseBtn.title = analysisEnabled ? 'Pause analysis' : 'Resume analysis';
        animateElement(elements.pauseBtn, 'scale(1.1)', 150);
    }
    
    if (!analysisEnabled) {
        hideAnalysisSection();
        showNotification('Password analysis paused', 'info');
    } else {
        analyzePassword(elements.passwordInput?.value || '');
        showNotification('Password analysis resumed', 'info');
    }
}

// ===== PASSWORD GENERATOR FUNCTIONS =====
function updateLengthDisplay(length) {
    if (!elements.lengthValue) return;
    
    passwordGeneratorSettings.length = length;
    
    const lengthSettings = [
        { min: 32, color: '#2ed573', label: '(Fortress)' },
        { min: 20, color: '#58a6ff', label: '(Military)' },
        { min: 16, color: '#ffa502', label: '(Strong)' },
        { min: 12, color: '#ff6348', label: '(Good)' },
        { min: 0, color: '#ff4757', label: '(Weak)' }
    ];
    
    const setting = lengthSettings.find(s => length >= s.min);
    elements.lengthValue.style.color = setting.color;
    elements.lengthValue.textContent = `${length} ${setting.label}`;
}

function generateNewPassword() {
    if (!elements.generateBtn) return;
    
    updateButtonState(elements.generateBtn, true, 'Generating Secure Password...');
    
    setTimeout(() => {
        const password = generateRandomPassword();
        if (elements.generatedPassword) {
            elements.generatedPassword.value = password;
            elements.generatedPassword.style.animation = 'fadeIn 0.3s ease-out';
        }
        
        updateButtonState(elements.generateBtn, false, '🎲 Generate Secure Password');
        showNotification('Cryptographically secure password generated!', 'success');
    }, 500);
}

async function copyGeneratedPassword() {
    if (!elements.generatedPassword?.value) {
        showNotification('No generated password to copy', 'warning');
        return;
    }
    
    try {
        await navigator.clipboard.writeText(elements.generatedPassword.value);
        showNotification('Generated password copied securely!', 'success');
        
        setTimeout(() => {
            navigator.clipboard.writeText('').catch(() => {});
        }, 30000);
    } catch (err) {
        console.error('Clipboard error:', err);
        showNotification('Failed to copy password', 'error');
    }
}

function useGeneratedPassword() {
    if (!elements.generatedPassword?.value || !elements.passwordInput) {
        showNotification('No generated password to use', 'warning');
        return;
    }
    
    elements.passwordInput.value = elements.generatedPassword.value;
    analyzePassword(elements.generatedPassword.value);
    showNotification('Password moved to analyzer!', 'success');
    
    const analyzerSection = document.getElementById('analyzer-section');
    if (analyzerSection) {
        analyzerSection.scrollIntoView({ behavior: 'smooth' });
    }
}

function updatePasswordGeneratorSettings() {
    const settings = {
        length: elements.lengthSlider ? parseInt(elements.lengthSlider.value) : passwordGeneratorSettings.length,
        includeUpper: elements.includeUpper?.checked ?? passwordGeneratorSettings.includeUpper,
        includeLower: elements.includeLower?.checked ?? passwordGeneratorSettings.includeLower,
        includeNumbers: elements.includeNumbers?.checked ?? passwordGeneratorSettings.includeNumbers,
        includeSymbols: elements.includeSymbols?.checked ?? passwordGeneratorSettings.includeSymbols
    };
    
    Object.assign(passwordGeneratorSettings, settings);
}

function validateGeneratorSettings() {
    const hasAnySelected = [
        elements.includeUpper?.checked,
        elements.includeLower?.checked,
        elements.includeNumbers?.checked,
        elements.includeSymbols?.checked
    ].some(Boolean);
    
    if (!hasAnySelected) {
        showNotification('At least one character type must be selected', 'warning');
        if (elements.includeLower) {
            elements.includeLower.checked = true;
            passwordGeneratorSettings.includeLower = true;
        }
    }
}

function generateRandomPassword(customLength = null) {
    updatePasswordGeneratorSettings();
    
    const length = customLength || passwordGeneratorSettings.length;
    let charset = '';
    
    const charSets = [
        { condition: passwordGeneratorSettings.includeUpper, chars: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' },
        { condition: passwordGeneratorSettings.includeLower, chars: 'abcdefghijklmnopqrstuvwxyz' },
        { condition: passwordGeneratorSettings.includeNumbers, chars: '0123456789' },
        { condition: passwordGeneratorSettings.includeSymbols, chars: '!@#$%^&*()_+-=[]{}|;:,.<>?~`' }
    ];
    
    charSets.forEach(({ condition, chars }) => {
        if (condition) charset += chars;
    });
    
    if (!charset) {
        charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        showNotification('No character types selected, using all types', 'warning');
    }
    
    let password = '';
    
    // Ensure at least one character from each selected type
    const requiredChars = charSets.filter(s => s.condition).map(s => s.chars);
    requiredChars.forEach(charSet => {
        const randomIndex = Math.floor(Math.random() * charSet.length);
        password += charSet[randomIndex];
    });
    
    // Fill remaining length
    const remainingLength = Math.max(0, length - requiredChars.length);
    const array = new Uint8Array(remainingLength);
    crypto.getRandomValues(array);
    
    for (let i = 0; i < remainingLength; i++) {
        password += charset.charAt(array[i] % charset.length);
    }
    
    return shuffleString(password);
}

function shuffleString(str) {
    const array = str.split('');
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array.join('');
}

// ===== AUTHENTICATION FUNCTIONS =====
function openAuthModal() {
    if (elements.authModal) {
        elements.authModal.classList.add('show');
        elements.authModal.style.animation = 'modalFadeIn 0.3s ease-out';
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
        elements.authModal.style.animation = 'modalFadeOut 0.3s ease-out';
        setTimeout(() => {
            elements.authModal.classList.remove('show');
        }, 300);
        
         if (elements.authForm) {
            elements.authForm.reset();
        }
        
        clearAuthErrors();
    }
}

function setAuthMode(loginMode) {
    isLoginMode = loginMode;
    
    if (elements.authTitle && elements.authSubmit && elements.authSwitchText && elements.authSwitchLink) {
        const modeConfig = isLoginMode ? {
            title: '🔐 VaultGuard Secure Access',
            submit: 'Secure Login',
            switchText: "Don't have an account?",
            switchLink: 'Create Account'
        } : {
            title: '🛡️ Create Secure Account',
            submit: 'Create Account',
            switchText: 'Already have an account?',
            switchLink: 'Login'
        };
        
        elements.authTitle.textContent = modeConfig.title;
        elements.authSubmit.textContent = modeConfig.submit;
        elements.authSwitchText.textContent = modeConfig.switchText;
        elements.authSwitchLink.textContent = modeConfig.switchLink;
    }
    
    clearAuthErrors();
}

function clearAuthErrors() {
    document.querySelectorAll('.auth-error').forEach(el => el.remove());
    
    [elements.authUsername, elements.authPassword].forEach(input => {
        if (input) {
            input.style.borderColor = '';
            input.classList.remove('error');
        }
    });
}

function showAuthError(message, targetElement = null) {
    clearAuthErrors();
    
    const errorDiv = document.createElement('div');
    errorDiv.className = 'auth-error';
    errorDiv.style.cssText = `
        color: #ff4757;
        background: rgba(255, 71, 87, 0.1);
        border: 1px solid rgba(255, 71, 87, 0.3);
        padding: 0.75rem;
        border-radius: 6px;
        margin-top: 0.5rem;
        font-size: 0.9rem;
        animation: fadeIn 0.3s ease-out;
    `;
    errorDiv.textContent = message;
    
    if (targetElement && targetElement.parentNode) {
        targetElement.parentNode.appendChild(errorDiv);
        targetElement.style.borderColor = '#ff4757';
        targetElement.classList.add('error');
    } else if (elements.authForm) {
        elements.authForm.appendChild(errorDiv);
    }
}

async function handleAuth(event) {
    event.preventDefault();
    
    const username = elements.authUsername?.value.trim();
    const password = elements.authPassword?.value;
    
    if (!username || !password) {
        showAuthError('Please fill in all fields');
        return;
    }
    
    if (!isLoginMode) {
        const validation = validateRegistration(username, password);
        if (!validation.isValid) {
            showAuthError(validation.message, validation.field);
            return;
        }
    }
    
    const endpoint = isLoginMode ? '/api/login' : '/api/register';
    
    try {
        updateButtonState(elements.authSubmit, true, 
            isLoginMode ? 'Authenticating...' : 'Creating Account...');
        
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ username, password })
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
            showAuthError(data.message);
        }
    } catch (error) {
        console.error('Auth error:', error);
        showAuthError('Network error. Please check your connection and try again.');
    } finally {
        updateButtonState(elements.authSubmit, false, 
            isLoginMode ? 'Secure Login' : 'Create Account');
    }
}

function validateRegistration(username, password) {
    if (username.length < 3) {
        return { isValid: false, message: 'Username must be at least 3 characters long', field: elements.authUsername };
    }
    
    if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
        return { isValid: false, message: 'Username can only contain letters, numbers, dots, hyphens, and underscores', field: elements.authUsername };
    }
    
    if (password.length < 12) {
        return { isValid: false, message: 'Password must be at least 12 characters long for security', field: elements.authPassword };
    }
    
    const passwordValidation = validatePasswordComplexity(password);
    if (!passwordValidation.isValid) {
        return { isValid: false, message: passwordValidation.message, field: elements.authPassword };
    }
    
    return { isValid: true };
}

function validatePasswordComplexity(password) {
    const requirements = [];
    
    const checks = [
        { test: /[a-z]/.test(password), req: 'lowercase letter' },
        { test: /[A-Z]/.test(password), req: 'uppercase letter' },
        { test: /[0-9]/.test(password), req: 'number' },
        { test: /[!@#$%^&*()_+-=\[\]{}|;:,.<>?]/.test(password), req: 'special character' }
    ];
    
    checks.forEach(({ test, req }) => {
        if (!test) requirements.push(req);
    });
    
    return requirements.length > 0 ? {
        isValid: false,
        message: `Password must contain: ${requirements.join(', ')}`
    } : { isValid: true, message: '' };
}

// ===== VAULT MANAGEMENT FUNCTIONS =====
async function checkAuthenticationStatus() {
    try {
        const response = await fetch('/api/me', {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        const data = await response.json();
        
        if (data.success && data.authenticated) {
            currentUserSalt = data.salt;
            updateUIForAuthenticatedUser(data);
        } else {
            updateUIForUnauthenticatedUser();
        }
    } catch (error) {
        console.error('Failed to check auth status:', error);
        updateUIForUnauthenticatedUser();
    }
}

function updateUIForAuthenticatedUser(userData) {
    document.querySelectorAll('.current-username').forEach(el => {
        el.textContent = userData.username;
    });
    
    document.querySelectorAll('.vault-count').forEach(el => {
        el.textContent = userData.vault_count || 0;
    });
    
    if (userData.alerts && userData.alerts.length > 0) {
        updateNotificationBadge(userData.alerts.length);
    }
}

function updateUIForUnauthenticatedUser() {
    currentUserSalt = null;
    masterPasswordCache = null;
}

async function loadVaultData() {
    try {
        showLoadingState('vault');
        
        const response = await fetch('/api/vault', {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                vaultData = data.vault_entries;
                updateVaultDisplay();
                showNotification(`Loaded ${vaultData.length} encrypted passwords`, 'info');
            }
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (error) {
        console.error('Failed to load vault data:', error);
        showNotification('Failed to load vault data', 'error');
    } finally {
        hideLoadingState('vault');
    }
}

async function savePassword() {
    const site = elements.siteName?.value.trim();
    const username = elements.vaultUsername?.value.trim();
    const password = elements.vaultPassword?.value;
    
    if (!site || !username || !password) {
        showNotification('Please fill in all fields', 'error');
        highlightEmptyFields([elements.siteName, elements.vaultUsername, elements.vaultPassword]);
        return;
    }
    
    if (site.length > 120 || username.length > 120) {
        showNotification('Site name and username must be less than 120 characters', 'error');
        return;
    }
    
    const masterPassword = await getMasterPassword();
    if (!masterPassword) return;
    
    try {
        updateButtonState(elements.savePasswordBtn, true, 'Encrypting & Saving...');
        
        const response = await fetch('/api/vault', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({
                site: site,
                username: username,
                password: password,
                master_password: masterPassword
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            elements.siteName.value = '';
            elements.vaultUsername.value = '';
            elements.vaultPassword.value = '';
            
            await loadVaultData();
            showNotification(data.message, 'success');
            elements.siteName.focus();
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Failed to save password:', error);
        showNotification('Failed to save password. Please try again.', 'error');
    } finally {
        updateButtonState(elements.savePasswordBtn, false, '💾 Save to Vault');
    }
}

async function getMasterPassword() {
    if (masterPasswordCache) {
        return masterPasswordCache;
    }
    
    const password = prompt('🔐 Enter your master password to access secure vault:');
    if (!password) {
        showNotification('Master password required for vault access', 'warning');
        return null;
    }
    
    masterPasswordCache = password;
    setTimeout(() => { 
        masterPasswordCache = null;
        showNotification('Master password session expired for security', 'info');
    }, 5 * 60 * 1000);
    
    return password;
}

// ===== ENHANCED VAULT DISPLAY FUNCTIONS =====
function filterVaultEntries(searchTerm) {
    vaultFilter = searchTerm.toLowerCase();
    updateVaultDisplay();
}

function sortVaultEntries(sortBy) {
    vaultSortBy = sortBy;
    updateVaultDisplay();
}

function updateVaultDisplay() {
    if (!elements.vaultList) return;
    
    let filteredData = vaultData;
    
    if (vaultFilter) {
        filteredData = vaultData.filter(item => 
            item.site.toLowerCase().includes(vaultFilter) ||
            item.username.toLowerCase().includes(vaultFilter)
        );
    }
    
    filteredData.sort((a, b) => {
        switch (vaultSortBy) {
            case 'site':
                return a.site.localeCompare(b.site);
            case 'username':
                return a.username.localeCompare(b.username);
            case 'created_at':
                return new Date(b.created_at) - new Date(a.created_at);
            case 'updated_at':
            default:
                return new Date(b.updated_at) - new Date(a.updated_at);
        }
    });
    
    if (filteredData.length === 0) {
        displayEmptyVault();
        return;
    }
    
    displayVaultStats(filteredData.length);
    
    elements.vaultList.innerHTML = filteredData.map((item, index) => `
        <li class="vault-item" style="animation: fadeInUp 0.4s ease-out ${index * 0.05}s backwards;">
            <div class="vault-info">
                <div class="site-header">
                    <h4 class="site-name">${escapeHtml(item.site)}</h4>
                    <div class="vault-meta">
                        <span class="created-date">Added: ${item.created_at}</span>
                        ${item.updated_at !== item.created_at ? '<span class="updated-badge">Updated</span>' : ''}
                        ${item.is_breached ? '<span class="breach-badge">⚠️ Breached</span>' : ''}
                    </div>
                </div>
                <p class="username-display">👤 ${escapeHtml(item.username)}</p>
                <div class="password-preview">🔒 Password: ••••••••••• (AES-256 Encrypted)</div>
                <div class="security-metrics">
                    <span class="strength-badge strength-${getStrengthClass(item.password_strength_score)}">
                        Strength: ${getStrengthLabel(item.password_strength_score)}
                    </span>
                    ${item.access_count ? `<span class="access-count">Accessed: ${item.access_count} times</span>` : ''}
                </div>
                ${item.updated_at !== item.created_at ? `<div class="updated-date">Last updated: ${item.updated_at}</div>` : ''}
            </div>
            <div class="vault-actions">
                <button id="copy-btn-${item.id}" class="vault-btn copy-btn" onclick="copyVaultPassword(${item.id})" title="Secure copy">
                    📋 <span>Copy</span>
                </button>
                <button id="view-btn-${item.id}" class="vault-btn view-btn" onclick="viewVaultPassword(${item.id})" title="Decrypt & view">
                    👁️ <span>View</span>
                </button>
                <button id="delete-btn-${item.id}" class="vault-btn delete-btn" onclick="deleteVaultPassword(${item.id})" title="Secure delete">
                    🗑️ <span>Delete</span>
                </button>
            </div>
        </li>
    `).join('');
}

function getStrengthClass(score) {
    if (score >= 4) return 'strong';
    if (score >= 3) return 'good';
    if (score >= 2) return 'fair';
    return 'weak';
}

function getStrengthLabel(score) {
    const labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    return labels[Math.min(score || 0, 4)];
}

function displayEmptyVault() {
    const content = vaultFilter ? `
        <div class="empty-vault-content">
            <div style="font-size: 3rem; margin-bottom: 1rem;">🔍</div>
            <h3>No Results Found</h3>
            <p>No passwords match your search for "${vaultFilter}"</p>
            <button onclick="clearVaultFilter()" class="clear-filter-btn">Clear Filter</button>
        </div>
    ` : `
        <div class="empty-vault-content">
            <div style="font-size: 4rem; margin-bottom: 1rem;">🔐</div>
            <h3>Your Secure Vault is Empty</h3>
            <p>Add your first password to experience military-grade encryption!</p>
            <div class="security-reminder">
                <strong>Security:</strong> All passwords encrypted with AES-256 before storage
            </div>
            <div class="security-features">
                <div class="feature">🛡️ PBKDF2 Key Derivation</div>
                <div class="feature">🔑 Fernet Encryption</div>
                <div class="feature">🚫 Zero-Knowledge Architecture</div>
            </div>
        </div>
    `;
    
    elements.vaultList.innerHTML = `<li class="empty-vault">${content}</li>`;
}

function clearVaultFilter() {
    vaultFilter = '';
    if (elements.vaultSearch) {
        elements.vaultSearch.value = '';
    }
    updateVaultDisplay();
}

function displayVaultStats(visibleCount) {
    const existingStats = document.querySelector('.vault-stats');
    if (existingStats) {
        existingStats.remove();
    }
    
    const statsDiv = document.createElement('div');
    statsDiv.className = 'vault-stats';
    statsDiv.innerHTML = `
        <div class="stats-grid">
            <div class="stat-item">
                <span class="stat-value">${visibleCount}</span>
                <span class="stat-label">${vaultFilter ? 'Filtered' : 'Total'} Passwords</span>
            </div>
            <div class="stat-item">
                <span class="stat-value">${50 - vaultData.length}</span>
                <span class="stat-label">Remaining Slots</span>
            </div>
            <div class="stat-item">
                <span class="stat-value">🔒</span>
                <span class="stat-label">AES-256 Secured</span>
            </div>
            <div class="stat-item">
                <span class="stat-value">${Math.round((vaultData.length / 50) * 100)}%</span>
                <span class="stat-label">Vault Usage</span>
            </div>
        </div>
    `;
    
    if (elements.vaultList && elements.vaultList.parentNode) {
        elements.vaultList.parentNode.insertBefore(statsDiv, elements.vaultList);
    }
}

// ===== VAULT PASSWORD OPERATIONS =====
async function copyVaultPassword(id) {
    const masterPassword = await getMasterPassword();
    if (!masterPassword) return;
    
    try {
        updateButtonState(document.getElementById(`copy-btn-${id}`), true, 'Copying...');
        
        const response = await fetch(`/api/vault/${id}/password`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ master_password: masterPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
            await navigator.clipboard.writeText(data.password);
            showNotification('Password securely copied to clipboard!', 'success');
            
            setTimeout(() => {
                navigator.clipboard.writeText('').catch(() => {});
            }, 30000);
            
            await loadVaultData();
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Failed to copy password:', error);
        showNotification('Failed to copy password', 'error');
    } finally {
        updateButtonState(document.getElementById(`copy-btn-${id}`), false, '📋 Copy');
    }
}

async function viewVaultPassword(id) {
    const masterPassword = await getMasterPassword();
    if (!masterPassword) return;
    
    try {
        updateButtonState(document.getElementById(`view-btn-${id}`), true, 'Decrypting...');
        
        const response = await fetch(`/api/vault/${id}/password`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ master_password: masterPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
            const item = vaultData.find(item => item.id === id);
            displayPasswordModal(item, data.password);
            await loadVaultData();
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Failed to view password:', error);
        showNotification('Failed to decrypt password', 'error');
    } finally {
        updateButtonState(document.getElementById(`view-btn-${id}`), false, '👁️ View');
    }
}

async function deleteVaultPassword(id) {
    const item = vaultData.find(item => item.id === id);
    
    if (!confirm(`⚠️ Permanently delete password for "${item.site}"?\n\nThis action cannot be undone and will remove the encrypted data.`)) {
        return;
    }
    
    try {
        updateButtonState(document.getElementById(`delete-btn-${id}`), true, 'Deleting...');
        
        const response = await fetch(`/api/vault/${id}`, {
            method: 'DELETE',
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        const data = await response.json();
        
        if (data.success) {
            await loadVaultData();
            showNotification('Password securely deleted', 'success');
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Failed to delete password:', error);
        showNotification('Failed to delete password', 'error');
    } finally {
        updateButtonState(document.getElementById(`delete-btn-${id}`), false, '🗑️ Delete');
    }
}

// ===== NOTIFICATION SYSTEM =====
async function loadUserNotifications() {
    try {
        const response = await fetch('/api/me', {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        const data = await response.json();
        
        if (data.success && data.alerts) {
            updateNotificationBadge(data.alerts.length);
            displayNotifications(data.alerts);
        }
    } catch (error) {
        console.error('Failed to load notifications:', error);
    }
}

function updateNotificationBadge(count) {
    if (elements.notificationsBtn) {
        const badge = elements.notificationsBtn.querySelector('.notification-badge') || 
                     document.createElement('span');
        
        if (count > 0) {
            badge.className = 'notification-badge';
            badge.textContent = count > 99 ? '99+' : count.toString();
            badge.style.cssText = `
                position: absolute; top: -5px; right: -5px; background: #ff4757;
                color: white; border-radius: 50%; padding: 2px 6px; font-size: 0.7rem;
                font-weight: bold; min-width: 18px; height: 18px; display: flex;
                align-items: center; justify-content: center; animation: notificationPulse 2s infinite;
            `;
            
            if (!elements.notificationsBtn.querySelector('.notification-badge')) {
                elements.notificationsBtn.style.position = 'relative';
                elements.notificationsBtn.appendChild(badge);
            }
        } else if (elements.notificationsBtn.querySelector('.notification-badge')) {
            badge.remove();
        }
    }
}

function openNotificationModal() {
    if (elements.notificationModal) {
        elements.notificationModal.classList.add('show');
        elements.notificationModal.style.animation = 'modalFadeIn 0.3s ease-out';
        loadUserNotifications();
    }
}

function closeNotificationModal() {
    if (elements.notificationModal) {
        elements.notificationModal.style.animation = 'modalFadeOut 0.3s ease-out';
        setTimeout(() => {
            elements.notificationModal.classList.remove('show');
        }, 300);
    }
}

function displayNotifications(alerts) {
    if (!elements.notificationsList) return;
    
    if (alerts.length === 0) {
        elements.notificationsList.innerHTML = `
            <div class="no-notifications">
                <div style="font-size: 2rem; margin-bottom: 1rem;">🔔</div>
                <h3>No Active Alerts</h3>
                <p>Your security status is all clear!</p>
            </div>
        `;
        return;
    }
    
    elements.notificationsList.innerHTML = alerts.map((alert, index) => `
        <div class="notification-item ${alert.severity}" style="animation: fadeInUp 0.3s ease-out ${index * 0.1}s backwards;">
            <div class="notification-header">
                <div class="notification-icon">
                    ${getAlertIcon(alert.type, alert.severity)}
                </div>
                <div class="notification-content">
                    <h4 class="notification-title">${getAlertTitle(alert.type)}</h4>
                    <p class="notification-message">${alert.message}</p>
                    <div class="notification-time">${alert.created_at}</div>
                </div>
                <button class="acknowledge-btn" onclick="acknowledgeAlert(${alert.id})" title="Acknowledge alert">
                    ✓
                </button>
            </div>
        </div>
    `).join('');
}

function getAlertIcon(type, severity) {
    const icons = {
        'breach': severity === 'critical' ? '🚨' : '⚠️',
        'weak_password': '🔓',
        'old_password': '⏰',
        'suspicious_activity': '🔍'
    };
    return icons[type] || '⚠️';
}

function getAlertTitle(type) {
    const titles = {
        'breach': 'Security Breach Detected',
        'weak_password': 'Weak Password Alert',
        'old_password': 'Password Age Warning',
        'suspicious_activity': 'Suspicious Activity'
    };
    return titles[type] || 'Security Alert';
}

async function acknowledgeAlert(alertId) {
    try {
        const response = await fetch(`/api/alerts/${alertId}/acknowledge`, {
            method: 'POST',
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Alert acknowledged', 'success');
            await loadUserNotifications();
        } else {
            showNotification('Failed to acknowledge alert', 'error');
        }
    } catch (error) {
        console.error('Failed to acknowledge alert:', error);
        showNotification('Network error', 'error');
    }
}

// ===== SETTINGS SYSTEM =====
async function loadUserSettings() {
    try {
        const response = await fetch('/api/notifications/preferences', {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        const data = await response.json();
        
        if (data.success) {
            updateSettingsUI(data.preferences);
        }
    } catch (error) {
        console.error('Failed to load settings:', error);
    }
}

function updateSettingsUI(preferences) {
    const settingMappings = [
        { element: elements.breachAlertsToggle, value: preferences.breach_alerts },
        { element: elements.passwordAgeWarningsToggle, value: preferences.password_age_warnings },
        { element: elements.suspiciousActivityToggle, value: preferences.suspicious_activity },
        { element: elements.notificationEmail, value: preferences.email },
        { element: elements.notificationPhone, value: preferences.phone }
    ];
    
    settingMappings.forEach(({ element, value }) => {
        if (element) {
            if (element.type === 'checkbox') {
                element.checked = value || false;
            } else {
                element.value = value || '';
            }
        }
    });
}

function openSettingsModal() {
    if (elements.settingsModal) {
        elements.settingsModal.classList.add('show');
        elements.settingsModal.style.animation = 'modalFadeIn 0.3s ease-out';
        loadUserSettings();
    }
}

function closeSettingsModal() {
    if (elements.settingsModal) {
        elements.settingsModal.style.animation = 'modalFadeOut 0.3s ease-out';
        setTimeout(() => {
            elements.settingsModal.classList.remove('show');
        }, 300);
    }
}

async function saveNotificationSettings() {
    try {
        updateButtonState(elements.saveSettingsBtn, true, 'Saving...');
        
        const preferences = {
            breach_alerts: elements.breachAlertsToggle?.checked || false,
            password_age_warnings: elements.passwordAgeWarningsToggle?.checked || false,
            suspicious_activity: elements.suspiciousActivityToggle?.checked || false,
            email: elements.notificationEmail?.value.trim() || '',
            phone: elements.notificationPhone?.value.trim() || ''
        };
        
        const response = await fetch('/api/notifications/preferences', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(preferences)
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Settings saved successfully!', 'success');
            closeSettingsModal();
        } else {
            showNotification(data.message || 'Failed to save settings', 'error');
        }
    } catch (error) {
        console.error('Failed to save settings:', error);
        showNotification('Network error', 'error');
    } finally {
        updateButtonState(elements.saveSettingsBtn, false, 'Save Settings');
    }
}

// ===== PASSWORD MODAL FUNCTIONS =====
function displayPasswordModal(item, password) {
    document.querySelectorAll('.password-modal').forEach(modal => modal.remove());
    
    const modal = document.createElement('div');
    modal.className = 'password-modal';
    modal.innerHTML = `
        <div class="password-modal-content">
            <div class="modal-header">
                <h3>🔓 Securely Decrypted Password</h3>
                <button onclick="this.closest('.password-modal').remove()" class="close-modal-btn">×</button>
            </div>
            <div class="password-display">
                <div class="password-field">
                    <label>Site/Service:</label>
                    <span class="field-value">${escapeHtml(item.site)}</span>
                </div>
                <div class="password-field">
                    <label>Username:</label>
                    <span class="field-value">${escapeHtml(item.username)}</span>
                </div>
                <div class="password-field">
                    <label>Password:</label>
                    <div class="password-reveal-container">
                        <span class="revealed-password" id="revealed-password-${item.id}">${escapeHtml(password)}</span>
                        <button class="reveal-toggle" onclick="togglePasswordVisibilityInModal('revealed-password-${item.id}')">👁️</button>
                    </div>
                </div>
                <div class="password-stats">
                    <div class="stat">Created: ${item.created_at}</div>
                    <div class="stat">Updated: ${item.updated_at}</div>
                    ${item.access_count ? `<div class="stat">Accessed: ${item.access_count} times</div>` : ''}
                    <div class="stat">Strength: ${getStrengthLabel(item.password_strength_score)}</div>
                </div>
                <div class="security-timer">
                    🔒 Auto-hide in <span id="timer-${item.id}">15</span> seconds for security
                </div>
            </div>
            <div class="modal-actions">
                <button onclick="copyPasswordFromModal('${password.replace(/'/g, "\\'")}');" class="copy-modal-btn">📋 Secure Copy</button>
                <button onclick="this.closest('.password-modal').remove()" class="close-modal-btn secondary">Close</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    startSecurityTimer(item.id, modal);
    
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

function startSecurityTimer(itemId, modal) {
    let timeLeft = 15;
    const timerElement = modal.querySelector(`#timer-${itemId}`);
    
    const countdown = setInterval(() => {
        timeLeft--;
        if (timerElement) {
            timerElement.textContent = timeLeft;
            
            if (timeLeft <= 5) {
                timerElement.style.color = '#ff4757';
                timerElement.style.fontWeight = 'bold';
            }
        }
        
        if (timeLeft <= 0) {
            clearInterval(countdown);
            if (modal.parentNode) {
                modal.style.animation = 'modalFadeOut 0.3s ease-out';
                setTimeout(() => modal.remove(), 300);
            }
        }
    }, 1000);
}

function togglePasswordVisibilityInModal(passwordElementId) {
    const passwordElement = document.getElementById(passwordElementId);
    const toggleButton = passwordElement?.nextElementSibling;
    
    if (passwordElement) {
        if (passwordElement.style.filter === 'blur(5px)') {
            passwordElement.style.filter = '';
            if (toggleButton) toggleButton.textContent = '🙈';
        } else {
            passwordElement.style.filter = 'blur(5px)';
            if (toggleButton) toggleButton.textContent = '👁️';
        }
    }
}

async function copyPasswordFromModal(password) {
    try {
        await navigator.clipboard.writeText(password);
        showNotification('Password securely copied!', 'success');
    } catch (error) {
        console.error('Failed to copy password:', error);
        showNotification('Failed to copy password', 'error');
    }
}

// ===== BREACH CHECK FUNCTIONS =====
async function checkPasswordStrength(password) {
    try {
        const response = await fetch('/api/check_password', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ password: password })
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                updateBreachStatus(data.breached, data.count, data.security_level);
                updateAdvancedMetrics(data);
            }
        } else {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
    } catch (error) {
        console.error('Password strength check failed:', error);
        if (elements.breachStatus) {
            elements.breachStatus.innerHTML = '<span style="color: var(--text-secondary);">⚠️ Unable to check breach status</span>';
        }
    }
}

function updateBreachStatus(isBreached, count, securityLevel) {
    if (!elements.breachStatus) return;
    
    if (isBreached) {
        const warningLevels = {
            critical: { level: 'CRITICAL RISK', color: '#ff4757' },
            high_risk: { level: 'HIGH RISK', color: '#ff6348' },
            medium_risk: { level: 'MEDIUM RISK', color: '#ffa502' }
        };
        
        const warning = warningLevels[securityLevel] || { level: 'COMPROMISED', color: '#ff4757' };
        
        elements.breachStatus.innerHTML = `
            <span class="breach-warning" style="color: ${warning.color}; animation: breachPulse 1.5s ease-in-out infinite; font-weight: 700;">
                🚨 ${warning.level}: Found in ${count.toLocaleString()} breaches!
            </span>`;
    } else {
        const securityLevels = {
            fortress: { text: 'FORTRESS LEVEL', color: '#2ed573' },
            military: { text: 'MILITARY GRADE', color: '#58a6ff' },
            strong: { text: 'STRONG SECURITY', color: '#2ed573' }
        };
        
        const security = securityLevels[securityLevel] || { text: 'SECURE', color: '#2ed573' };
        
        elements.breachStatus.innerHTML = `
            <span class="breach-safe" style="color: ${security.color}; font-weight: 700;">
                ✅ ${security.text}: Not found in known breaches
            </span>`;
    }
}

function updateAdvancedMetrics(data) {
    const entropyElement = document.getElementById('passwordEntropy');
    const timeElement = document.getElementById('crackTimeDetailed');
    
    if (entropyElement) {
        const entropy = Math.log2(Math.pow(95, data.score * 2));
        entropyElement.textContent = `${entropy.toFixed(1)} bits`;
    }
    
    if (timeElement && data.crack_time) {
        timeElement.textContent = data.crack_time;
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

function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function animateElement(element, transform, duration = 200) {
    if (element) {
        element.style.transform = transform;
        setTimeout(() => { element.style.transform = 'scale(1)'; }, duration);
    }
}

function updateButtonState(button, isLoading, loadingText) {
    if (!button) return;
    
    if (isLoading) {
        button.disabled = true;
        button.textContent = loadingText;
        button.style.opacity = '0.7';
    } else {
        button.disabled = false;
        button.style.opacity = '1';
    }
}

function showLoadingState(component) {
    const loadingElement = document.getElementById(`${component}-loading`);
    if (loadingElement) {
        loadingElement.style.display = 'block';
    }
}

function hideLoadingState(component) {
    const loadingElement = document.getElementById(`${component}-loading`);
    if (loadingElement) {
        loadingElement.style.display = 'none';
    }
}

function highlightEmptyFields(fields) {
    fields.forEach(field => {
        if (field && !field.value.trim()) {
            field.style.borderColor = '#ff4757';
            field.style.animation = 'shake 0.5s ease-in-out';
            
            setTimeout(() => {
                field.style.borderColor = '';
                field.style.animation = '';
            }, 2000);
        }
    });
}

// ===== SECURITY FUNCTIONS =====
function checkSecureContext() {
    if (!window.isSecureContext) {
        showNotification('Warning: Not running in secure context. Some features may be limited.', 'warning');
        return false;
    }
    return true;
}

function handleVisibilityChange() {
    if (document.hidden && masterPasswordCache) {
        setTimeout(() => {
            masterPasswordCache = null;
            showNotification('Master password cleared for security', 'info');
        }, 30000);
    }
}

function handleKeyboardShortcuts(event) {
    if (event.ctrlKey) {
        switch (event.key) {
            case 'g':
                event.preventDefault();
                if (elements.passwordInput) {
                    generateAndAnalyzePassword();
                } else if (elements.generateBtn) {
                    generateNewPassword();
                }
                break;
            case 'c':
                if (document.activeElement === elements.passwordInput) {
                    event.preventDefault();
                    copyPasswordToClipboard();
                }
                break;
            case 'l':
                event.preventDefault();
                if (elements.loginBtn) {
                    openAuthModal();
                }
                break;
        }
    }
    
    if (event.key === 'Escape') {
        [
            { modal: elements.authModal, close: closeAuthModal },
            { modal: elements.notificationModal, close: closeNotificationModal },
            { modal: elements.settingsModal, close: closeSettingsModal }
        ].forEach(({ modal, close }) => {
            if (modal?.classList.contains('show')) {
                close();
            }
        });
        
        const passwordModal = document.querySelector('.password-modal');
        if (passwordModal) {
            passwordModal.remove();
        }
    }
}

function recordPerformanceMetric(metric, value) {
    performanceMetrics[metric] = value;
    
    if (metric === 'analysisTime' && value > 1000) {
        console.warn('Password analysis taking longer than expected:', value + 'ms');
    }
}

// ===== INITIALIZATION HELPERS =====
function initializePasswordGenerator() {
    if (elements.generateBtn && elements.generatedPassword) {
        setTimeout(() => {
            generateNewPassword();
        }, 500);
    }
    
    if (elements.lengthSlider && elements.lengthValue) {
        updateLengthDisplay(parseInt(elements.lengthSlider.value));
    }
}

function showSecurityStatus() {
    setTimeout(() => {
        if (location.protocol === 'https:') {
            showNotification('Secure HTTPS connection established', 'success');
        } else {
            showNotification('Warning: Use HTTPS for maximum security', 'warning');
        }
    }, 1000);
}

// ===== NOTIFICATION SYSTEM =====
function showNotification(message, type = 'success') {
    document.querySelectorAll(`.notification.${type}`).forEach(notification => {
        notification.style.animation = 'slideOutRight 0.3s ease-in';
        setTimeout(() => notification.remove(), 300);
    });
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    const colors = {
        success: 'linear-gradient(135deg, #2ed573, #17d97a)',
        error: 'linear-gradient(135deg, #ff4757, #ff3742)',
        info: 'linear-gradient(135deg, #3742fa, #2f3542)',
        warning: 'linear-gradient(135deg, #ffa502, #ff6348)'
    };
    
    const icons = { success: '✅', error: '❌', info: 'ℹ️', warning: '⚠️' };
    
    notification.style.cssText = `
        position: fixed; top: 20px; right: 20px; background: ${colors[type] || colors.success};
        color: white; padding: 16px 24px; border-radius: 12px; z-index: 10000;
        font-weight: 600; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3); max-width: 350px;
        word-wrap: break-word; animation: slideInRight 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        backdrop-filter: blur(15px); border: 1px solid rgba(255, 255, 255, 0.2); cursor: pointer;
    `;
    
    notification.innerHTML = `<span style="margin-right: 8px;">${icons[type] || icons.success}</span>${message}`;
    
    notification.addEventListener('click', () => {
        notification.style.animation = 'slideOutRight 0.3s ease-in';
        setTimeout(() => notification.remove(), 300);
    });
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideOutRight 0.3s ease-in';
            setTimeout(() => notification.remove(), 300);
        }
    }, 4000);
}

// ===== ENHANCED CSS STYLES =====
function addEnhancedStyles() {
    const style = document.createElement('style');
    style.textContent = `
        @keyframes strengthPulse {
            0%, 100% { box-shadow: 0 0 15px rgba(46, 213, 115, 0.6); transform: scale(1); }
            50% { box-shadow: 0 0 25px rgba(46, 213, 115, 0.9); transform: scale(1.02); }
        }
        
        @keyframes breachPulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(1.05); }
        }
        
        @keyframes notificationPulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes modalFadeIn {
            from { opacity: 0; transform: scale(0.85) translateY(-20px); }
            to { opacity: 1; transform: scale(1) translateY(0); }
        }
        
        @keyframes modalFadeOut {
            from { opacity: 1; transform: scale(1) translateY(0); }
            to { opacity: 0; transform: scale(0.85) translateY(-20px); }
        }
        
        @keyframes slideInRight {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        @keyframes slideOutRight {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }
    `;
    document.head.appendChild(style);
}

// ===== CONSOLE SECURITY WARNING =====
function showSecurityWarning() {
    console.log('%c🛡️ VaultGuard Security Notice', 'color: #2ed573; font-size: 16px; font-weight: bold;');
    console.log('%cThis application handles sensitive password data.', 'color: #ffa502; font-size: 12px;');
    console.log('%cDo not paste or execute unknown code in this console.', 'color: #ff4757; font-size: 12px;');
    console.log('%cAll passwords are encrypted with AES-256 before storage.', 'color: #58a6ff; font-size: 12px;');
}

// ===== ERROR HANDLING =====
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    showNotification('An unexpected error occurred', 'error');
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    showNotification('Network or server error occurred', 'error');
    event.preventDefault();
});

// ===== SECURITY CLEANUP ON PAGE UNLOAD =====
window.addEventListener('beforeunload', () => {
    masterPasswordCache = null;
    
    document.querySelectorAll('.revealed-password').forEach(el => {
        el.textContent = '••••••••••';
    });
    
    if (navigator.clipboard) {
        navigator.clipboard.writeText('').catch(() => {});
    }
});

// ===== GLOBAL FUNCTION EXPORTS =====
window.copyVaultPassword = copyVaultPassword;
window.viewVaultPassword = viewVaultPassword;
window.deleteVaultPassword = deleteVaultPassword;
window.clearVaultFilter = clearVaultFilter;
window.togglePasswordVisibilityInModal = togglePasswordVisibilityInModal;
window.copyPasswordFromModal = copyPasswordFromModal;
window.acknowledgeAlert = acknowledgeAlert;

window.VaultGuard = {
    analyzePassword,
    generateRandomPassword,
    openAuthModal,
    closeAuthModal,
    showNotification,
    initialize
};

// ===== MAIN INITIALIZATION =====
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}

showSecurityWarning();// ===== COMPLETE VAULTGUARD JAVASCRIPT - CLEANED & OPTIMIZED 2025 =====
