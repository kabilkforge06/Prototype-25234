/**
 * NCVD Government Platform - Main JavaScript
 * Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
 * National Cybersecurity Vulnerability Detection Platform
 */

// Global government system variables
const NCVD_CONFIG = {
    currentUser: 'Agent Smith',
    clearanceLevel: 'TS/SCI',
    classification: 'TOP SECRET//SI//NOFORN',
    sessionTimeout: 30 * 60 * 1000, // 30 minutes
    auditLogging: true,
    systemName: 'NCVD'
};

let systemNotifications = [];
let securitySession = null;

// Initialize government platform
$(document).ready(function() {
    initializeGovernmentPlatform();
    initializeSecurityFeatures();
    startSystemMonitoring();
});

function initializeGovernmentPlatform() {
    // Enhanced CSRF protection for government systems
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
                xhr.setRequestHeader("X-Classification", NCVD_CONFIG.classification);
                xhr.setRequestHeader("X-User-Clearance", NCVD_CONFIG.clearanceLevel);
            }
        },
        error: function(xhr, status, error) {
            if (xhr.status === 401) {
                handleSecurityBreach('Unauthorized access attempt detected');
            } else if (xhr.status === 403) {
                handleSecurityBreach('Insufficient clearance level');
            }
        }
    });

    // Initialize government-grade tooltips and UI components
    initializeGovernmentUI();
    
    // Setup security monitoring
    setupSecurityMonitoring();
    
    // Log system initialization
    logSecurityEvent('NCVD platform initialized', 'INFO', 'SYSTEM');
    
    console.log(`[NCVD] Government platform initialized - Classification: ${NCVD_CONFIG.classification}`);
}

function initializeGovernmentUI() {
    // Enhanced tooltips for government interface
    const tooltipElements = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipElements.forEach(el => {
        new bootstrap.Tooltip(el, {
            boundary: 'viewport',
            customClass: 'government-tooltip'
        });
    });

    // Initialize popovers for detailed information
    const popoverElements = document.querySelectorAll('[data-bs-toggle="popover"]');
    popoverElements.forEach(el => {
        new bootstrap.Popover(el, {
            trigger: 'hover focus',
            boundary: 'viewport'
        });
    });

    // Auto-hide government alerts after extended time
    setTimeout(() => {
        $('.alert').fadeOut('slow');
    }, 10000); // 10 seconds for government alerts
}

function initializeSecurityFeatures() {
    // Session management
    securitySession = {
        startTime: new Date(),
        lastActivity: new Date(),
        warningShown: false,
        userId: NCVD_CONFIG.currentUser,
        clearance: NCVD_CONFIG.clearanceLevel
    };

    // Activity tracking for session timeout
    $(document).on('click keypress mousemove', () => {
        updateActivityTimer();
    });

    // Session timeout warning (5 minutes before expiry)
    setTimeout(() => {
        showSessionWarning();
    }, NCVD_CONFIG.sessionTimeout - (5 * 60 * 1000));

    // Classification watermarks
    addClassificationWatermarks();
}

function startSystemMonitoring() {
    // Real-time system health monitoring
    setInterval(() => {
        checkSystemHealth();
        validateSecurityPosture();
    }, 30000); // Every 30 seconds

    // Network connectivity monitoring
    setInterval(() => {
        monitorNetworkStatus();
    }, 10000); // Every 10 seconds
}

// Government notification system
function showGovernmentAlert(message, classification = 'UNCLASSIFIED', type = 'info', timeout = 8000) {
    const alertId = 'alert-' + Date.now();
    const alertClass = getAlertClass(type);
    const classificationBadge = getClassificationBadge(classification);
    
    const alertHtml = `
        <div id="${alertId}" class="alert ${alertClass} alert-dismissible fade show government-alert" role="alert">
            <div class="d-flex align-items-center">
                <div class="me-3">
                    <i class="fas fa-shield-alt fs-5"></i>
                </div>
                <div class="flex-grow-1">
                    <div class="d-flex justify-content-between align-items-center mb-1">
                        <strong>NCVD System Alert</strong>
                        ${classificationBadge}
                    </div>
                    <div>${message}</div>
                    <small class="text-muted">
                        <i class="fas fa-clock me-1"></i>${new Date().toLocaleString()} UTC
                        <span class="ms-2"><i class="fas fa-user me-1"></i>${NCVD_CONFIG.currentUser}</span>
                    </small>
                </div>
            </div>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;

    // Add to top of main container
    $('.container-fluid').first().prepend(alertHtml);

    // Log the alert
    logSecurityEvent(`Alert displayed: ${message}`, 'INFO', 'UI');

    // Auto-remove after timeout
    if (timeout > 0) {
        setTimeout(() => {
            $(`#${alertId}`).fadeOut('slow', function() {
                $(this).remove();
            });
        }, timeout);
    }

    return alertId;
}

function getAlertClass(type) {
    const alertMap = {
        'success': 'alert-success border-start border-success border-3',
        'warning': 'alert-warning border-start border-warning border-3',
        'danger': 'alert-danger border-start border-danger border-3',
        'info': 'alert-info border-start border-info border-3',
        'government': 'alert-government border-start border-3'
    };
    return alertMap[type] || alertMap['info'];
}

function getClassificationBadge(classification) {
    const classMap = {
        'UNCLASSIFIED': 'bg-success',
        'CONFIDENTIAL': 'bg-warning text-dark',
        'SECRET': 'bg-danger',
        'TOP SECRET': 'bg-dark'
    };
    const badgeClass = classMap[classification] || 'bg-secondary';
    return `<span class="badge ${badgeClass} fs-6">${classification}</span>`;
}

// Security and monitoring functions
function updateActivityTimer() {
    if (securitySession) {
        securitySession.lastActivity = new Date();
    }
}

function showSessionWarning() {
    if (securitySession && !securitySession.warningShown) {
        securitySession.warningShown = true;
        const modal = new bootstrap.Modal(document.getElementById('sessionWarningModal'));
        modal.show();
        logSecurityEvent('Session timeout warning displayed', 'WARNING', 'SECURITY');
    }
}

function checkSystemHealth() {
    // Monitor system performance and security status
    const healthMetrics = {
        timestamp: new Date(),
        memoryUsage: performance.memory ? performance.memory.usedJSHeapSize : 'N/A',
        connectionStatus: navigator.onLine ? 'ONLINE' : 'OFFLINE',
        securityLevel: 'OPERATIONAL'
    };
    
    // Log system health (in production, this would send to monitoring system)
    if (!navigator.onLine) {
        showGovernmentAlert('Network connectivity lost - Operating in offline mode', 'UNCLASSIFIED', 'warning');
        logSecurityEvent('Network connectivity lost', 'WARNING', 'NETWORK');
    }
}

function validateSecurityPosture() {
    // Validate current security configuration
    const securityChecks = {
        sessionValid: securitySession && (new Date() - securitySession.startTime) < NCVD_CONFIG.sessionTimeout,
        httpsEnabled: window.location.protocol === 'https:',
        classificationValid: true // In production, validate classification headers
    };

    if (!securityChecks.sessionValid) {
        handleSecurityBreach('Session expired - security violation detected');
    }
}

function monitorNetworkStatus() {
    // Monitor network connectivity and security
    if (!navigator.onLine) {
        logSecurityEvent('Network offline detected', 'WARNING', 'NETWORK');
    }
}

function handleSecurityBreach(reason) {
    logSecurityEvent(`Security breach: ${reason}`, 'CRITICAL', 'SECURITY');
    showGovernmentAlert(`Security Alert: ${reason}`, 'SECRET', 'danger', 0);
    
    // In production, this would trigger additional security protocols
    console.error(`[SECURITY BREACH] ${reason}`);
}

function addClassificationWatermarks() {
    // Add classification watermarks to sensitive areas
    // This would be implemented based on specific government requirements
    console.log('[NCVD] Classification watermarks initialized');
}

function setupSecurityMonitoring() {
    // Initialize security event monitoring
    // Log all user interactions for audit purposes
    $(document).on('click', 'button, a, input[type="submit"]', function(e) {
        const element = $(this);
        const action = element.attr('onclick') || element.attr('href') || element.val() || 'unknown';
        logSecurityEvent(`User interaction: ${action}`, 'INFO', 'USER');
    });
}

function logSecurityEvent(event, level, category, metadata = {}) {
    if (NCVD_CONFIG.auditLogging) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            level: level,
            category: category,
            event: event,
            user: NCVD_CONFIG.currentUser,
            clearance: NCVD_CONFIG.clearanceLevel,
            sessionId: securitySession ? securitySession.startTime.getTime() : null,
            metadata: metadata
        };
        
        // Log to console (in production, send to secure audit system)
        console.log(`[AUDIT] ${JSON.stringify(logEntry)}`);
        
        // Store in local audit log for session
        systemNotifications.push(logEntry);
    }
}

// Enhanced utility functions for government platform
function formatGovernmentTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
        timeZone: 'UTC',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    }) + ' UTC';
}

function getThreatSeverityClass(severity) {
    const severityMap = {
        'CRITICAL': 'threat-critical',
        'HIGH': 'threat-high', 
        'MEDIUM': 'threat-medium',
        'LOW': 'threat-low',
        'INFO': 'threat-info'
    };
    return severityMap[severity?.toUpperCase()] || 'threat-info';
}

function secureClipboardCopy(text, classification = 'UNCLASSIFIED') {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            showGovernmentAlert(`Data copied to clipboard - Classification: ${classification}`, classification, 'success');
            logSecurityEvent(`Clipboard copy operation - Classification: ${classification}`, 'INFO', 'DATA');
        }).catch(err => {
            logSecurityEvent(`Clipboard copy failed: ${err.message}`, 'ERROR', 'DATA');
            showGovernmentAlert('Secure clipboard operation failed', 'UNCLASSIFIED', 'danger');
        });
    } else {
        showGovernmentAlert('Secure clipboard not available - use manual copy', 'UNCLASSIFIED', 'warning');
    }
}

// Enhanced API functions with government security
function makeSecureApiCall(endpoint, method = 'GET', data = null, classification = 'UNCLASSIFIED') {
    const requestId = 'REQ-' + Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
    
    logSecurityEvent(`API request initiated: ${method} ${endpoint}`, 'INFO', 'API', {
        requestId: requestId,
        classification: classification
    });

    const config = {
        url: endpoint,
        method: method,
        contentType: 'application/json',
        dataType: 'json',
        timeout: 30000, // 30 second timeout for government systems
        headers: {
            'X-Classification': classification,
            'X-Request-ID': requestId,
            'X-User-Clearance': NCVD_CONFIG.clearanceLevel
        }
    };

    if (data) {
        config.data = JSON.stringify(data);
    }

    return $.ajax(config)
        .done((response) => {
            logSecurityEvent(`API request successful: ${requestId}`, 'INFO', 'API');
        })
        .fail((xhr, status, error) => {
            logSecurityEvent(`API request failed: ${requestId} - ${status}: ${error}`, 'ERROR', 'API');
            
            if (xhr.status === 401 || xhr.status === 403) {
                handleSecurityBreach(`Unauthorized API access attempt: ${endpoint}`);
            }
        });
}

// Real-time data refresh for government dashboards
function scheduleDataRefresh(callback, interval = 30000) {
    const refreshId = setInterval(() => {
        try {
            callback();
            logSecurityEvent('Scheduled data refresh executed', 'DEBUG', 'SYSTEM');
        } catch (error) {
            logSecurityEvent(`Data refresh error: ${error.message}`, 'ERROR', 'SYSTEM');
        }
    }, interval);
    
    return refreshId;
}

// Export government platform functions
window.NCVD = {
    // Core functions
    showGovernmentAlert,
    logSecurityEvent,
    makeSecureApiCall,
    
    // Utility functions  
    formatGovernmentTimestamp,
    getThreatSeverityClass,
    secureClipboardCopy,
    scheduleDataRefresh,
    
    // Security functions
    updateActivityTimer,
    checkSystemHealth,
    validateSecurityPosture,
    
    // Configuration
    config: NCVD_CONFIG,
    session: () => securitySession
};

// Legacy compatibility (maintain old function names)
window.showNotification = showGovernmentAlert;
window.formatTimestamp = formatGovernmentTimestamp;
window.getSeverityClass = getThreatSeverityClass;
window.copyToClipboard = secureClipboardCopy;
window.makeApiCall = makeSecureApiCall;