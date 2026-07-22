/**
 * ═══════════════════════════════════════════════════════════════════════════
 * 🛡️ نظام الحماية المتقدم - Rate Limiting و Session Management
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * هذا الملف يحتوي على:
 * 1. Rate Limiter - حد أقصى للمحاولات
 * 2. Session Manager - إدارة الجلسات الآمنة
 * 3. Security Monitor - مراقبة الأنشطة المريبة
 * 4. Audit Logger - تسجيل جميع العمليات الحساسة
 */

// ═══════════════════════════════════════════════════════════════════════════
// 🔐 ENHANCED RATE LIMITER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @class RateLimiter
 * @description نظام حد أقصى متقدم للمحاولات مع تتبع تفصيلي
 * 
 * @example
 * const limiter = new RateLimiter({
 *   maxAttempts: 5,
 *   windowMs: 900000,  // 15 دقيقة
 *   blockDurationMs: 3600000  // ساعة واحدة
 * });
 * 
 * if (!limiter.canProceed('user@example.com')) {
 *   throw new Error('Too many attempts');
 * }
 */
class RateLimiter {
    /**
     * @constructor
     * @param {Object} options - إعدادات المحدد
     * @param {number} options.maxAttempts - الحد الأقصى للمحاولات (افتراضي: 5)
     * @param {number} options.windowMs - النافذة الزمنية بالميلي ثانية (افتراضي: 900000)
     * @param {number} options.blockDurationMs - مدة الحظر بالميلي ثانية (افتراضي: 900000)
     * @param {string} options.storageKey - مفتاح التخزين (افتراضي: 'rate_limit')
     */
    constructor(options = {}) {
        this.maxAttempts = options.maxAttempts || 5;
        this.windowMs = options.windowMs || 900000; // 15 دقيقة
        this.blockDurationMs = options.blockDurationMs || 900000;
        this.storageKey = options.storageKey || 'rate_limit';
        this.alerts = options.alerts || null; // callback للتنبيهات
        
        /**
         * هيكل البيانات في localStorage:
         * {
         *   'key1': { attempts: [ts1, ts2], blocked: false, unblockAt: 0 },
         *   'key2': { attempts: [], blocked: true, unblockAt: 1234567890 }
         * }
         */
    }

    /**
     * التحقق من إمكانية تنفيذ العملية
     * @param {string} key - معرف فريد للعملية (بريد العميل، رقم الهاتف، إلخ)
     * @returns {boolean} true إذا كان يمكن المتابعة، false إذا تم تجاوز الحد
     * 
     * @example
     * if (limiter.canProceed('user123')) {
     *   // تنفيذ العملية
     * } else {
     *   // إظهار رسالة خطأ
     * }
     */
    canProceed(key) {
        const record = this._getRecord(key);
        const now = Date.now();

        // التحقق من الحظر النشط
        if (record.blocked && now < record.unblockAt) {
            if (this.alerts) {
                this.alerts.warn(`🚫 الحساب ${key} محظور حتى ${new Date(record.unblockAt).toLocaleTimeString('ar-KW')}`);
            }
            return false;
        }

        // إزالة الحظر إذا انتهت مدته
        if (record.blocked && now >= record.unblockAt) {
            record.blocked = false;
            record.attempts = [];
            this._saveRecord(key, record);
        }

        // تنظيف المحاولات القديمة
        const recentAttempts = record.attempts.filter(t => now - t < this.windowMs);

        // التحقق من تجاوز الحد
        if (recentAttempts.length >= this.maxAttempts) {
            record.blocked = true;
            record.unblockAt = now + this.blockDurationMs;
            record.attempts = recentAttempts;
            this._saveRecord(key, record);

            if (this.alerts) {
                this.alerts.error(`🔒 تم حظر ${key} لمحاولات كثيرة (${recentAttempts.length}/${this.maxAttempts})`);
            }
            return false;
        }

        // إضافة محاولة جديدة
        recentAttempts.push(now);
        record.attempts = recentAttempts;
        this._saveRecord(key, record);

        return true;
    }

    /**
     * الحصول على معلومات المحاولات المتبقية
     * @param {string} key - معرف الحساب
     * @returns {Object} معلومات التفاصيل
     */
    getStatus(key) {
        const record = this._getRecord(key);
        const now = Date.now();
        const recentAttempts = record.attempts.filter(t => now - t < this.windowMs);
        const remainingAttempts = Math.max(0, this.maxAttempts - recentAttempts.length);
        const isBlocked = record.blocked && now < record.unblockAt;

        return {
            isBlocked,
            attempts: recentAttempts.length,
            maxAttempts: this.maxAttempts,
            remainingAttempts,
            blockedUntil: isBlocked ? new Date(record.unblockAt) : null,
            minutesRemaining: isBlocked ? Math.ceil((record.unblockAt - now) / 60000) : 0
        };
    }

    /**
     * إعادة تعيين محاولات معين
     * @param {string} key - معرف الحساب
     */
    reset(key) {
        localStorage.removeItem(`${this.storageKey}_${key}`);
    }

    /**
     * حظر حساب فوراً
     * @param {string} key - معرف الحساب
     * @param {number} durationMs - مدة الحظر بالميلي ثانية
     */
    blockKey(key, durationMs = this.blockDurationMs) {
        const record = this._getRecord(key);
        record.blocked = true;
        record.unblockAt = Date.now() + durationMs;
        record.attempts = [];
        this._saveRecord(key, record);
    }

    /**
     * الحصول على تقرير الحسابات المحظورة
     * @returns {Array} قائمة الحسابات المحظورة
     */
    getBlockedAccounts() {
        const prefix = `${this.storageKey}_`;
        const blocked = [];

        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith(prefix)) {
                const record = JSON.parse(localStorage.getItem(key));
                if (record.blocked && Date.now() < record.unblockAt) {
                    blocked.push({
                        account: key.replace(prefix, ''),
                        blockedUntil: new Date(record.unblockAt)
                    });
                }
            }
        }
        return blocked;
    }

    // ─── Private Methods ───

    /**
     * @private
     * الحصول على سجل المحاولات
     */
    _getRecord(key) {
        const stored = localStorage.getItem(`${this.storageKey}_${key}`);
        return stored ? JSON.parse(stored) : {
            attempts: [],
            blocked: false,
            unblockAt: 0
        };
    }

    /**
     * @private
     * حفظ سجل المحاولات
     */
    _saveRecord(key, record) {
        localStorage.setItem(`${this.storageKey}_${key}`, JSON.stringify(record));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 🔐 ADVANCED SESSION MANAGER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @class SessionManager
 * @description إدارة متقدمة للجلسات الآمنة مع كشف الأنشطة المريبة
 * 
 * @example
 * const sessionMgr = new SessionManager({
 *   sessionDuration: 24 * 60 * 60 * 1000,
 *   idleTimeout: 15 * 60 * 1000
 * });
 * 
 * await sessionMgr.createSession(userId, userData);
 * const isValid = await sessionMgr.validateSession(userId);
 */
class SessionManager {
    /**
     * @constructor
     * @param {Object} options - إعدادات الجلسة
     * @param {number} options.sessionDuration - مدة الجلسة (افتراضي: 24 ساعة)
     * @param {number} options.idleTimeout - مهلة عدم النشاط (افتراضي: 15 دقيقة)
     * @param {number} options.maxSessions - الحد الأقصى للجلسات المتزامنة (افتراضي: 3)
     */
    constructor(options = {}) {
        this.sessionDuration = options.sessionDuration || 24 * 60 * 60 * 1000;
        this.idleTimeout = options.idleTimeout || 15 * 60 * 1000;
        this.maxSessions = options.maxSessions || 3;
        this.storageKey = 'admin_sessions';
        this.alerts = options.alerts || null;

        // بدء مراقب الخمول
        this._startIdleMonitor();
    }

    /**
     * إنشاء جلسة جديدة
     * @param {string} userId - معرف المستخدم
     * @param {Object} userData - بيانات المستخدم
     * @returns {Promise<Object>} بيانات الجلسة
     * 
     * @example
     * const session = await sessionMgr.createSession(
     *   'user@example.com',
     *   { name: 'أحمد', role: 'admin' }
     * );
     */
    async createSession(userId, userData) {
        const deviceFingerprint = await this._getDeviceFingerprint();
        const sessionId = this._generateSessionId();

        const session = {
            id: sessionId,
            userId,
            userData,
            createdAt: Date.now(),
            lastActivityAt: Date.now(),
            expiresAt: Date.now() + this.sessionDuration,
            deviceFingerprint,
            ipHash: await this._hashIP(),
            isValid: true,
            activities: [],
            securityFlags: []
        };

        // حفظ الجلسة
        await this._saveSession(session);

        // التحقق من الحد الأقصى للجلسات
        await this._enforceMaxSessions(userId);

        return session;
    }

    /**
     * التحقق من صحة الجلسة
     * @param {string} userId - معرف المستخدم
     * @returns {Promise<boolean>} true إذا كانت الجلسة صالحة
     */
    async validateSession(userId) {
        const session = await this._loadSession(userId);

        if (!session) {
            return false;
        }

        const now = Date.now();

        // 1️⃣ التحقق من انتهاء الصلاحية
        if (now > session.expiresAt) {
            await this._removeSession(userId);
            return false;
        }

        // 2️⃣ التحقق من الخمول
        if (now - session.lastActivityAt > this.idleTimeout) {
            await this._removeSession(userId);
            if (this.alerts) {
                this.alerts.warn(`⏱️ انتهت جلسة ${userId} بسبب الخمول`);
            }
            return false;
        }

        // 3️⃣ التحقق من بصمة الجهاز
        const currentFingerprint = await this._getDeviceFingerprint();
        if (session.deviceFingerprint !== currentFingerprint) {
            if (this.alerts) {
                this.alerts.error(`🚨 تحذير: بصمة جهاز مختلفة للمستخدم ${userId}`);
            }
            session.securityFlags.push({
                type: 'device_mismatch',
                timestamp: now,
                severity: 'high'
            });
            await this._saveSession(session);
            return false;
        }

        // 4️⃣ تحديث آخر نشاط
        session.lastActivityAt = now;
        await this._saveSession(session);

        return true;
    }

    /**
     * تسجيل نشاط الجلسة
     * @param {string} userId - معرف المستخدم
     * @param {string} action - نوع النشاط
     * @param {Object} details - تفاصيل النشاط
     */
    async logActivity(userId, action, details = {}) {
        const session = await this._loadSession(userId);
        if (!session) return;

        session.activities.push({
            action,
            details,
            timestamp: Date.now()
        });

        // الاحتفاظ بـ آخر 100 نشاط فقط
        if (session.activities.length > 100) {
            session.activities = session.activities.slice(-100);
        }

        await this._saveSession(session);
    }

    /**
     * كشف الأنشطة المريبة
     * @param {string} userId - معرف المستخدم
     * @returns {Promise<Array>} قائمة الأنشطة المريبة
     */
    async detectSuspiciousActivity(userId) {
        const session = await this._loadSession(userId);
        if (!session) return [];

        const suspicious = [];
        const now = Date.now();
        const recentActivities = session.activities.filter(
            a => now - a.timestamp < 60000 // آخر دقيقة
        );

        // 1. كثافة العمليات غير الطبيعية
        if (recentActivities.length > 50) {
            suspicious.push({
                type: 'high_frequency',
                severity: 'medium',
                message: `عدد كبير من العمليات (${recentActivities.length} في دقيقة واحدة)`
            });
        }

        // 2. محاولات غير موفقة متتالية
        const failedAttempts = recentActivities.filter(a => a.details.failed);
        if (failedAttempts.length > 5) {
            suspicious.push({
                type: 'repeated_failures',
                severity: 'high',
                message: `${failedAttempts.length} محاولات فاشلة متتالية`
            });
        }

        // 3. عمليات حساسة غير عادية
        const deletions = session.activities.filter(
            a => a.action.includes('delete')
        ).filter(a => now - a.timestamp < 3600000); // آخر ساعة

        if (deletions.length > 10) {
            suspicious.push({
                type: 'excessive_deletions',
                severity: 'critical',
                message: `عدد كبير من عمليات الحذف (${deletions.length} في الساعة)`
            });
        }

        return suspicious;
    }

    /**
     * إنهاء جلسة
     * @param {string} userId - معرف المستخدم
     */
    async endSession(userId) {
        await this._removeSession(userId);
    }

    /**
     * الحصول على معلومات الجلسة
     * @param {string} userId - معرف المستخدم
     * @returns {Promise<Object>} بيانات الجلسة
     */
    async getSessionInfo(userId) {
        const session = await this._loadSession(userId);
        if (!session) return null;

        const now = Date.now();
        return {
            id: session.id,
            userId,
            createdAt: new Date(session.createdAt),
            lastActivityAt: new Date(session.lastActivityAt),
            expiresAt: new Date(session.expiresAt),
            remainingTime: Math.max(0, session.expiresAt - now),
            activitiesCount: session.activities.length,
            securityFlags: session.securityFlags,
            isExpired: now > session.expiresAt
        };
    }

    // ─── Private Methods ───

    /**
     * @private
     * توليد معرف جلسة فريد
     */
    _generateSessionId() {
        return `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * @private
     * الحصول على بصمة الجهاز
     */
    async _getDeviceFingerprint() {
        const fingerprint = {
            userAgent: navigator.userAgent,
            language: navigator.language,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            screenResolution: `${screen.width}x${screen.height}`,
            platform: navigator.platform,
            hardwareConcurrency: navigator.hardwareConcurrency || 'unknown'
        };

        const jsonStr = JSON.stringify(fingerprint);
        const encoder = new TextEncoder();
        const data = encoder.encode(jsonStr);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * @private
     * حساب Hash عنوان IP (من الـ Backend)
     */
    async _hashIP() {
        // ملاحظة: في الواقع يجب الحصول على IP من الـ Backend
        // هذا مجرد تخمين محلي
        return btoa(navigator.userAgent).slice(0, 16);
    }

    /**
     * @private
     * حفظ الجلسة
     */
    async _saveSession(session) {
        const data = {
            ...session,
            savedAt: Date.now()
        };
        localStorage.setItem(`${this.storageKey}_${session.userId}`, JSON.stringify(data));
    }

    /**
     * @private
     * تحميل الجلسة
     */
    async _loadSession(userId) {
        const stored = localStorage.getItem(`${this.storageKey}_${userId}`);
        return stored ? JSON.parse(stored) : null;
    }

    /**
     * @private
     * حذف الجلسة
     */
    async _removeSession(userId) {
        localStorage.removeItem(`${this.storageKey}_${userId}`);
    }

    /**
     * @private
     * فرض الحد الأقصى للجلسات المتزامنة
     */
    async _enforceMaxSessions(userId) {
        const prefix = `${this.storageKey}_`;
        const sessions = [];

        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith(prefix)) {
                const session = JSON.parse(localStorage.getItem(key));
                if (session.userId === userId && Date.now() < session.expiresAt) {
                    sessions.push(session);
                }
            }
        }

        // حذف الجلسات القديمة إذا تجاوزنا الحد الأقصى
        if (sessions.length > this.maxSessions) {
            sessions.sort((a, b) => a.createdAt - b.createdAt);
            for (let i = 0; i < sessions.length - this.maxSessions; i++) {
                localStorage.removeItem(`${this.storageKey}_${sessions[i].userId}`);
            }
        }
    }

    /**
     * @private
     * بدء مراقب الخمول
     */
    _startIdleMonitor() {
        const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
        let idleTimer = null;

        const resetIdleTimer = () => {
            if (idleTimer) clearTimeout(idleTimer);
            // يمكن إضافة منطق إضافي هنا
        };

        events.forEach(event => {
            document.addEventListener(event, resetIdleTimer);
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 📊 AUDIT LOGGER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @class AuditLogger
 * @description تسجيل شامل لجميع العمليات الحساسة والحرجة
 * 
 * @example
 * const auditLog = new AuditLogger(dbRef);
 * await auditLog.logAction('delete_branch', { branchId: 'br1' }, userId);
 */
class AuditLogger {
    /**
     * @constructor
     * @param {Object} dbRef - مرجع Firebase Database
     * @param {Object} options - الإعدادات
     */
    constructor(dbRef, options = {}) {
        this.dbRef = dbRef;
        this.maxLocalLogs = options.maxLocalLogs || 500;
        this.storageKey = 'audit_logs';
        this.severityLevels = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        };
    }

    /**
     * تسجيل عملية
     * @param {string} action - نوع العملية
     * @param {Object} details - تفاصيل العملية
     * @param {string} userId - معرف المستخدم
     * @param {string} severity - مستوى الخطورة
     * @returns {Promise<Object>} بيانات السجل المحفوظ
     * 
     * @example
     * await auditLog.logAction(
     *   'delete_order',
     *   { orderId: 'ord123', clientName: 'أحمد' },
     *   'admin@example.com',
     *   'high'
     * );
     */
    async logAction(action, details = {}, userId = 'unknown', severity = 'low') {
        const logEntry = {
            id: this._generateLogId(),
            timestamp: Date.now(),
            action,
            details,
            userId,
            severity,
            deviceInfo: {
                userAgent: navigator.userAgent,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                timestamp: new Date().toLocaleString('ar-KW')
            }
        };

        // 1️⃣ حفظ محلي
        this._saveLocalLog(logEntry);

        // 2️⃣ إرسال للـ Firebase (بشكل غير متزامن)
        if (this.dbRef) {
            this._sendToServer(logEntry).catch(err => {
                console.warn('Failed to send audit log to server:', err.message);
            });
        }

        return logEntry;
    }

    /**
     * الحصول على السجلات المحلية
     * @param {Object} filter - معايير التصفية
     * @returns {Array} قائمة السجلات
     * 
     * @example
     * const logs = auditLog.getLocalLogs({
     *   action: 'delete_order',
     *   severity: 'high',
     *   limit: 50
     * });
     */
    getLocalLogs(filter = {}) {
        try {
            const allLogs = JSON.parse(localStorage.getItem(this.storageKey) || '[]');
            let filtered = allLogs;

            // تطبيق المرشحات
            if (filter.action) {
                filtered = filtered.filter(l => l.action.includes(filter.action));
            }
            if (filter.userId) {
                filtered = filtered.filter(l => l.userId === filter.userId);
            }
            if (filter.severity) {
                const severityLevel = this.severityLevels[filter.severity] || 0;
                filtered = filtered.filter(l => this.severityLevels[l.severity] >= severityLevel);
            }
            if (filter.fromDate) {
                filtered = filtered.filter(l => l.timestamp >= filter.fromDate.getTime());
            }

            // ترتيب وتحديد عدد النتائج
            const limit = filter.limit || 100;
            return filtered.sort((a, b) => b.timestamp - a.timestamp).slice(0, limit);
        } catch (e) {
            console.error('Error reading audit logs:', e);
            return [];
        }
    }

    /**
     * تحليل السجلات للكشف عن الأنماط المريبة
     * @param {Object} options - خيارات التحليل
     * @returns {Object} التقرير التحليلي
     * 
     * @example
     * const report = auditLog.analyzePatterns({
     *   timewindowMs: 3600000 // آخر ساعة
     * });
     */
    analyzePatterns(options = {}) {
        const timeWindowMs = options.timewindowMs || 3600000;
        const logs = this.getLocalLogs({ limit: 1000 });
        const now = Date.now();
        const recentLogs = logs.filter(l => now - l.timestamp < timeWindowMs);

        const analysis = {
            totalActions: recentLogs.length,
            actionsByType: {},
            actionsByUser: {},
            criticalActions: [],
            suspiciousPatterns: []
        };

        // إحصائيات العمليات
        recentLogs.forEach(log => {
            // حسب النوع
            analysis.actionsByType[log.action] = (analysis.actionsByType[log.action] || 0) + 1;

            // حسب المستخدم
            analysis.actionsByUser[log.userId] = (analysis.actionsByUser[log.userId] || 0) + 1;

            // العمليات الحرجة
            if (this.severityLevels[log.severity] >= this.severityLevels['high']) {
                analysis.criticalActions.push(log);
            }
        });

        // الكشف عن الأنماط المريبة
        if (analysis.actionsByType.delete_order > 50) {
            analysis.suspiciousPatterns.push({
                type: 'excessive_deletions',
                severity: 'critical',
                message: `عدد غير عادي من حذف الطلبات: ${analysis.actionsByType.delete_order}`
            });
        }

        // محاولات دخول فاشلة متعددة
        const failedLogins = recentLogs.filter(l => l.action === 'login_failed');
        if (failedLogins.length > 10) {
            analysis.suspiciousPatterns.push({
                type: 'brute_force_attempt',
                severity: 'high',
                message: `محاولات دخول فاشلة: ${failedLogins.length}`
            });
        }

        return analysis;
    }

    /**
     * تصدير السجلات إلى CSV
     * @param {Object} filter - معايير التصفية
     * @returns {string} محتوى CSV
     */
    exportToCSV(filter = {}) {
        const logs = this.getLocalLogs({ ...filter, limit: 10000 });

        let csv = 'الوقت,المستخدم,العملية,التفاصيل,مستوى الخطورة\n';

        logs.forEach(log => {
            const time = new Date(log.timestamp).toLocaleString('ar-KW');
            const user = log.userId.replace(/"/g, '""');
            const action = log.action.replace(/"/g, '""');
            const details = JSON.stringify(log.details).replace(/"/g, '""');
            csv += `"${time}","${user}","${action}","${details}","${log.severity}"\n`;
        });

        return csv;
    }

    /**
     * حذف السجلات القديمة
     * @param {number} daysOld - حذف السجلات الأقدم من هذا العدد من الأيام
     */
    purgeLogs(daysOld = 30) {
        try {
            const allLogs = JSON.parse(localStorage.getItem(this.storageKey) || '[]');
            const cutoffTime = Date.now() - (daysOld * 24 * 60 * 60 * 1000);
            const filtered = allLogs.filter(l => l.timestamp > cutoffTime);
            localStorage.setItem(this.storageKey, JSON.stringify(filtered));
            return allLogs.length - filtered.length;
        } catch (e) {
            console.error('Error purging logs:', e);
            return 0;
        }
    }

    // ─── Private Methods ───

    /**
     * @private
     */
    _generateLogId() {
        return `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * @private
     */
    _saveLocalLog(logEntry) {
        try {
            const logs = JSON.parse(localStorage.getItem(this.storageKey) || '[]');
            logs.push(logEntry);

            // الاحتفاظ بـ آخر N سجل فقط
            if (logs.length > this.maxLocalLogs) {
                logs.splice(0, logs.length - this.maxLocalLogs);
            }

            localStorage.setItem(this.storageKey, JSON.stringify(logs));
        } catch (e) {
            console.error('Error saving local log:', e);
        }
    }

    /**
     * @private
     */
    async _sendToServer(logEntry) {
        if (!this.dbRef) return;

        try {
            // يتم الحفظ في مسار منفصل للأدمن
            await this.dbRef.child(`admin_audit_logs/${logEntry.id}`).set(logEntry);
        } catch (e) {
            console.error('Error sending audit log to server:', e);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 🚨 SECURITY MONITOR
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @class SecurityMonitor
 * @description مراقب الأمان المركزي - يجمع بين جميع أدوات الحماية
 */
class SecurityMonitor {
    /**
     * @constructor
     * @param {Object} config - إعدادات المراقب
     */
    constructor(config = {}) {
        this.rateLimiter = new RateLimiter({
            maxAttempts: config.maxLoginAttempts || 5,
            windowMs: config.rateLimitWindow || 900000,
            blockDurationMs: config.blockDuration || 3600000,
            alerts: this
        });

        this.sessionManager = new SessionManager({
            sessionDuration: config.sessionDuration || 24 * 60 * 60 * 1000,
            idleTimeout: config.idleTimeout || 15 * 60 * 1000,
            maxSessions: config.maxSessions || 3,
            alerts: this
        });

        this.auditLogger = new AuditLogger(config.dbRef, {
            maxLocalLogs: config.maxAuditLogs || 500
        });

        this.alertCallbacks = [];
    }

    /**
     * تسجيل callback للتنبيهات
     * @param {Function} callback - دالة معالجة التنبيه
     */
    onAlert(callback) {
        this.alertCallbacks.push(callback);
    }

    /**
     * إرسال تنبيه
     * @private
     */
    _emitAlert(type, message, data = {}) {
        const alert = { type, message, data, timestamp: Date.now() };
        this.alertCallbacks.forEach(cb => {
            try {
                cb(alert);
            } catch (e) {
                console.error('Alert callback error:', e);
            }
        });
    }

    // Proxy methods
    warn(message) { this._emitAlert('warning', message); }
    error(message) { this._emitAlert('error', message); }
    info(message) { this._emitAlert('info', message); }
}

// ═══════════════════════════════════════════════════════════════════════════
// 📤 EXPORT
// ═══════════════════════════════════════════════════════════════════════════

// جعلها متاحة عالمياً
if (typeof window !== 'undefined') {
    window.SecurityTools = {
        RateLimiter,
        SessionManager,
        AuditLogger,
        SecurityMonitor
    };
}

// للاستخدام في Node.js أو ES Modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        RateLimiter,
        SessionManager,
        AuditLogger,
        SecurityMonitor
    };
}
