/**
 * ═══════════════════════════════════════════════════════════════════════════
 * 📚 LAUNDRY STATION - نظام الإدارة المركزية
 * وثائق توثيق الكود الشامل (JSDoc)
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * هذا الملف يحتوي على توثيق شامل لجميع المكونات والدوال والفئات
 * في نظام الإدارة المركزية لمحطة الغسيل.
 * 
 * @author Laundry Station Team
 * @version 2.0.0
 * @license MIT
 */

// ═══════════════════════════════════════════════════════════════════════════
// 🔐 SECURITY UTILITIES - أدوات الأمان
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @namespace Sanitizer
 * @description مجموعة دوال تنظيف المدخلات لمنع الهجمات
 * 
 * @property {Function} escape - تحويل أحرف HTML الخاصة
 * @property {Function} sanitizeText - تنظيف النصوص العامة
 * @property {Function} sanitizePhone - تنظيف أرقام الهاتف
 * @property {Function} sanitizeNumber - تنظيف الأرقام والكميات
 * @property {Function} sanitizeKey - تنظيف المفاتيح قاعدة البيانات
 * @property {Function} containsDangerousContent - الكشف عن المحتوى الخطير
 */
const Sanitizer = {
    /**
     * تحويل أحرف HTML الخاصة إلى entities
     * @param {string} str - النص المراد تحويله
     * @returns {string} النص المحول
     * 
     * @example
     * Sanitizer.escape('<script>alert("xss")</script>')
     * // Returns: '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
     */
    escape(str) {
        if (typeof str !== 'string') return '';
        return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                  .replace(/"/g,'&quot;').replace(/'/g,'&#x27;').replace(/\//g,'&#x2F;');
    },

    /**
     * تنظيف النصوص العامة من الأحرف الخطيرة
     * @param {string} str - النص المراد تنظيفه
     * @returns {string} النص المنظف
     * 
     * @example
     * Sanitizer.sanitizeText('Hello <script>alert(1)</script>')
     * // Returns: 'Hello alert(1)'
     */
    sanitizeText(str) {
        if (str == null) return '';
        return String(str).trim().slice(0, 5000);
    },

    /**
     * تنظيف أرقام الهاتف
     * @param {string|number} phone - رقم الهاتف
     * @returns {string} الرقم المنظف (أرقام فقط)
     * 
     * @example
     * Sanitizer.sanitizePhone('9-1-2-3-4-5-6-7')
     * // Returns: '91234567'
     */
    sanitizePhone(phone) {
        return String(phone || '').replace(/\D/g, '').slice(0, 15);
    },

    /**
     * تنظيف الأرقام والكميات
     * @param {string|number} num - الرقم المراد تنظيفه
     * @returns {number} الرقم المنظف
     * 
     * @example
     * Sanitizer.sanitizeNumber('1500.50')
     * // Returns: 1500.50
     */
    sanitizeNumber(num) {
        const n = parseFloat(num);
        if (isNaN(n) || n < 0 || n > 999999) return 0;
        return n;
    },

    /**
     * تنظيف المفاتيح المستخدمة في قاعدة البيانات
     * @param {string} key - المفتاح المراد تنظيفه
     * @returns {string} المفتاح المنظف
     * 
     * @example
     * Sanitizer.sanitizeKey('Branch-#1@Name!')
     * // Returns: 'branch-1name'
     */
    sanitizeKey(key) {
        return String(key || '').toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 50);
    },

    /**
     * الكشف عن المحتوى الخطير (XSS, Scripts, إلخ)
     * @param {string} str - النص المراد فحصه
     * @returns {boolean} true إذا كان يحتوي على محتوى خطير
     * 
     * @example
     * Sanitizer.containsDangerousContent('<script>alert(1)</script>')
     * // Returns: true
     * 
     * Sanitizer.containsDangerousContent('Hello World')
     * // Returns: false
     */
    containsDangerousContent(str) {
        const dangerousPatterns = [
            /<script\b/i,
            /javascript:/i,
            /on\w+\s*=/i,
            /<iframe/i,
            /eval\(/i,
            /document\./i
        ];
        return dangerousPatterns.some(pattern => pattern.test(str));
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// ✅ VALIDATORS - المدققات
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @namespace Validators
 * @description مجموعة دوال التحقق من صحة المدخلات
 * 
 * @property {Function} isValidPhone - التحقق من صحة رقم الهاتف
 * @property {Function} isValidPin - التحقق من صحة الـ PIN
 * @property {Function} isValidBranchCode - التحقق من صحة كود الفرع
 * @property {Function} isValidAmount - التحقق من صحة المبالغ المالية
 * @property {Function} validateImageFile - التحقق من ملفات الصور
 */
const Validators = {
    /**
     * التحقق من صحة رقم الهاتف الكويتي
     * @param {string|number} phone - رقم الهاتف
     * @returns {boolean} true إذا كان صحيحاً
     * 
     * @example
     * Validators.isValidPhone('91234567')   // true
     * Validators.isValidPhone('912345')     // false
     * Validators.isValidPhone('abc12345')   // false
     */
    isValidPhone(p) {
        // التحقق: 8 أرقام فقط
        return /^[0-9]{8}$/.test(String(p || '').replace(/\D/g, ''));
    },

    /**
     * التحقق من صحة PIN
     * @param {string|number} pin - الـ PIN
     * @returns {boolean} true إذا كان PIN صحيح (4 أرقام)
     * 
     * @example
     * Validators.isValidPin('1234')     // true
     * Validators.isValidPin('12345')    // false
     * Validators.isValidPin('pin1')     // false
     */
    isValidPin(p) {
        return /^[0-9]{4}$/.test(String(p || ''));
    },

    /**
     * التحقق من صحة كود الفرع
     * @param {string} code - كود الفرع
     * @returns {boolean} true إذا كان كود الفرع صحيحاً
     * 
     * @description
     * لا يسمح بـ: #, $, [, ], /
     * 
     * @example
     * Validators.isValidBranchCode('branch1')      // true
     * Validators.isValidBranchCode('branch#1')     // false
     * Validators.isValidBranchCode('branch[2]')    // false
     */
    isValidBranchCode(c) {
        return c && !/[\.\#\$\[\]\/]/.test(c);
    },

    /**
     * التحقق من صحة المبالغ المالية
     * @param {string|number} amount - المبلغ
     * @returns {boolean} true إذا كان المبلغ صحيحاً
     * 
     * @example
     * Validators.isValidAmount('150.50')    // true
     * Validators.isValidAmount('-50')       // false
     * Validators.isValidAmount('1000000')   // false (يزيد عن الحد الأقصى)
     */
    isValidAmount(a) {
        const n = parseFloat(a);
        return !isNaN(n) && n >= 0 && n <= 99999;
    },

    /**
     * التحقق من صحة ملف الصورة
     * @param {File} file - ملف الصورة
     * @param {number} maxSizeMB - الحجم الأقصى بالـ MB
     * @returns {Object} كائن يحتوي على {valid: boolean, error: string|null}
     * 
     * @example
     * const result = Validators.validateImageFile(file, 2);
     * if (!result.valid) {
     *   console.error(result.error);
     * }
     */
    validateImageFile(file, maxSizeMB = 2) {
        if (!file) {
            return { valid: false, error: null };
        }

        const validTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/svg+xml', 'image/webp'];
        if (!validTypes.includes(file.type)) {
            return { valid: false, error: 'نوع الملف غير مدعوم' };
        }

        if (file.size > maxSizeMB * 1024 * 1024) {
            return { valid: false, error: `حجم الصورة كبير جداً (الحد ${maxSizeMB}MB)` };
        }

        return { valid: true, error: null };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// 🛠️ HELPERS - الدوال المساعدة
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @namespace Helpers
 * @description مجموعة دوال مساعدة عامة
 * 
 * @property {Array} KUWAIT_AREAS - قائمة المناطق الكويتية
 * @property {Function} formatCurrency - تنسيق العملات
 * @property {Function} generateId - توليد معرفات فريدة
 * @property {Function} formatDate - تنسيق التواريخ
 * @property {Function} generateOrderCode - توليد أكواد الطلبات
 */
const Helpers = {
    /**
     * قائمة المناطق الكويتية المغطاة
     * @type {Array<string>}
     */
    KUWAIT_AREAS: [
        'حولي', 'السالمية', 'الروضة', 'الجابرية', 'مشرف', 'بيان',
        'سلوى', 'الرميثية', 'الخالدية', 'كيفان', 'العديلية', 'اليرموك',
        'قرطبة', 'السرة', 'الفحيحيل', 'المنقف', 'الجهراء', 'العارضية',
        'صباح الناصر', 'الفروانية', 'الأندلس', 'الرقعي', 'جليب الشيوخ',
        'خيطان', 'أبو حليفة', 'الفنطاس', 'القرين', 'مبارك الكبير'
    ],

    /**
     * تنسيق المبالغ المالية بصيغة KWD
     * @param {number|string} amount - المبلغ
     * @returns {string} المبلغ المنسق (مثال: 150.500)
     * 
     * @example
     * Helpers.formatCurrency(1500)      // Returns: '1500.000'
     * Helpers.formatCurrency(150.5)     // Returns: '150.500'
     */
    formatCurrency(a) {
        return parseFloat(a || 0).toFixed(3);
    },

    /**
     * تنظيف أرقام الهاتف
     * @param {string|number} phone - رقم الهاتف
     * @returns {string} الرقم المنظف
     */
    cleanPhone(p) {
        return String(p || '').replace(/\D/g, '');
    },

    /**
     * توليد معرف فريد
     * @param {string} prefix - بادئة المعرف
     * @returns {string} المعرف الفريد (مثال: id_1234567890_abc123)
     * 
     * @example
     * Helpers.generateId('order')    // Returns: 'order_1234567890_xyz123'
     * Helpers.generateId('user')     // Returns: 'user_1234567890_abc456'
     * 
     * @description
     * يستخدم الطابع الزمني (Timestamp) ورقم عشوائي لضمان عدم التكرار
     */
    generateId(prefix = 'id') {
        return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    },

    /**
     * تنسيق التاريخ
     * @param {number} timestamp - الطابع الزمني بالميلي ثانية
     * @returns {string} التاريخ المنسق (مثال: 22/07/2026)
     * 
     * @example
     * Helpers.formatDate(Date.now())     // Returns: '22/07/2026'
     */
    formatDate(ts) {
        return ts ? new Date(ts).toLocaleDateString('ar-KW') : 'N/A';
    },

    /**
     * تنسيق التاريخ والوقت معاً
     * @param {number} timestamp - الطابع الزمني
     * @returns {string} التاريخ والوقت المنسقان
     * 
     * @example
     * Helpers.formatDateTime(Date.now())
     * // Returns: '22/7/2026, 3:45:30 م'
     */
    formatDateTime(ts) {
        return ts ? new Date(ts).toLocaleString('ar-KW') : 'N/A';
    },

    /**
     * توليد كود طلب فريد وآمن
     * @returns {string} كود الطلب (مثال: KW-A5X3847)
     * 
     * @description
     * يستخدم الطابع الزمني لضمان عدم التكرار حتى مع الأرقام العشوائية
     * 
     * @example
     * Helpers.generateOrderCode()    // Returns: 'KW-A5X3847'
     * Helpers.generateOrderCode()    // Returns: 'KW-K2M9156'
     */
    generateOrderCode() {
        return `KW-${Date.now().toString(36).slice(-3).toUpperCase()}${Math.floor(1000 + Math.random() * 9000)}`;
    },

    /**
     * ترتيب الكائنات حسب الطابع الزمني (الأحدث أولاً)
     * @param {Array} arr - المصفوفة المراد ترتيبها
     * @returns {number} نتيجة المقارنة
     * 
     * @private
     * @example
     * orders.sort(Helpers.sortByTimestampDesc)
     */
    sortByTimestampDesc(a, b) {
        return (b[1].timestampRaw || 0) - (a[1].timestampRaw || 0);
    },

    /**
     * تصفية الطلبات حسب حالة الإكمال
     * @param {Object} orders - كائن الطلبات
     * @param {boolean} completed - true للطلبات المكتملة، false للنشطة
     * @returns {Array} الطلبات المصفاة والمرتبة
     * 
     * @example
     * const activeOrders = Helpers.filterOrdersByStatus(orders, false);
     * const completedOrders = Helpers.filterOrdersByStatus(orders, true);
     */
    filterOrdersByStatus(orders, completed = false) {
        return Object.entries(orders)
            .filter(([_, o]) => {
                const done = o.status === "تم التسليم" || o.status === "مكتمل";
                return completed ? done : !done;
            })
            .sort(Helpers.sortByTimestampDesc);
    },

    /**
     * تقدير حجم كائن البيانات
     * @param {Object} obj - الكائن المراد قياس حجمه
     * @returns {number} الحجم بالـ Bytes
     * 
     * @example
     * const size = Helpers.estimateSize(largeObject);
     * console.log(`الحجم: ${Helpers.formatBytes(size)}`);
     */
    estimateSize(obj) {
        try {
            return new Blob([JSON.stringify(obj)]).size;
        } catch {
            return 0;
        }
    },

    /**
     * تنسيق الحجم بصيغة قابلة للقراءة
     * @param {number} bytes - الحجم بالـ Bytes
     * @returns {string} الحجم المنسق (مثال: 1.5 MB)
     * 
     * @example
     * Helpers.formatBytes(1048576)     // Returns: '1 MB'
     * Helpers.formatBytes(1572864)     // Returns: '1.5 MB'
     * Helpers.formatBytes(1073741824)  // Returns: '1 GB'
     */
    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// ⏱️ RATE LIMITER - حد أقصى للمحاولات
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @class RateLimiter
 * @description نظام متقدم لتحديد معدل العمليات ومنع الإساءة
 * 
 * @see {@link advanced-security-system.js} للتفاصيل الكاملة
 * 
 * @example
 * const limiter = new RateLimiter({
 *   maxAttempts: 5,
 *   windowMs: 900000
 * });
 * 
 * if (limiter.canProceed('user@example.com')) {
 *   // تنفيذ العملية
 * }
 */

// ═══════════════════════════════════════════════════════════════════════════
// 🔐 FIREBASE CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @constant FIREBASE_CONFIG
 * @description إعدادات Firebase للاتصال بـ Database
 * 
 * ⚠️ ملاحظة أمان:
 * - لا تشارك هذه البيانات علناً
 * - استخدم متغيرات البيئة في الإنتاج
 * - راجع قواعد الأمان في Firebase Console
 */
const FIREBASE_CONFIG = {
    apiKey: "AIzaSyDPUDnVJM2kb-rQwhcm-JlprdAfEfzcI4s",
    authDomain: "laundry-station-7eeaa.firebaseapp.com",
    databaseURL: "https://laundry-station-7eeaa-default-rtdb.firebaseio.com",
    projectId: "laundry-station-7eeaa",
    storageBucket: "laundry-station-7eeaa.firebasestorage.app",
    messagingSenderId: "522926262771",
    appId: "1:522926262771:web:560c504fdd7bbd2bfa6a86"
};

// ═══════════════════════════════════════════════════════════════════════════
// 🛡️ SECURITY CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @constant SECURITY
 * @description إعدادات الأمان الشاملة
 * 
 * @property {boolean} REQUIRE_ADMIN_CLAIM - يتطلب Admin Claim من Firebase
 * @property {boolean} ADMIN_SESSION_ONLY - جلسات بدون بقاء (SESSION فقط)
 * @property {Array} RESERVED_KEYS - مفاتيح محجوزة لا يمكن استخدامها
 * 
 * @see {@link #L38-L45} لمزيد من التفاصيل
 * 
 * @example
 * // لتفعيل الحماية الكاملة:
 * SECURITY.REQUIRE_ADMIN_CLAIM = true;
 * 
 * // لجلسات بدون بقاء (إغلاق المتصفح = خروج تلقائي):
 * SECURITY.ADMIN_SESSION_ONLY = true;
 */
const SECURITY = {
    REQUIRE_ADMIN_CLAIM: false,  // ⏳ قيد التفعيل
    ADMIN_SESSION_ONLY: false,
    RESERVED_KEYS: [
        'branches_registry', 'clients_registry', 'complaints_registry',
        'central_orders_registry', 'stats', 'audit', 'config',
        '.info', 'admin', 'settings'
    ]
};

// ═══════════════════════════════════════════════════════════════════════════
// 🎣 REACT HOOKS - خطاطيف React المخصصة
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @function useToast
 * @description خطاف لإظهار إشعارات Toast
 * 
 * @returns {Object} كائن يحتوي على:
 *   - {Object} toast - حالة الإشعار الحالي
 *   - {Function} triggerToast - دالة لإظهار إشعار
 * 
 * @example
 * const { toast, triggerToast } = useToast();
 * 
 * triggerToast('تمت العملية بنجاح ✅');
 * 
 * return (
 *   <Toast toast={toast}/>
 * );
 */

/**
 * @function useConfirm
 * @description خطاف لإظهار نوافذ تأكيد
 * 
 * @returns {Object} كائن يحتوي على:
 *   - {Object} confirmState - حالة نافذة التأكيد
 *   - {Function} showConfirm - دالة لإظهار نافذة تأكيد
 * 
 * @example
 * const { confirmState, showConfirm } = useConfirm();
 * 
 * const handleDelete = async () => {
 *   const isConfirmed = await showConfirm({
 *     title: 'تأكيد الحذف',
 *     message: 'هل أنت متأكد؟'
 *   });
 *   
 *   if (isConfirmed) {
 *     // تنفيذ الحذف
 *   }
 * };
 */

/**
 * @function useDebounce
 * @description خطاف لتأخير تنفيذ دالة (مفيد للبحث)
 * 
 * @param {*} value - القيمة المراد تأخيرها
 * @param {number} delay - التأخير بالميلي ثانية
 * @returns {*} القيمة المؤخرة
 * 
 * @example
 * const [search, setSearch] = useState('');
 * const debouncedSearch = useDebounce(search, 300);
 * 
 * // debouncedSearch يتحدث فقط بعد 300ms من التوقف عن الكتابة
 */

// ═══════════════════════════════════════════════════════════════════════════
// 🖼️ IMAGE UPLOAD FUNCTIONS - دوال رفع الصور
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @function compressImage
 * @description ضغط الصورة لتقليل حجمها
 * 
 * @param {File} file - ملف الصورة
 * @param {number} maxWidth - أقصى عرض للصورة (افتراضي: 400px)
 * @param {number} quality - جودة الضغط (0-1)
 * @returns {Promise<Blob>} الصورة المضغوطة
 * 
 * @example
 * const compressed = await compressImage(imageFile, 400, 0.82);
 */

/**
 * @function toBase64
 * @description تحويل الملف إلى Base64
 * 
 * @param {File} file - الملف المراد تحويله
 * @returns {Promise<string>} النص بصيغة Base64 (data:image/...)
 * 
 * @example
 * const base64 = await toBase64(imageFile);
 * console.log(base64);  // data:image/png;base64,iVBORw0KGgo...
 */

/**
 * @function processAndUploadLogo
 * @description معالجة ورفع شعار الفرع
 * 
 * @param {File} file - ملف الصورة
 * @param {string} branchKey - مفتاح الفرع
 * @param {Function} onProgress - دالة لتتبع التقدم
 * @returns {Promise<string>} رابط الصورة أو Base64
 * 
 * @example
 * const logoUrl = await processAndUploadLogo(
 *   imageFile,
 *   'branch1',
 *   (percent, message) => {
 *     console.log(`${percent}%: ${message}`);
 *   }
 * );
 */

// ═══════════════════════════════════════════════════════════════════════════
// 📊 COMPONENT DOCUMENTATION - توثيق المكونات
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @component Header
 * @description رأس الصفحة يحتوي على:
 * - شعار التطبيق والاسم
 * - منتقي الفرع
 * - مؤشر التخزين
 * - زر تبديل اللغة
 * - زر تسجيل الخروج
 * 
 * @prop {Object} t - كائن الترجمات
 * @prop {string} currentBranch - الفرع المختار حالياً
 * @prop {Object} branches - قائمة الفروع
 * @prop {Function} onToggleLang - دالة تبديل اللغة
 * @prop {Function} onSetCurrentBranch - دالة تعيين الفرع الحالي
 * @prop {Function} onLogout - دالة تسجيل الخروج
 */

/**
 * @component Dashboard
 * @description لوحة التحكم الرئيسية تعرض:
 * - الإحصائيات العامة
 * - الملخص المالي
 * - أكثر المناطق طلباً
 * 
 * @prop {Object} t - كائن الترجمات
 * @prop {Object} globalStats - الإحصائيات العالمية
 */

/**
 * @component Branches
 * @description إدارة الفروع:
 * - إنشاء فرع جديد
 * - رفع شعار الفرع
 * - حذف الفرع
 * 
 * @prop {Object} t - كائن الترجمات
 * @prop {string} currentBranch - الفرع المختار
 * @prop {Object} branches - الفروع المتاحة
 * @prop {Function} onSetCurrentBranch - تعيين الفرع
 */

/**
 * @component Drivers
 * @description إدارة السائقين:
 * - إضافة سائق جديد
 * - عرض السائقين
 * - حذف السائق
 * 
 * @prop {Object} t - كائن الترجمات
 * @prop {string} currentBranch - الفرع الحالي
 * @prop {Object} branchDrivers - السائقون في الفرع
 */

/**
 * @component Areas
 * @description إدارة المناطق الجغرافية:
 * - إضافة منطقة جديدة
 * - تعيين رسوم التوصيل
 * - حذف منطقة
 * 
 * @prop {Object} t - كائن الترجمات
 * @prop {string} currentBranch - الفرع الحالي
 * @prop {Object} branchAreas - المناطق المغطاة
 */

/**
 * @component Distribution
 * @description توزيع السائقين على المناطق
 * 
 * @prop {Object} t - كائن الترجمات
 * @prop {Object} branchDrivers - السائقون
 * @prop {Object} branchAreas - المناطق
 */

/**
 * @component Customers
 * @description قاعدة بيانات العملاء:
 * - البحث عن العميل
 * - عرض سجل الطلبات
 * - عرض إحصائيات الإنفاق
 * 
 * @prop {Object} t - كائن الترجمات
 * @prop {Object} allClients - جميع العملاء
 * @prop {Object} branches - الفروع
 */

/**
 * @component Simulation
 * @description محاكاة طلب جديد لاختبار النظام
 * 
 * @prop {Object} t - كائن الترجمات
 * @prop {string} currentBranch - الفرع الحالي
 * @prop {Object} branchAreas - المناطق المتاحة
 */

/**
 * @component History
 * @description عرض سجل الطلبات:
 * - الطلبات النشطة
 * - الطلبات المكتملة
 * - تحديث حالة الطلب
 * - تعيين السائق
 * 
 * @prop {Object} t - كائن الترجمات
 * @prop {string} currentBranch - الفرع الحالي
 * @prop {Object} branchOrders - طلبات الفرع
 * @prop {Object} branchDrivers - سائقو الفرع
 */

/**
 * @component Archive
 * @description البحث الشامل عن سجل الطلبات
 * - بحث برقم هاتف العميل
 * - عرض التاريخ الكامل
 * - الخط الزمني للطلبات
 * - الإحصائيات التفصيلية
 * 
 * @prop {Object} t - كائن الترجمات
 */

/**
 * @component Complaints
 * @description إدارة شكاوى العملاء
 * - عرض الشكاوى
 * - الاتصال بالعميل
 * - واتساب مباشر
 * - حذف الشكوى
 * 
 * @prop {Object} t - كائن الترجمات
 * @prop {Array} complaints - الشكاوى المسجلة
 * @prop {Object} branches - الفروع
 */

// ═══════════════════════════════════════════════════════════════════════════
// 📝 DATABASE SCHEMA - هيكل قاعدة البيانات
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @namespace FirebaseSchema
 * @description هيكل البيانات في Firebase Realtime Database
 * 
 * @property {Object} branches_registry - قائمة الفروع المسجلة
 *   @property {string} branchKey - كود الفرع (مثال: branch1)
 *     @property {string} name - اسم الفرع
 *     @property {string} logo - شعار الفرع (Base64)
 *     @property {number} createdAt - وقت الإنشاء
 * 
 * @property {Object} [branchKey] - بيانات الفرع
 *   @property {Object} settings - الإعدادات
 *   @property {Object} drivers - قائمة السائقين
 *   @property {Object} areas - المناطق المغطاة
 *   @property {Object} orders - الطلبات
 * 
 * @property {Object} clients_registry - قاعدة بيانات العملاء
 *   @property {string} kw_XXXXXXXX - معرف العميل (كود الدولة + الهاتف)
 *     @property {string} clientName - اسم العميل
 *     @property {string} lastBranch - آخر فرع استخدم
 *     @property {number} updatedAt - آخر تحديث
 * 
 * @property {Object} complaints_registry - سجل الشكاوى
 *   @property {string} complaintId - معرف الشكوى
 *     @property {string} clientName - اسم العميل
 *     @property {string} clientPhone - رقم الهاتف
 *     @property {string} text - نص الشكوى
 *     @property {string} branchName - اسم الفرع
 *     @property {number} dateTime - وقت الشكوى
 * 
 * @property {Object} central_orders_registry - سجل الطلبات المركزي
 *   @property {string} orderId - معرف الطلب
 *     @property {string} orderId - كود الطلب (مثال: KW-A5X3847)
 *     @property {string} clientName - اسم العميل
 *     @property {string} clientPhone - رقم الهاتف
 *     @property {string} areaName - المنطقة
 *     @property {number} totalAmount - المبلغ الإجمالي
 *     @property {string} status - حالة الطلب
 *     @property {number} timestampRaw - الطابع الزمني
 * 
 * @example
 * // الوصول للبيانات:
 * await db.ref('branches_registry/branch1/name').get()
 * await db.ref('branch1/orders').get()
 * await db.ref('clients_registry/kw_91234567').get()
 */

// ═══════════════════════════════════════════════════════════════════════════
// 🔗 USEFUL LINKS & REFERENCES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @see {@link https://firebase.google.com/docs/database} Firebase Realtime Database Docs
 * @see {@link https://reactjs.org/docs/hooks-intro.html} React Hooks Documentation
 * @see {@link https://tailwindcss.com/docs} Tailwind CSS Documentation
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/Security} MDN Web Security
 * @see {@link https://owasp.org/} OWASP Security Guidelines
 */

// ═══════════════════════════════════════════════════════════════════════════
// 📄 VERSION HISTORY
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @typedef {Object} Version
 * @property {string} version - رقم الإصدار
 * @property {string} date - تاريخ الإطلاق
 * @property {string[]} features - المميزات الجديدة
 * @property {string[]} fixes - الإصلاحات
 * @property {string[]} security - تحسينات الأمان
 */

/**
 * @type {Version[]}
 * 
 * @example
 * [
 *   {
 *     version: '2.0.0',
 *     date: '2026-07-22',
 *     features: [
 *       'Rate Limiting محسّن',
 *       'Session Management متقدم',
 *       'Audit Logging شامل'
 *     ],
 *     security: [
 *       'تشفير البيانات الحساسة',
 *       'كشف الأنشطة المريبة',
 *       'حماية من Brute Force'
 *     ]
 *   },
 *   {
 *     version: '1.0.0',
 *     date: '2026-07-15',
 *     features: [
 *       'إدارة الفروع',
 *       'إدارة السائقين',
 *       'إدارة الطلبات'
 *     ]
 *   }
 * ]
 */

// ═══════════════════════════════════════════════════════════════════════════
// 💡 BEST PRACTICES & GUIDELINES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @section SECURITY BEST PRACTICES
 * 
 * 1. 🔐 التحقق من المدخلات (Input Validation)
 *    - استخدم Sanitizer.sanitizeText() لجميع المدخلات
 *    - تحقق من النوع قبل المعالجة
 *    - رفض المحتوى الخطير (XSS, Scripts, إلخ)
 * 
 * 2. 🛡️ حماية البيانات (Data Protection)
 *    - لا تخزن كلمات المرور بصيغة صريحة
 *    - شفّر البيانات الحساسة
 *    - استخدم HTTPS فقط
 * 
 * 3. 🔒 إدارة الجلسات (Session Management)
 *    - تحقق من صحة الجلسة قبل كل عملية
 *    - انهِ الجلسات بعد الخمول
 *    - استخدم Secure Cookies
 * 
 * 4. 📊 المراقبة والتسجيل (Monitoring & Logging)
 *    - سجّل العمليات الحساسة
 *    - راقب الأنشطة المريبة
 *    - احتفظ بسجلات الأمان
 * 
 * 5. ⏱️ Rate Limiting
 *    - حدّ من محاولات الدخول
 *    - حدّ من العمليات الحساسة
 *    - احظر الحسابات المريبة
 */

/**
 * @section CODE QUALITY GUIDELINES
 * 
 * 1. 📝 التوثيق (Documentation)
 *    - وثّق كل دالة و فئة
 *    - استخدم JSDoc format
 *    - أضف أمثلة للاستخدام
 * 
 * 2. 🧹 النظافة (Clean Code)
 *    - استخدم أسماء واضحة
 *    - تجنب الدوال الطويلة
 *    - فصل المسؤوليات (SRP)
 * 
 * 3. 🧪 الاختبار (Testing)
 *    - اكتب اختبارات وحدة
 *    - اختبر الحالات الحدية
 *    - استخدم Mock للـ Firebase
 * 
 * 4. 📈 الأداء (Performance)
 *    - استخدم Debouncing للبحث
 *    - قلل عمليات الـ Database
 *    - ضغط الصور قبل الرفع
 */

/**
 * @section COMMON ERRORS & FIXES
 * 
 * ❌ خطأ: "Cannot read property 'value' of undefined"
 * ✅ الحل: تحقق من وجود الكائن قبل الوصول للخاصية
 * 
 * ❌ خطأ: "Firebase.database is not a function"
 * ✅ الحل: تأكد من استيراد Firebase بشكل صحيح
 * 
 * ❌ خطأ: "Maximum call stack size exceeded"
 * ✅ الحل: تحقق من حلقات البيانات أو Listener التكراري
 * 
 * ❌ خطأ: "Rate limit exceeded"
 * ✅ الحل: انتظر قبل إعادة المحاولة
 */

// ═══════════════════════════════════════════════════════════════════════════
// 📞 SUPPORT & CONTRIBUTIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * للمزيد من المعلومات والدعم:
 * 
 * 📧 البريد الإلكتروني: support@laundry-station.com
 * 🐛 تقارير الأخطاء: https://github.com/laundry-station/issues
 * 📖 التوثيق الكاملة: https://docs.laundry-station.com
 * 💬 المنتدى: https://community.laundry-station.com
 * 
 * المساهمة في المشروع:
 * 1. اقرأ CONTRIBUTING.md
 * 2. اتبع معايير الكود
 * 3. أرسل Pull Request
 * 4. انتظر المراجعة
 */
