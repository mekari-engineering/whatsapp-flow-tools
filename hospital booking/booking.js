/**
 * WhatsApp Flow Endpoint for Hospital Booking System
 * 
 * This endpoint handles encrypted WhatsApp Flow interactions for:
 * - Patient registration (new/existing patients)
 * - Doctor appointment booking
 * - Payment method selection
 * - Booking confirmation
 * 
 * Flow: ADMISSION → REGISTRATION/PASIEN → KONFIRMASI → COMPLETE
 */

// Supports n8n code-node ($json) and server execution.
const n8nInput = globalThis.$json?.body ?? null;
const crypto = require('crypto'); 
const axios = require('axios');

// Load environment variables
require('dotenv').config();

// =============================================================================
// ENVIRONMENT VALIDATION
// =============================================================================

/** Required environment variables */
const REQUIRED_ENV_VARS = [
  'RSA_PASSPHRASE',
  'RSA_PRIVATE_KEY',
  'API_BASE_URL',
  'API_SIGNUP_ENDPOINT',
  'API_SIGNIN_ENDPOINT',
  'API_BOOKING_ENDPOINT'
];

/** Validate that all required environment variables are present */
function validateEnvironment() {
  const missing = REQUIRED_ENV_VARS.filter(envVar => !process.env[envVar]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

// Validate environment on startup
validateEnvironment();

// =============================================================================
// CONFIGURATION CONSTANTS
// =============================================================================

/** RSA decryption passphrase for encrypted AES key */
const PASSPHRASE = process.env.RSA_PASSPHRASE;

/** RSA private key for decrypting the AES key from WhatsApp */
const PRIVATE_KEY = process.env.RSA_PRIVATE_KEY;

/** API endpoints for external services */
const API_ENDPOINTS = {
  SIGNUP: `${process.env.API_BASE_URL}${process.env.API_SIGNUP_ENDPOINT}`,
  SIGN_IN: `${process.env.API_BASE_URL}${process.env.API_SIGNIN_ENDPOINT}`,
  SUBMIT_BOOKING: `${process.env.API_BASE_URL}${process.env.API_BOOKING_ENDPOINT}`
};

/** Optional demo-only sign-in mock configuration */
const SIGNIN_MOCK_CONFIG = {
    enabled: String(process.env.SIGNIN_MOCK_ENABLED || 'false').toLowerCase() === 'true',
    nameOrPhone: process.env.SIGNIN_MOCK_NAME_OR_PHONE || '',
    birthDate: process.env.SIGNIN_MOCK_BIRTH_DATE || '',
    userId: process.env.SIGNIN_MOCK_USER_ID || 'demo-user-001'
};

/** Indonesian month names for date formatting */
const INDONESIAN_MONTHS = [
  "Januari", "Februari", "Maret", "April", "Mei", "Juni",
  "Juli", "Agustus", "September", "Oktober", "November", "Desember"
];

// =============================================================================
// CUSTOM ERROR CLASSES
// =============================================================================

/**
 * Custom error class for Flow endpoint exceptions
 * @param {number} statusCode - HTTP status code
 * @param {string} message - Error message
 */
class FlowEndpointException extends Error {
  constructor(statusCode, message) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
  }
}

// =============================================================================
// ENCRYPTION/DECRYPTION UTILITIES
// =============================================================================

/**
 * Decrypts the incoming WhatsApp Flow request
 * 
 * WhatsApp sends encrypted data using hybrid encryption:
 * 1. AES key is encrypted with RSA public key
 * 2. Flow data is encrypted with AES-128-GCM
 * 
 * @param {Object} body - Request body containing encrypted data
 * @param {string} privatePem - RSA private key in PEM format
 * @param {string} passphrase - Private key passphrase
 * @returns {Object} Decrypted data and encryption keys
 */
function decryptRequest(body, privatePem, passphrase) {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

    if (!encrypted_aes_key || !encrypted_flow_data || !initial_vector) {
        throw new FlowEndpointException(
            400,
            "Invalid request payload. Required fields: encrypted_aes_key, encrypted_flow_data, initial_vector."
        );
    }

  // Step 1: Decrypt the AES key using RSA private key
    let privateKey;
    try {
        privateKey = crypto.createPrivateKey({ key: privatePem, passphrase });
    } catch (error) {
        throw new FlowEndpointException(
            421,
            "Failed to load private key. Please verify RSA_PRIVATE_KEY and RSA_PASSPHRASE."
        );
    }
  let decryptedAesKey = null;

  try {
    decryptedAesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encrypted_aes_key, "base64")
    );
  } catch (error) {
    throw new FlowEndpointException(
      421,
      "Failed to decrypt the request. Please verify your private key."
    );
  }

  // Step 2: Decrypt the flow data using AES-128-GCM
  const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
  const initialVectorBuffer = Buffer.from(initial_vector, "base64");

  const TAG_LENGTH = 16;
  const encrypted_flow_data_body = flowDataBuffer.subarray(0, -TAG_LENGTH);
  const encrypted_flow_data_tag = flowDataBuffer.subarray(-TAG_LENGTH);

  const decipher = crypto.createDecipheriv(
    "aes-128-gcm",
    decryptedAesKey,
    initialVectorBuffer
  );
  decipher.setAuthTag(encrypted_flow_data_tag);

  const decryptedJSONString = Buffer.concat([
    decipher.update(encrypted_flow_data_body),
    decipher.final(),
  ]).toString("utf-8");

  return {
    decryptedBody: JSON.parse(decryptedJSONString),
    aesKeyBuffer: decryptedAesKey,
    initialVectorBuffer,
  };
}

/**
 * Encrypts the response back to WhatsApp using the same AES key
 * 
 * @param {Object} response - Response object to encrypt
 * @param {Buffer} aesKeyBuffer - AES key from decryption
 * @param {Buffer} initialVectorBuffer - IV from decryption
 * @returns {string} Base64 encoded encrypted response
 */
function encryptResponse(response, aesKeyBuffer, initialVectorBuffer) {
  // WhatsApp requires flipping the IV bits for response encryption
  const flipped_iv = [];
  for (const pair of initialVectorBuffer.entries()) {
    flipped_iv.push(~pair[1]);
  }

  const cipher = crypto.createCipheriv(
    "aes-128-gcm",
    aesKeyBuffer,
    Buffer.from(flipped_iv)
  );

  return Buffer.concat([
    cipher.update(JSON.stringify(response), "utf-8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]).toString("base64");
}

/**
 * Builds safe diagnostics for private/public key pair readiness.
 * Never returns key material or passphrase.
 * @returns {{keyLoadable: boolean, publicKeyFingerprintSha256: string|null, error: string|null}}
 */
function getCryptoDiagnostics() {
    try {
        const privateKey = crypto.createPrivateKey({ key: PRIVATE_KEY, passphrase: PASSPHRASE });
        const publicKey = crypto.createPublicKey(privateKey);
        const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
        const fingerprint = crypto
            .createHash('sha256')
            .update(publicKeyDer)
            .digest('hex');

        return {
            keyLoadable: true,
            publicKeyFingerprintSha256: fingerprint,
            error: null
        };
    } catch (error) {
        return {
            keyLoadable: false,
            publicKeyFingerprintSha256: null,
            error: error?.message || 'Unknown key error'
        };
    }
}

// =============================================================================
// DATA FILTERING AND UTILITY FUNCTIONS
// =============================================================================

/**
 * Efficiently filters array of objects to only include specified keys
 * @param {Array} array - Array of objects to filter
 * @param {Array} allowedKeys - Keys to keep in each object
 * @returns {Array} Filtered array with only allowed keys
 */
function pickFieldsFromArrayHelper(array, allowedKeys) {
  if (!Array.isArray(array)) return [];
  
  // Use Set for faster key lookup
  const keySet = new Set(allowedKeys);
  
  return array.map((item) => {
    const filtered = {};
    for (const key in item) {
      if (keySet.has(key)) {
        filtered[key] = item[key];
      }
    }
    return filtered;
  });
}

/**
 * Gets available doctors for a specific clinic
 * @param {string|null} klinikId - Clinic ID to filter by
 * @returns {Array} List of doctors for the clinic
 */
function getDokterOptionsForKlinik(klinikId) {
  if (klinikId == null) return DOKTER_LIST_MIN;
  const key = String(klinikId);
  return DOKTER_BY_KLINIK[key] || [];
}

/**
 * Gets available dates for a specific doctor
 * @param {string|null} dokterId - Doctor ID to filter by
 * @returns {Array} List of available dates
 */
function getDateOptionsForDokterHelper(dokterId) {
  if (dokterId == null) return [];
  
  const idStr = String(dokterId);
  
  // Check if dates are in ADMISSION_OPTIONS first
  if (Array.isArray(ADMISSION_OPTIONS.date) && ADMISSION_OPTIONS.date.length > 0) {
    const first = ADMISSION_OPTIONS.date[0];
    if (first && Object.prototype.hasOwnProperty.call(first, 'dokter_id')) {
      return ADMISSION_OPTIONS.date
        .filter((d) => String(d.dokter_id) === idStr)
        .map((d) => ({ id: d.id, title: d.title }));
    }
  }
  
  // Fallback to generated dates
  return (DATES_BY_DOKTER_ID[idStr] || []).map((d) => ({ id: d.id, title: d.title }));
}

/**
 * Gets available time slots for a doctor on a specific date
 * @param {string|null} dokterId - Doctor ID
 * @param {string|null} dateId - Date ID
 * @returns {Array} List of available time slots
 */
function getTimeOptionsForDokterAndDateHelper(dokterId, dateId) {
  if (dokterId == null || dateId == null) return [];
  
  // For now, return all time options since there's no specific filtering logic needed
  // In the future, you could add filtering based on dokter availability for specific dates
  return ADMISSION_OPTIONS.time.map((t) => ({ 
    id: t.id, 
    title: t.title, 
    enabled: t.enabled ?? true 
  }));
}

/**
 * Gets patient type options
 * @returns {Array} List of patient types
 */
function getTipePasienOptionsHelper() {
  return ADMISSION_OPTIONS.tipe_pasien.map((t) => ({ id: t.id, title: t.title }));
}

/**
 * Gets payment method options
 * @returns {Array} List of payment methods
 */
function getPembayaranOptionsHelper() {
  return ADMISSION_OPTIONS.pembayaran.map((p) => ({ id: p.id, title: p.title }));
}

// =============================================================================
// STATIC DATA CONFIGURATIONS
// =============================================================================

/**
 * Main admission options for the booking flow
 * Contains all available clinics, doctors, dates, times, patient types, and payment methods
 */
const ADMISSION_OPTIONS = Object.freeze({
    klinik: [
      { "id": "Anak-Imunisasi Anak", "title": "Anak - Imunisasi Anak" },
      { "id": "Anak-Pediatric", "title": "Anak / Pediatric" },
      { "id": "Anestesi-Anaesthesiology", "title": "Anestesi / Anaesthesiology" },
      { "id": "Bedah-Anak", "title": "Bedah Anak" },
      { "id": "Bedah-Digestif", "title": "Bedah Digestif" },
      { "id": "Bedah-Onkologi", "title": "Bedah Onkologi" },
      { "id": "Bedah-Plastik", "title": "Bedah Plastik" },
      { "id": "Bedah-Saraf", "title": "Bedah Saraf" },
      { "id": "Bedah Saraf Kortek", "title": "Bedah Saraf Kortek" },
      { "id": "Bedah Thorax Vaskuler", "title": "Bedah Thorax Vaskuler" },
      { "id": "Bedah Umum-Surgery", "title": "Bedah Umum / Surgery" },
      { "id": "Dermatologi-Anak", "title": "Dermatologi Anak" },
      { "id": "Gigi-Dentistry", "title": "Gigi / Dentistry" },
      { "id": "Gigi-Anak", "title": "Gigi Anak" },
      { "id": "Gigi-Spesialis", "title": "Gigi Spesialis" }
    ],
    /** Available doctors with their clinic associations */
    dokter: [
        { "id": "dr. Sarah Wijaya, M.Sc, Sp.A", "title": "dr. Sarah Wijaya, M.Sc, Sp.A", "klinik_id": "Anak-Imunisasi Anak" , "image": ""},
        { "id": "dr. Maria Indriati, Sp.An-KIC", "title": "dr. Maria Indriati, Sp.An-KIC", "klinik_id": "Anak-Pediatric" , "image": ""},
        { "id": "Ahmad Prasetyo, S.ST., RD", "title": "Ahmad Prasetyo, S.ST., RD", "klinik_id": "Anestesi-Anaesthesiology" , "image": ""},
        { "id": "dr. Budi Santoso, Sp.JP", "title": "dr. Budi Santoso, Sp.JP", "klinik_id": "Bedah-Anak" , "image": ""}
    ],
    /** Available appointment dates mapped to specific doctors */
    date: [
        { "id": "2025-09-20", "title": "20 September 2025", "dokter_id": "dr. Sarah Wijaya, M.Sc, Sp.A" },
        { "id": "2025-09-21", "title": "21 September 2025", "dokter_id": "dr. Sarah Wijaya, M.Sc, Sp.A" },
        { "id": "2025-09-22", "title": "22 September 2025", "dokter_id": "dr. Sarah Wijaya, M.Sc, Sp.A" },
        { "id": "2025-09-23", "title": "23 September 2025", "dokter_id": "dr. Maria Indriati, Sp.An-KIC" },
        { "id": "2025-09-24", "title": "24 September 2025", "dokter_id": "dr. Maria Indriati, Sp.An-KIC" },
        { "id": "2025-09-25", "title": "25 September 2025", "dokter_id": "Ahmad Prasetyo, S.ST., RD" },
        { "id": "2025-09-19", "title": "19 September 2025", "dokter_id": "Ahmad Prasetyo, S.ST., RD" },
        { "id": "2025-09-20", "title": "20 September 2025", "dokter_id": "Ahmad Prasetyo, S.ST., RD" },
        { "id": "2025-09-21", "title": "21 September 2025", "dokter_id": "Ahmad Prasetyo, S.ST., RD" },
        { "id": "2025-09-24", "title": "24 September 2025", "dokter_id": "dr. Budi Santoso, Sp.JP" },
        { "id": "2025-09-25", "title": "25 September 2025", "dokter_id": "dr. Budi Santoso, Sp.JP" },
        { "id": "2025-09-27", "title": "27 September 2025", "dokter_id": "dr. Budi Santoso, Sp.JP" }
    ],
    /** Available appointment time slots */
    time: [
        { "id": "10:30", "title": "10:30" },
        { "id": "11:00", "title": "11:00", "enabled": false },
        { "id": "11:30", "title": "11:30" },
        { "id": "12:00", "title": "12:00", "enabled": false },
        { "id": "12:30", "title": "12:30" }
    ],
    /** Patient type options (new/existing) */
    tipe_pasien: [
        { "id": "Pasien Baru", "title": "Pasien Baru" },
        { "id": "Pasien Lama", "title": "Pasien Lama" }
    ],
    /** Payment method options */
    pembayaran: [
        { "id": "Pribadi", "title": "Pribadi" },
        { "id": "Asuransi", "title": "Asuransi" }
    ]
});

/**
 * Registration form options for new patients
 */
const REGISTRATION_OPTIONS = Object.freeze({
    /** ID card type options */
    tipe_kartu: [
        { "id": "KTP", "title": "KTP" },
        { "id": "KIA", "title": "KIA" },
        { "id": "KK", "title": "KK" },
        { "id": "Passport", "title": "Passport" }
    ],
    /** Gender options */
    jenis_kelamin: [
        { "id": "Laki-Laki", "title": "Laki-Laki" },
        { "id": "Perempuan", "title": "Perempuan" }
    ]
});

// =============================================================================
// DERIVED DATA STRUCTURES (Pre-computed for efficiency)
// =============================================================================

/** Minimal doctor list (id and title only) for initial display */
const DOKTER_LIST_MIN = Object.freeze(
    pickFieldsFromArrayHelper(ADMISSION_OPTIONS.dokter, ["id", "title"])
);

/** Doctors grouped by clinic ID for efficient lookup */
const DOKTER_BY_KLINIK = Object.freeze(
    ADMISSION_OPTIONS.dokter.reduce((acc, dokter) => {
        const key = String(dokter.klinik_id);
        if (!acc[key]) acc[key] = [];
        acc[key].push({ id: dokter.id, title: dokter.title });
        return acc;
    }, {})
);

// =============================================================================
// DATE GENERATION UTILITIES
// =============================================================================

/**
 * Formats a Date object to YYYY-MM-DD string
 * @param {Date} date - Date to format
 * @returns {string} Formatted date string
 */
function formatDateIdHelper(date) {
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, "0");
    const d = String(date.getDate()).padStart(2, "0");
    return `${y}-${m}-${d}`;
}

/**
 * Formats a Date object to Indonesian date format
 * @param {Date} date - Date to format
 * @returns {string} Indonesian formatted date string
 */
function formatDateTitleHelper(date) {
    const d = String(date.getDate()).padStart(2, "0");
    const monthName = INDONESIAN_MONTHS[date.getMonth()];
    const y = date.getFullYear();
    return `${d} ${monthName} ${y}`;
}

/**
 * Generates a random integer between min and max (inclusive)
 * @param {number} minInclusive - Minimum value
 * @param {number} maxInclusive - Maximum value
 * @returns {number} Random integer
 */
function randomIntHelper(minInclusive, maxInclusive) {
    return Math.floor(Math.random() * (maxInclusive - minInclusive + 1)) + minInclusive;
}

/**
 * Generates 2-3 random future dates for a doctor's availability
 * @param {string} dokterId - Doctor ID
 * @returns {Array} Array of date objects with id, title, and dokter_id
 */
function generateRandomDatesForDokterHelper(dokterId) {
    const count = randomIntHelper(2, 3);
    const usedDays = new Set();
    const result = [];
    
    for (let i = 0; i < count; i += 1) {
        let dayOffset;
        do {
            dayOffset = randomIntHelper(1, 30); // 1-30 days from today
        } while (usedDays.has(dayOffset));
        usedDays.add(dayOffset);

        const date = new Date();
        date.setDate(date.getDate() + dayOffset);

        result.push({
            id: formatDateIdHelper(date),
            title: formatDateTitleHelper(date),
            dokter_id: String(dokterId),
        });
    }

    // Sort ascending by id (YYYY-MM-DD) for stable order
    result.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return Object.freeze(result);
}

/** Pre-computed dates for each doctor (for performance) */
const DATES_BY_DOKTER_ID = Object.freeze(
    ADMISSION_OPTIONS.dokter.reduce((acc, dokter) => {
        acc[String(dokter.id)] = generateRandomDatesForDokterHelper(dokter.id);
        return acc;
    }, {})
);

// =============================================================================
// SCREEN RESPONSE TEMPLATES
// =============================================================================

/**
 * Predefined screen responses for WhatsApp Flow navigation
 * Each screen represents a step in the booking process
 */

const SCREEN_RESPONSES = Object.freeze({
    /** Initial admission screen with clinic/doctor/date/time selection */
    ADMISSION: {
        "screen": "ADMISSION",
        "data": {
            ...ADMISSION_OPTIONS,
            "is_dokter_enabled": true,
            "is_date_enabled": true,
            "is_time_enabled": true
        }
    },
    /** Registration form for new patients */
    REGISTRATION: {
      "screen": "REGISTRATION",
      "data": {
        ...REGISTRATION_OPTIONS
      }
    },
    /** Sign-in form for existing patients */
    PASIEN: {
        "screen": "PASIEN",
        "data": {
          "nama": "Example",
          "tanggal_lahir": "Example",
          "tempat_lahir": "Example",
          "tipe_kartu": "Example",
          "nomor_kartu": "Example",
          "jenis_kelamin": "Example",
          "klinik": "Example",
          "dokter": "Example",
          "date": "Example",
          "time": "Example",
          "tipe_pasien": "Example",
          "pembayaran": "Example"
        }
    },
    /** Booking confirmation screen */
    KONFIRMASI: {
      "screen": "KONFIRMASI",
      "data": {}
    },
    /** Final success screen with booking completion */
    SUCCESS: {
        "screen": "SUCCESS",
        "data": {
            "extension_message_response": {
                "params": {
                    "flow_token": "REPLACE_FLOW_TOKEN",
                    "some_param_name": "PASS_CUSTOM_VALUE"
                }
            }
        }
    },
});

// =============================================================================
// API HELPER FUNCTIONS
// =============================================================================

/**
 * Makes an API call with error handling and consistent structure
 * @param {string} url - API endpoint URL
 * @param {Object} payload - Data to send
 * @returns {Promise<Object>} API response or error
 */
async function makeApiCall(url, payload) {
    const config = {
        method: 'post',
        maxBodyLength: Infinity,
        url: url,
        headers: { 
            'Content-Type': 'application/json'
        },
        data: JSON.stringify(payload)
    };
    
    try {
        const response = await axios.request(config);
        return {
            success: response.status === 200,
            data: response.data,
            status: response.status
        };
    } catch (error) {
        console.error('API call failed:', error);
        return {
            success: false,
            error: error.response?.data?.error_message || 'Network error occurred',
            status: error.response?.status || 500
        };
    }
}

/**
 * Handles patient registration API call
 * @param {Object} registrationData - Registration form data
 * @returns {Promise<Object>} Registration result
 */
async function handleRegistration(registrationData) {
    const payload = {
        trigger: 'submit_registration',
        nama_lengkap: registrationData.nama_lengkap,
        tanggal_lahir: registrationData.tanggal_lahir,
        tempat_lahir: registrationData.tempat_lahir,
        tipe_kartu: registrationData.tipe_kartu,
        nomor_kartu: registrationData.nomor_kartu,
        jenis_kelamin: registrationData.jenis_kelamin
    };
    
    return await makeApiCall(API_ENDPOINTS.SIGNUP, payload);
}

/**
 * Handles patient sign-in API call
 * @param {Object} signInData - Sign-in form data
 * @returns {Promise<Object>} Sign-in result
 */
async function handleSignIn(signInData) {
    if (
        SIGNIN_MOCK_CONFIG.enabled &&
        String(signInData.pasien_nama_or_telp || '').trim() === SIGNIN_MOCK_CONFIG.nameOrPhone &&
        String(signInData.pasien_tanggal_lahir || '').trim() === SIGNIN_MOCK_CONFIG.birthDate
    ) {
        return {
            success: true,
            status: 200,
            data: {
                user_id: SIGNIN_MOCK_CONFIG.userId,
                mocked: true
            }
        };
    }

    const payload = {
        trigger: 'sign_in',
        pasien_nama_or_telp: signInData.pasien_nama_or_telp,
        pasien_tanggal_lahir: signInData.pasien_tanggal_lahir
    };
    
    return await makeApiCall(API_ENDPOINTS.SIGN_IN, payload);
}

/**
 * Handles booking submission API call
 * @param {Object} bookingData - Complete booking data
 * @returns {Promise<Object>} Booking result
 */
async function handleBookingSubmission(bookingData) {
    const payload = {
        trigger: 'submit_booking',
        ...bookingData
    };
    
    return await makeApiCall(API_ENDPOINTS.SUBMIT_BOOKING, payload);
}

// =============================================================================
// MAIN SCREEN NAVIGATION LOGIC
// =============================================================================


/**
 * Main function to determine the next screen based on current state and user input
 * Handles the flow: INIT → ADMISSION → REGISTRATION/PASIEN → KONFIRMASI → COMPLETE
 * 
 * @param {Object} decryptedBody - Decrypted request data from WhatsApp
 * @returns {Promise<Object>} Next screen response
 */
async function getNextScreen(decryptedBody) {
  const { screen, data, action, flow_token } = decryptedBody;
  const currentScreen = screen;

  // Handle health check
  if (action === "ping") {
    return { data: { status: "active" } };
  }

  // Handle client error notifications
  if (data?.error) {
    console.warn("⚠️ Client error received:", data);
    return { data: { acknowledged: true } };
  }

  // Handle initial flow start → show ADMISSION screen
  if (action === "INIT") {
    return getInitialAdmissionScreen(data);
  }
  
  // Handle data exchange actions
  if (action === "data_exchange") {
    return await handleDataExchange(currentScreen, data, flow_token);
  }

  console.error("🚨 Unhandled request:", decryptedBody);
  throw new Error("Unhandled endpoint request.");
}

/**
 * Returns the initial admission screen with empty or filtered data
 * @param {Object} data - Initial data (may contain pre-selected clinic)
 * @returns {Object} Initial admission screen response
 */
function getInitialAdmissionScreen(data) {
    const dokterListForInit = getDokterOptionsForKlinik(data?.klinik);
    return {
      ...SCREEN_RESPONSES.ADMISSION,
      data: {
        ...SCREEN_RESPONSES.ADMISSION.data,
        dokter: dokterListForInit,
        date: [],
        is_dokter_enabled: false,
        is_date_enabled: false,
        is_time_enabled: false,
      },
    };
}

/**
 * Handles data exchange logic and screen transitions
 * @param {string} currentScreen - Current screen name
 * @param {Object} data - Form data from user
 * @param {string} flow_token - Flow token for session
 * @returns {Promise<Object>} Next screen response
 */
async function handleDataExchange(currentScreen, data, flow_token) {
    // Check if all required admission fields are selected
    const admissionComplete = checkAdmissionComplete(data);
    
    // Handle navigation after admission completion
    if (admissionComplete && data.trigger === "continue_selected") {
        return handleAdmissionCompletion(data);
    }
    
    // Route to specific screen handlers
    switch (currentScreen?.toUpperCase()) {
        case "ADMISSION":
            return handleAdmissionScreen(data);
        case "REGISTRATION": 
            return await handleRegistrationScreen(data);
        case "PASIEN":
            return await handlePasienScreen(data);
        case "KONFIRMASI":
            return await handleKonfirmasiScreen(data);
        case "SUCCESS":
            return {
                ...SCREEN_RESPONSES.SUCCESS,
                data: {
                    extension_message_response: {
                        params: { flow_token },
                    },
                },
            };
        default:
            return { 
                response: 'default', 
                screen: currentScreen, 
                decryptedBody: { screen: currentScreen, data } 
            };
    }
}

/**
 * Checks if all required admission fields are completed
 * @param {Object} data - Form data
 * @returns {boolean} True if admission is complete
 */
function checkAdmissionComplete(data) {
    return Boolean(
        data.klinik && 
        data.dokter && 
        data.date && 
        data.time && 
        data.tipe_pasien && 
        data.pembayaran
    );
}

/**
 * Handles navigation after admission form completion
 * @param {Object} data - Admission data
 * @returns {Object} Next screen based on patient type
 */
function handleAdmissionCompletion(data) {
    if (String(data.tipe_pasien) === "Pasien Lama") {
        return {
            screen: "PASIEN",
            data: {}
        };
    } else if (String(data.tipe_pasien) === "Pasien Baru") {
        return {
            screen: "REGISTRATION",
            data: {
                ...SCREEN_RESPONSES.REGISTRATION.data
            }
        };
    }
}

/**
 * Handles admission screen logic with dynamic field enabling
 * @param {Object} data - Current form data
 * @returns {Object} Updated admission screen
 */
function handleAdmissionScreen(data) {
    const hasKlinik = Boolean(data.klinik);
    const hasDokter = Boolean(data.dokter);
    const hasDate = Boolean(data.date);
    
    // Get options based on current selections
    const dokterOptions = getDokterOptionsForKlinik(data.klinik);
    const dokterOptionsEmpty = (!dokterOptions || dokterOptions.length === 0);
    const dateOptions = hasDokter ? getDateOptionsForDokterHelper(data.dokter) : [];
    const timeOptions = (hasDate && hasDokter) ? getTimeOptionsForDokterAndDateHelper(data.dokter, data.date) : [];
    const tipePasienOptions = getTipePasienOptionsHelper();
    const pembayaranOptions = getPembayaranOptionsHelper();
    
    // Generate error message if no doctors available
    const errorMessage = hasKlinik && dokterOptionsEmpty ? 
        "Tidak ada dokter tersedia. Silakan pilih klinik lain." : "";
    
    return {
        screen: "ADMISSION",
        data: {
            ...SCREEN_RESPONSES.ADMISSION.data,
            ...(errorMessage ? { error_message: errorMessage } : {}),
            is_dokter_enabled: hasKlinik,
            is_date_enabled: hasKlinik && hasDokter,
            is_time_enabled: hasKlinik && hasDokter && hasDate,
            dokter: dokterOptions,
            date: dateOptions,
            time: timeOptions,
            tipe_pasien: tipePasienOptions,
            pembayaran: pembayaranOptions
        },
    };
}

/**
 * Handles registration screen and form submission
 * @param {Object} data - Registration form data
 * @returns {Promise<Object>} Registration result or form
 */
async function handleRegistrationScreen(data) {
    if (data.trigger === "submit_registration") {
        const result = await handleRegistration(data);
        
        if (result.success) {
            return {
                screen: "KONFIRMASI",
                data: {
                    user_id: result.data?.user_id
                }
            };
        } else {
            return {
                screen: "REGISTRATION",
                data: {
                    ...SCREEN_RESPONSES.REGISTRATION.data,
                    error_message: result.error
                }
            };
        }
    }

    return {
        screen: "REGISTRATION",
        data: {
            ...SCREEN_RESPONSES.REGISTRATION.data
        },
    };
}

/**
 * Handles existing patient sign-in screen
 * @param {Object} data - Sign-in form data
 * @returns {Promise<Object>} Sign-in result or form
 */
async function handlePasienScreen(data) {
    if (data.trigger === "sign_in") {
        const result = await handleSignIn(data);
        
        if (result.success) {
            return {
                screen: "KONFIRMASI",
                data: {
                    user_id: result.data?.user_id
                }
            };
        } else {
            return {
                screen: "PASIEN",
                data: {
                    error_message: result.error
                }
            };
        }
    }

    return {
        screen: "PASIEN",
        data: {}
    };
}

/**
 * Handles booking confirmation and final submission
 * @param {Object} data - Complete booking data
 * @returns {Promise<Object>} Booking result
 */
async function handleKonfirmasiScreen(data) {
    if (data.trigger === "submit_booking") {
        const result = await handleBookingSubmission(data);
        
        if (result.success) {
            return {
                screen: "COMPLETE",
                data: {
                    user_id: result.data?.user_id,
                    booking_qr_code: result.data?.booking_qr_code,
                    booking_code: result.data?.booking_code,
                    nama: result.data?.nama,
                    dokter: result.data?.dokter,
                    ruang: result.data?.ruang,
                    antrian: result.data?.antrian
                }
            };
        } else {
            return {
                screen: "KONFIRMASI",
                data: {
                    error_message: result.error
                }
            };
        }
    }

    return {
        screen: "KONFIRMASI",
        data: {}
    };
}
// =============================================================================
// MAIN EXECUTION BLOCK
// =============================================================================

/**
 * Main execution function that handles the entire request-response cycle
 * 1. Decrypts the incoming WhatsApp Flow request
 * 2. Processes the request and determines the next screen
 * 3. Encrypts and returns the response
 */
async function processFlowRequest(input) {
    let decryptedRequest;

    if (!input || typeof input !== 'object') {
        return {
            code: 400,
            message: "Missing request body."
        };
    }

    // Step 1: Decrypt the incoming request
    try {
        decryptedRequest = decryptRequest(input, PRIVATE_KEY, PASSPHRASE);
    } catch (err) {
        console.error("❌ Decryption error:", err);

        if (err instanceof FlowEndpointException) {
            return { 
                code: err.statusCode,
                message: err.message 
            };
        }

        return { 
            code: 500,
            message: "Internal Server Error" 
        };
    }

    const { aesKeyBuffer, initialVectorBuffer, decryptedBody } = decryptedRequest;
    console.log("💬 Decrypted Request:", JSON.stringify(decryptedBody, null, 2));

    // Step 2: Process the request and get the screen response
    let screenResponse;
    try {
        screenResponse = await getNextScreen(decryptedBody);
        console.log("👉 Response to Encrypt:", JSON.stringify(screenResponse, null, 2));
    } catch (err) {
        console.error("❌ Screen processing error:", err);
        
        // Return error screen or fallback response
        screenResponse = {
            screen: "ERROR",
            data: {
                error_message: "Terjadi kesalahan sistem. Silakan coba lagi."
            }
        };
    }

    // Step 3: Encrypt and return the response
    try {
        const encryptedResponse = encryptResponse(screenResponse, aesKeyBuffer, initialVectorBuffer);
        
        return { 
            decryptedRequest: decryptedRequest,
            decryptedBody: decryptedBody,
            screenResponse: screenResponse,
            response: encryptedResponse
        };
    } catch (err) {
        console.error("❌ Encryption error:", err);
        return { 
            code: 500,
            message: "Failed to encrypt response" 
        };
    }
}

async function main() {
    return processFlowRequest(n8nInput);
}

// Execute only when running as a standalone Node script.
if (require.main === module) {
    main()
        .then((result) => {
            console.log(JSON.stringify(result, null, 2));
        })
        .catch((error) => {
            console.error("❌ Fatal error:", error);
            process.exitCode = 1;
        });
}

module.exports = { main, processFlowRequest, getCryptoDiagnostics };