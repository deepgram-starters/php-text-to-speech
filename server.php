<?php
/**
 * PHP Text-to-Speech Starter - Backend Server
 *
 * This is a simple PHP built-in server router that provides a text-to-speech API
 * endpoint powered by Deepgram's Text-to-Speech service. It's designed to be easily
 * modified and extended for your own projects.
 *
 * Key Features:
 * - Contract-compliant API endpoint: POST /api/text-to-speech
 * - Accepts text in body and model as query parameter
 * - Returns binary audio data (audio/mpeg)
 * - CORS enabled for frontend communication
 * - JWT session auth with Bearer token validation
 * - Pure API server (frontend served separately)
 */

require_once __DIR__ . '/vendor/autoload.php';

use Dotenv\Dotenv;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Yosymfony\Toml\Toml;

// ============================================================================
// CONFIGURATION - Customize these values for your needs
// ============================================================================

/**
 * Default text-to-speech model to use when none is specified
 * Options: "aura-2-thalia-en", "aura-2-theia-en", "aura-2-andromeda-en", etc.
 * See: https://developers.deepgram.com/docs/text-to-speech-models
 */
define('DEFAULT_MODEL', 'aura-2-thalia-en');

/**
 * Maximum allowed text length (characters)
 */
define('MAX_TEXT_LENGTH', 10000);

/**
 * JWT token expiry time in seconds (1 hour)
 */
define('JWT_EXPIRY', 3600);

// ============================================================================
// ENVIRONMENT - Load .env and validate API key
// ============================================================================

/**
 * Load environment variables from .env file if it exists.
 * Falls back to system environment variables.
 */
if (file_exists(__DIR__ . '/.env')) {
    $dotenv = Dotenv::createImmutable(__DIR__);
    $dotenv->load();
}

/**
 * Loads the Deepgram API key from environment variables.
 * Exits with helpful error if not found.
 *
 * @return string The Deepgram API key
 */
function loadApiKey(): string
{
    $apiKey = $_ENV['DEEPGRAM_API_KEY'] ?? getenv('DEEPGRAM_API_KEY') ?: '';

    if (empty($apiKey)) {
        fwrite(STDERR, "\nERROR: Deepgram API key not found!\n\n");
        fwrite(STDERR, "Please set your API key using one of these methods:\n\n");
        fwrite(STDERR, "1. Create a .env file (recommended):\n");
        fwrite(STDERR, "   DEEPGRAM_API_KEY=your_api_key_here\n\n");
        fwrite(STDERR, "2. Environment variable:\n");
        fwrite(STDERR, "   export DEEPGRAM_API_KEY=your_api_key_here\n\n");
        fwrite(STDERR, "Get your API key at: https://console.deepgram.com\n\n");
        exit(1);
    }

    return $apiKey;
}

$apiKey = loadApiKey();

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

/**
 * Session secret for signing JWTs.
 * In production, set SESSION_SECRET env var for stable tokens across restarts.
 * In development, a random secret is generated each time.
 */
$sessionSecret = $_ENV['SESSION_SECRET'] ?? getenv('SESSION_SECRET') ?: bin2hex(random_bytes(32));

/**
 * Validates JWT from Authorization: Bearer header.
 * Returns decoded payload on success, sends 401 JSON error on failure.
 *
 * @param string $sessionSecret The secret key used to verify JWTs
 * @return object|null Decoded JWT payload, or null (response already sent)
 */
function requireSession(string $sessionSecret): ?object
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

    if (empty($authHeader) || !str_starts_with($authHeader, 'Bearer ')) {
        sendJson(401, [
            'error' => [
                'type' => 'AuthenticationError',
                'code' => 'MISSING_TOKEN',
                'message' => 'Authorization header with Bearer token is required',
            ],
        ]);
        return null;
    }

    $token = substr($authHeader, 7);

    try {
        $decoded = JWT::decode($token, new Key($sessionSecret, 'HS256'));
        return $decoded;
    } catch (\Firebase\JWT\ExpiredException $e) {
        sendJson(401, [
            'error' => [
                'type' => 'AuthenticationError',
                'code' => 'INVALID_TOKEN',
                'message' => 'Session expired, please refresh the page',
            ],
        ]);
        return null;
    } catch (\Exception $e) {
        sendJson(401, [
            'error' => [
                'type' => 'AuthenticationError',
                'code' => 'INVALID_TOKEN',
                'message' => 'Invalid session token',
            ],
        ]);
        return null;
    }
}

// ============================================================================
// HELPER FUNCTIONS - Modular logic for easier understanding and testing
// ============================================================================

/**
 * Sends a JSON response with the given status code and exits.
 *
 * @param int $statusCode HTTP status code
 * @param array $data Response data to encode as JSON
 */
function sendJson(int $statusCode, array $data): void
{
    http_response_code($statusCode);
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    echo json_encode($data);
    exit;
}

/**
 * Sends CORS headers for preflight OPTIONS requests and exits.
 */
function handleCorsPreFlight(): void
{
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    http_response_code(204);
    exit;
}

/**
 * Sets CORS headers on the current response.
 */
function setCorsHeaders(): void
{
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
}

/**
 * Validates that text was provided and is a non-empty string.
 *
 * @param mixed $text Text from request body
 * @return bool True if text is valid
 */
function validateTextInput($text): bool
{
    return is_string($text) && strlen(trim($text)) > 0;
}

/**
 * Formats error responses in a consistent structure matching the contract.
 *
 * @param string $message Error message
 * @param int $statusCode HTTP status code
 * @param string $errorCode Contract error code (EMPTY_TEXT, INVALID_TEXT, TEXT_TOO_LONG, MODEL_NOT_FOUND)
 * @return array Formatted error response with statusCode and body
 */
function formatErrorResponse(string $message, int $statusCode = 500, string $errorCode = 'INVALID_TEXT'): array
{
    $type = $statusCode === 400 ? 'ValidationError' : 'GenerationError';

    return [
        'statusCode' => $statusCode,
        'body' => [
            'error' => [
                'type' => $type,
                'code' => $errorCode,
                'message' => $message,
                'details' => [
                    'originalError' => $message,
                ],
            ],
        ],
    ];
}

/**
 * Calls the Deepgram TTS API using cURL and returns the binary audio data.
 *
 * @param string $text The text to convert to speech
 * @param string $model The TTS model to use
 * @param string $apiKey The Deepgram API key
 * @return array ['success' => bool, 'data' => string|null, 'error' => string|null, 'httpCode' => int]
 */
function callDeepgramTTS(string $text, string $model, string $apiKey): array
{
    $url = 'https://api.deepgram.com/v1/speak?model=' . urlencode($model);

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode(['text' => $text]),
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'Authorization: Token ' . $apiKey,
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    if ($curlError) {
        return [
            'success' => false,
            'data' => null,
            'error' => 'Failed to connect to Deepgram API: ' . $curlError,
            'httpCode' => 0,
        ];
    }

    if ($httpCode >= 400) {
        // Try to decode error response from Deepgram
        $errorBody = json_decode($response, true);
        $errorMessage = $errorBody['err_msg'] ?? $errorBody['message'] ?? 'Deepgram API error';

        return [
            'success' => false,
            'data' => null,
            'error' => $errorMessage,
            'httpCode' => $httpCode,
        ];
    }

    return [
        'success' => true,
        'data' => $response,
        'error' => null,
        'httpCode' => $httpCode,
    ];
}

/**
 * Determines the appropriate error code based on error message content.
 *
 * @param string $errorMessage The error message to analyze
 * @param int $httpCode The HTTP status code from Deepgram
 * @return array ['statusCode' => int, 'errorCode' => string]
 */
function classifyError(string $errorMessage, int $httpCode): array
{
    $msg = strtolower($errorMessage);

    if (str_contains($msg, 'model') || str_contains($msg, 'not found')) {
        return ['statusCode' => 400, 'errorCode' => 'MODEL_NOT_FOUND'];
    }
    if (str_contains($msg, 'too long') || str_contains($msg, 'length') || str_contains($msg, 'limit') || str_contains($msg, 'exceed')) {
        return ['statusCode' => 400, 'errorCode' => 'TEXT_TOO_LONG'];
    }
    if (str_contains($msg, 'invalid') || str_contains($msg, 'malformed')) {
        return ['statusCode' => 400, 'errorCode' => 'INVALID_TEXT'];
    }
    if ($httpCode === 400) {
        return ['statusCode' => 400, 'errorCode' => 'INVALID_TEXT'];
    }

    return ['statusCode' => 500, 'errorCode' => 'INVALID_TEXT'];
}

// ============================================================================
// ROUTING - Parse request URI and dispatch to handlers
// ============================================================================

// Parse the request
$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$queryString = $_SERVER['QUERY_STRING'] ?? '';
parse_str($queryString, $queryParams);

// Handle CORS preflight for all routes
if ($method === 'OPTIONS') {
    handleCorsPreFlight();
}

// ============================================================================
// SESSION ROUTES - Auth endpoints (unprotected)
// ============================================================================

/**
 * GET /api/session - Issues a signed JWT for session authentication.
 */
if ($uri === '/api/session' && $method === 'GET') {
    $now = time();
    $payload = [
        'iat' => $now,
        'exp' => $now + JWT_EXPIRY,
    ];

    $token = JWT::encode($payload, $sessionSecret, 'HS256');

    sendJson(200, ['token' => $token]);
}

// ============================================================================
// METADATA ROUTE - Returns deepgram.toml metadata
// ============================================================================

/**
 * GET /api/metadata - Returns metadata about this starter application.
 * Required for standardization compliance.
 */
if ($uri === '/api/metadata' && $method === 'GET') {
    try {
        $tomlPath = __DIR__ . '/deepgram.toml';

        if (!file_exists($tomlPath)) {
            sendJson(500, [
                'error' => 'INTERNAL_SERVER_ERROR',
                'message' => 'deepgram.toml not found',
            ]);
        }

        $config = Toml::parseFile($tomlPath);

        if (!isset($config['meta'])) {
            sendJson(500, [
                'error' => 'INTERNAL_SERVER_ERROR',
                'message' => 'Missing [meta] section in deepgram.toml',
            ]);
        }

        sendJson(200, $config['meta']);
    } catch (\Exception $e) {
        error_log('Error reading metadata: ' . $e->getMessage());
        sendJson(500, [
            'error' => 'INTERNAL_SERVER_ERROR',
            'message' => 'Failed to read metadata from deepgram.toml',
        ]);
    }
}

// ============================================================================
// API ROUTES - Text-to-Speech endpoint (protected)
// ============================================================================

/**
 * POST /api/text-to-speech
 *
 * Contract-compliant text-to-speech endpoint per starter-contracts specification.
 * Accepts:
 * - Query parameter: model (optional, default "aura-2-thalia-en")
 * - Body: JSON with text field (required)
 *
 * Returns:
 * - Success (200): Binary audio data (audio/mpeg)
 * - Error (4XX/5XX): JSON error response matching contract format
 *
 * Protected by JWT session auth (requireSession).
 */
if ($uri === '/api/text-to-speech' && $method === 'POST') {
    // Validate session token
    $session = requireSession($sessionSecret);
    if ($session === null) {
        // requireSession already sent 401 response
        exit;
    }

    // Get model from query parameter
    $model = $queryParams['model'] ?? DEFAULT_MODEL;

    // Read and parse JSON body
    $rawBody = file_get_contents('php://input');
    $body = json_decode($rawBody, true);

    // Validate: body must be valid JSON
    if ($body === null && json_last_error() !== JSON_ERROR_NONE) {
        $err = formatErrorResponse('Request body must be valid JSON', 400, 'INVALID_TEXT');
        sendJson($err['statusCode'], $err['body']);
    }

    $text = $body['text'] ?? null;

    // Validate: text is required
    if ($text === null || $text === '') {
        $err = formatErrorResponse('Text parameter is required', 400, 'EMPTY_TEXT');
        sendJson($err['statusCode'], $err['body']);
    }

    // Validate: text must be a non-empty string
    if (!validateTextInput($text)) {
        $err = formatErrorResponse('Text must be a non-empty string', 400, 'EMPTY_TEXT');
        sendJson($err['statusCode'], $err['body']);
    }

    // Validate: text length limit
    if (strlen($text) > MAX_TEXT_LENGTH) {
        $err = formatErrorResponse('Text exceeds maximum length of ' . MAX_TEXT_LENGTH . ' characters', 400, 'TEXT_TOO_LONG');
        sendJson($err['statusCode'], $err['body']);
    }

    // Call Deepgram TTS API
    $result = callDeepgramTTS($text, $model, $apiKey);

    if (!$result['success']) {
        error_log('Text-to-speech error: ' . $result['error']);

        $classified = classifyError($result['error'], $result['httpCode']);
        $err = formatErrorResponse(
            $result['error'],
            $classified['statusCode'],
            $classified['errorCode']
        );
        sendJson($err['statusCode'], $err['body']);
    }

    // Return binary audio data with proper content type
    setCorsHeaders();
    header('Content-Type: audio/mpeg');
    header('Content-Length: ' . strlen($result['data']));
    http_response_code(200);
    echo $result['data'];
    exit;
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

/**
 * GET /health - Returns a simple health check response.
 */
if ($uri === '/health' && $method === 'GET') {
    sendJson(200, ['status' => 'ok']);
}

// ============================================================================
// 404 - Not Found
// ============================================================================

setCorsHeaders();
sendJson(404, [
    'error' => 'NOT_FOUND',
    'message' => 'Endpoint not found: ' . $method . ' ' . $uri,
]);
