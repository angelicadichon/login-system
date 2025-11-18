<?php
require __DIR__ . '/../bootstrap.php';

use Kreait\Firebase\Factory;
use Kreait\Firebase\Auth;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;

const FIREBASE_DATABASE_URL = null; // Will be loaded from .env

/**
 * Sanitize email to be used as a Firebase database key
 * Replaces invalid characters (. $ # [ ]) with safe alternatives
 */
function sanitizeEmailForFirebaseKey(string $email): string {
    return str_replace(['.', '$', '#', '[', ']'], ['_', '_', '_', '_', '_'], $email);
}

function initializeFirebaseFactory(): Factory {
    return (new Factory)
        ->withServiceAccount(__DIR__ . '/serviceAccountKey.json')
        ->withDatabaseUri($_ENV['FIREBASE_DATABASE_URL']);
}

function getAuth(): Auth {
    return initializeFirebaseFactory()->createAuth();
}

function getDatabase() {
    return initializeFirebaseFactory()->createDatabase();
}

function getNextUserId() {
    $db = getDatabase();
    $usersRef = $db->getReference('users');
    $users = $usersRef->getValue();
    $maxId = 0;
    if ($users) {
        foreach ($users as $userData) {
            if (isset($userData['id']) && is_numeric($userData['id'])) {
                $maxId = max($maxId, (int)$userData['id']);
            }
        }
    }
    return $maxId + 1;
}

/**
 * Create temporary user record for OTP verification
 */
function createTempUserForOTP(string $email): string {
    try {
        $db = getDatabase();
        $id = getNextUserId();
        $user_id = 'usr' . str_pad($id, 3, '0', STR_PAD_LEFT);

        $userData = [
            'id' => $id,
            'user_id' => $user_id,
            'email' => $email,
            'password' => '',
            'email_otps' => [
                'code_hash' => '',
                'expires_at' => 0,
                'verified' => false,
                'sent_at' => 0,
                'verified_at' => 0
            ],
            'created_at' => date('c'),
        ];

        $db->getReference('users/' . $user_id)->set($userData);
        return $user_id;
    } catch (\Throwable $e) {
        return '';
    }
}

/**
 * Get user data from database by email
 */
function getUserByEmail(string $email): array {
    try {
        $db = getDatabase();
        $usersRef = $db->getReference('users');
        $users = $usersRef->getValue();

        if ($users) {
            foreach ($users as $userId => $userData) {
                if (isset($userData['email']) && $userData['email'] === $email) {
                    return array_merge($userData, ['user_id' => $userId]);
                }
            }
        }
        return [];
    } catch (\Throwable $e) {
        return [];
    }
}

/**
 * Send OTP email directly (for forgot password)
 */
function sendOtpDirect($email, $purpose = 'verification') {
    try {
        $config = require __DIR__ . '/config.php';
        $smtp = $config['smtp'];
        
        // Create OTP and store in user's record
        $db = getDatabase();
        $userData = getUserByEmail($email);
        
        // For forgot_password and password_verification, user must exist
        if (empty($userData) && ($purpose === 'forgot_password' || $purpose === 'password_verification')) {
            return ['success' => false, 'error' => 'No account found with this email address'];
        }
        
        // If user doesn't exist and it's for verification, create temporary user
        if (empty($userData) && $purpose === 'verification') {
            $userId = createTempUserForOTP($email);
            if (empty($userId)) {
                throw new Exception('Failed to create temporary user');
            }
            $userData = getUserByEmail($email);
        }
        
        $userId = $userData['user_id'];
        $code = random_int(100000, 999999);
        $hash = password_hash((string)$code, PASSWORD_DEFAULT);
        
        // Update user's email_otps field
        $db->getReference('users/' . $userId . '/email_otps')->update([
            'code_hash' => $hash,
            'expires_at' => time() + 300,
            'verified' => false,
            'sent_at' => time(),
            'verified_at' => 0,
            'purpose' => $purpose
        ]);

        // Configure PHPMailer
        $mail = new PHPMailer(true);
        $mail->SMTPDebug = SMTP::DEBUG_OFF;
        
        $mail->isSMTP();
        $mail->Host = $smtp['host'];
        $mail->SMTPAuth = true;
        $mail->Username = $smtp['user'];
        $mail->Password = $smtp['pass'];
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = (int)$smtp['port'];
        
        $mail->setFrom($smtp['user'], 'Account Security');
        $mail->addAddress($email);
        
        if ($purpose === 'forgot_password') {
            $mail->Subject = 'Password Reset Code';
            $mail->Body = "
Hello,

You requested a password reset for your account.

Your password reset code is: $code

This code will expire in 5 minutes.

If you didn't request a password reset, please ignore this email.

Best regards,
Your App Team
            ";
        } elseif ($purpose === 'password_verification') {
            $mail->Subject = 'Password Three Attempts Verification Code';
            $mail->Body = "
Hello,

We detected 3 failed login attempts with incorrect password on your account.

Your verification code is: $code

This code will expire in 5 minutes.

Please enter this code to verify your identity and continue logging in.

If this wasn't you, please secure your account immediately.

Best regards,
Your App Team
            ";
        } else {
            $mail->Subject = 'Email Verification Code';
            $mail->Body = "
Hello,

Thank you for registering with us!

Your email verification code is: $code

This code expires in 5 minutes.

Please enter this code to complete your registration.

Best regards,
Your App Team
            ";
        }
        
        if ($mail->send()) {
            return ['success' => true];
        } else {
            return ['success' => false, 'error' => 'Failed to send email: ' . $mail->ErrorInfo];
        }
        
    } catch (Exception $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Create user in Firebase Auth and save complete record in Realtime Database.
 * Returns ['uid'=>..., 'customToken'=>...] or ['error' => 'message']
 */
function firebaseSignUp(string $email, string $password): array {
    try {
        $auth = getAuth();

        // Check if user already exists in Firebase Auth
        $existingUser = null;
        try {
            $existingUser = $auth->getUserByEmail($email);
        } catch (\Kreait\Firebase\Exception\Auth\UserNotFound $e) {
            // User does not exist, will create below
        }

        if ($existingUser) {
            // User exists, use existing UID
            $uid = $existingUser->uid;
        } else {
            // Create new user
            $createdUser = $auth->createUser([
                'email' => $email,
                'password' => $password,
                'emailVerified' => false,
            ]);
            $uid = $createdUser->uid;
        }

        $db = getDatabase();

        // Find and update existing temp user or create new one
        $userData = getUserByEmail($email);
        if (!empty($userData)) {
            // Update existing temp user by setting the full record to reorder fields
            $userId = $userData['user_id'];
            $updatedUserData = [
                'id' => $userData['id'],
                'user_id' => $userId,
                'firebase_uid' => $uid,
                'email' => $email,
                'password' => password_hash($password, PASSWORD_DEFAULT),
                'created_at' => $userData['created_at']
            ];
            $db->getReference('users/' . $userId)->set($updatedUserData);
        } else {
            // Create new user record
            $id = getNextUserId();
            $user_id = 'usr' . str_pad($id, 3, '0', STR_PAD_LEFT);
            $userData = [
                'id' => $id,
                'user_id' => $user_id,
                'firebase_uid' => $uid,
                'email' => $email,
                'password' => password_hash($password, PASSWORD_DEFAULT),
                'created_at' => date('c')
            ];
            $db->getReference('users/' . $user_id)->set($userData);
        }

        $customToken = $auth->createCustomToken($uid);
        return ['uid' => $uid, 'customToken' => $customToken->toString()];
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    }
}

/**
 * Sign in with email/password using Firebase Auth REST API.
 * Returns decoded JSON (idToken, refreshToken, localId(uid), expiresIn) or ['error'=>'...']
 */
function firebaseSignIn(string $email, string $password): array {
    $url = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=' . $_ENV['FIREBASE_API_KEY'];
    $payload = json_encode([
        'email' => $email,
        'password' => $password,
        'returnSecureToken' => true,
    ]);

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    $result = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($result === false) {
        return ['error' => 'Curl error: ' . $curlErr];
    }

    $data = json_decode($result, true);
    if ($httpCode >= 400) {
        $msg = $data['error']['message'] ?? ($data['error'] ?? 'Unknown error');
        return ['error' => $msg];
    }

    return $data;
}

/**
 * Generate an email verification link for the given email (Admin SDK).
 * Returns link string or ['error'=>'...']
 */
function firebaseGetEmailVerificationLink(string $email): array {
    try {
        $auth = getAuth();
        $link = $auth->getEmailVerificationLink($email);
        return ['link' => $link];
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    }
}