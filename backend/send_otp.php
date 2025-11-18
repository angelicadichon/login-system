<?php
require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/firebase.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;

header('Content-Type: application/json');

// Load config
$config = require __DIR__ . '/config.php';
$smtp = $config['smtp'];

// Validate SMTP configuration
foreach (['host', 'port', 'user', 'pass'] as $key) {
    if (empty($smtp[$key])) {
        error_log("Missing SMTP config: $key");
        echo json_encode(['error' => "SMTP configuration incomplete ($key)"]); 
        exit;
    }
}

$email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
$purpose = $_POST['purpose'] ?? 'verification'; // 'verification' or 'forgot_password'

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['error' => 'Invalid email']); 
    exit;
}

try {
    // Create OTP and store in user's record
    $db = getDatabase();
    $userData = getUserByEmail($email);
    
    // If user doesn't exist and it's for verification, create temporary user
    if (empty($userData) && $purpose === 'verification') {
        $userId = createTempUserForOTP($email);
        if (empty($userId)) {
            throw new Exception('Failed to create temporary user');
        }
        $userData = getUserByEmail($email);
    }
    
    // For forgot password, user must exist
    if (empty($userData) && $purpose === 'forgot_password') {
        echo json_encode(['error' => 'No account found with this email address']); 
        exit;
    }
    
    $userId = $userData['user_id'];
    $code = random_int(100000, 999999);
    $hash = password_hash((string)$code, PASSWORD_DEFAULT);
    
    // Update user's email_otps field with purpose
    $db->getReference('users/' . $userId . '/email_otps')->update([
        'code_hash' => $hash,
        'expires_at' => time() + 300, // 5 minutes
        'verified' => false,
        'sent_at' => time(),
        'verified_at' => 0,
        'purpose' => $purpose
    ]);

    // Configure PHPMailer
    $mail = new PHPMailer(true);
    $mail->SMTPDebug = SMTP::DEBUG_CLIENT;
    $mail->Debugoutput = function($str, $level) {
        error_log("SMTP ($level): $str");
    };

    $mail->isSMTP();
    $mail->Host = $smtp['host'];
    $mail->SMTPAuth = true;
    $mail->Username = $smtp['user'];
    $mail->Password = $smtp['pass'];
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port = (int)$smtp['port'];
    
    $mail->setFrom($smtp['user'], 'Account Security');
    
    // Set email content based on purpose
    if ($purpose === 'forgot_password') {
        $mail->addAddress($email);
        $mail->Subject = 'Password Reset Code';
        $mail->Body = "

Your password reset code is: {$code}

This code will expire in 5 minutes.

For security reasons, please do not share this code with anyone.

        ";
        
        $mail->AltBody = "Your password reset code is: {$code}. This code will expire in 5 minutes. If you didn't request this, please ignore this email.";
    } else {
        $mail->addAddress($email);
        $mail->Subject = 'Email Verification Code';
        $mail->Body = "
Hello,


Your email verification code is: {$code}

This code will expire in 5 minutes.

      ";
        
        $mail->AltBody = "Your verification code is: {$code}. This code expires in 5 minutes.";
    }

    if (!$mail->send()) {
        throw new Exception('Mailer Error: ' . $mail->ErrorInfo);
    }

    echo json_encode(['ok' => true]);

} catch (\Throwable $e) {
    error_log('Send OTP error: ' . $e->getMessage());
    echo json_encode(['error' => $e->getMessage()]);
}