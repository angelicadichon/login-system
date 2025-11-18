<?php
require __DIR__ . '/firebase.php';
header('Content-Type: application/json');

$email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
$code = trim((string)($_POST['code'] ?? ''));

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $code === '') {
    echo json_encode(['error' => 'Invalid input']); exit;
}

try {
    $db = getDatabase();
    $userData = getUserByEmail($email);
    
    if (empty($userData)) {
        echo json_encode(['error' => 'User not found']); exit;
    }
    
    $userId = $userData['user_id'];
    $otpData = $userData['email_otps'] ?? [];
    
    // Debug output
    $output = [
        'email' => $email,
        'user_id' => $userId,
        'code_submitted' => $code,
        'code_length' => strlen($code),
        'stored_hash' => $otpData['code_hash'] ?? 'NOT SET',
        'has_hash' => !empty($otpData['code_hash']),
        'expires_at' => $otpData['expires_at'] ?? 'NOT SET',
        'current_time' => time(),
        'is_expired' => time() > (int)($otpData['expires_at'] ?? 0),
        'purpose_stored' => $otpData['purpose'] ?? 'NOT SET',
        'verified' => $otpData['verified'] ?? false
    ];
    
    if (empty($otpData['code_hash'])) {
        $output['result'] = 'NO OTP HASH FOUND';
    } elseif (time() > (int)$otpData['expires_at']) {
        $output['result'] = 'OTP EXPIRED';
    } else {
        $verify_result = password_verify($code, $otpData['code_hash']);
        $output['result'] = $verify_result ? 'CODE CORRECT' : 'CODE INCORRECT';
        $output['password_verify_result'] = $verify_result;
    }
    
    echo json_encode($output);
} catch (\Throwable $e) {
    echo json_encode(['error' => $e->getMessage(), 'trace' => $e->getTraceAsString()]);
}
?>
