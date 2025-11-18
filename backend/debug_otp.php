<?php
require __DIR__ . '/firebase.php';
header('Content-Type: application/json');

$email = filter_var($_GET['email'] ?? '', FILTER_SANITIZE_EMAIL);

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['error' => 'Invalid email']); exit;
}

try {
    $db = getDatabase();
    $userData = getUserByEmail($email);
    
    if (empty($userData)) {
        echo json_encode(['error' => 'User not found']); exit;
    }
    
    $otpData = $userData['email_otps'] ?? [];
    
    echo json_encode([
        'email' => $email,
        'user_id' => $userData['user_id'] ?? 'N/A',
        'has_code_hash' => !empty($otpData['code_hash']),
        'code_hash' => $otpData['code_hash'] ?? 'N/A',
        'expires_at' => $otpData['expires_at'] ?? 'N/A',
        'is_expired' => time() > ($otpData['expires_at'] ?? 0),
        'purpose' => $otpData['purpose'] ?? 'N/A',
        'verified' => $otpData['verified'] ?? false,
        'current_time' => time()
    ]);
} catch (\Throwable $e) {
    echo json_encode(['error' => $e->getMessage()]);
}
?>
