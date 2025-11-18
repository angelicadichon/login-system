<?php
require __DIR__ . '/firebase.php';
header('Content-Type: application/json');

$email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
$code = trim((string)($_POST['code'] ?? ''));

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $code === '') {
    echo json_encode(['success' => false, 'error' => 'Invalid input']); 
    exit;
}

try {
    $db = getDatabase();
    $userData = getUserByEmail($email);
    
    if (empty($userData)) {
        echo json_encode(['success' => false, 'error' => 'User not found']); 
        exit;
    }
    
    $userId = $userData['user_id'];
    $otpData = $userData['email_otps'] ?? [];
    
    if (empty($otpData['code_hash'])) {
        echo json_encode(['success' => false, 'error' => 'No OTP requested']); 
        exit;
    }
    
    if (empty($otpData['expires_at'])) {
        echo json_encode(['success' => false, 'error' => 'OTP incomplete']); 
        exit;
    }

    // Check if expired
    if (time() > (int)$otpData['expires_at']) {
        echo json_encode(['success' => false, 'error' => 'OTP expired']); 
        exit;
    }

    // Verify the code
    if (!password_verify($code, $otpData['code_hash'])) {
        echo json_encode(['success' => false, 'error' => 'Incorrect code']); 
        exit;
    }

    // Mark as verified
    $db->getReference('users/' . $userId . '/email_otps')->update([
        'verified' => true,
        'verified_at' => time(),
    ]);

    echo json_encode(['success' => true, 'message' => 'Verification successful']);
    exit;
    
} catch (\Throwable $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    exit;
}