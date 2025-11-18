<?php
session_start();

// Clear OTP-related session data
unset($_SESSION['reset_email']);
unset($_SESSION['otp_sent_time']);

echo json_encode(['status' => 'cleared']);
?>