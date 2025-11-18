<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/firebase.php';

$error = '';
$email = '';
$password = '';
$success = '';
$showOtpField = false;
$showPasswordVerificationOtp = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle password verification OTP submit
    if (isset($_POST['action']) && $_POST['action'] === 'verify_password_otp') {
        $email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
        $otpCode = trim($_POST['passwordOtpCode'] ?? '');
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email address.';
        } elseif (empty($otpCode)) {
            $error = 'Please enter the verification code.';
        } else {
            // Verify the OTP
            $url = 'http://' . $_SERVER['HTTP_HOST'] . '/backend/verify_otp.php';
            $payload = http_build_query([
                'email' => $email, 
                'code' => $otpCode
            ]);

            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            $result = curl_exec($ch);
            curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            $response = json_decode($result, true);
            
            if (isset($response['success']) && $response['success'] === true) {
                // Clear the flag and reset email
                $showPasswordVerificationOtp = false;
                $email = '';
                
                // Reset attempts counter
                try {
                    $db = getDatabase();
                    $sanitizedEmail = sanitizeEmailForFirebaseKey($email);
                    $loginAttemptsRef = $db->getReference('login_attempts');
                    $loginAttemptsRef->getChild($sanitizedEmail)->set(0);
                } catch (\Throwable $e) {
                    // Silently ignore
                }
                
                // Show success message and redirect to login
                $success = 'Verification successful! Please log in with your email and password.';
            } else {
                $error = $response['error'] ?? 'Invalid verification code. Please try again.';
                $showPasswordVerificationOtp = true;
            }
        }
    }
    
    // Login form submit
    if (isset($_POST['action']) && $_POST['action'] === 'login') {
        $email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
        $password = $_POST['password'] ?? '';

        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password === '') {
            $error = 'Please enter a valid email and password.';
        } else {
            // Get current attempt count for this email (with error handling)
            $attempts = 0;
            try {
                $db = getDatabase();
                $sanitizedEmail = sanitizeEmailForFirebaseKey($email);
                $loginAttemptsRef = $db->getReference('login_attempts');
                $attempts = $loginAttemptsRef->getChild($sanitizedEmail)->getValue() ?? 0;
            } catch (\Throwable $e) {
                // If we can't connect to Firebase for attempt tracking, continue with login
                // but don't track attempts to avoid blocking users during connection issues
                $attempts = 0;
            }
            
            $res = firebaseSignIn($email, $password);
            if (isset($res['error'])) {
                $errorMsg = $res['error'];
                if (strpos($errorMsg, 'INVALID_PASSWORD') !== false || strpos($errorMsg, 'INVALID_LOGIN_CREDENTIALS') !== false) {
                    // Increment failed attempt counter
                    $attempts++;
                    try {
                        $db = getDatabase();
                        $sanitizedEmail = sanitizeEmailForFirebaseKey($email);
                        $loginAttemptsRef = $db->getReference('login_attempts');
                        $loginAttemptsRef->getChild($sanitizedEmail)->set($attempts);
                    } catch (\Throwable $e) {
                        // Silently ignore attempt tracking errors
                    }
                    
                    if ($attempts >= 3) {
                        // Send verification code after 3 failed attempts
                        $otpResult = sendOtpDirect($email, 'password_verification');
                        if ($otpResult['success']) {
                            $error = 'Too many incorrect password attempts. A verification code has been sent to your email. Please verify before logging in again.';
                            $showPasswordVerificationOtp = true;
                            // Reset attempts counter
                            try {
                                $db = getDatabase();
                                $sanitizedEmail = sanitizeEmailForFirebaseKey($email);
                                $loginAttemptsRef = $db->getReference('login_attempts');
                                $loginAttemptsRef->getChild($sanitizedEmail)->set(0);
                            } catch (\Throwable $e) {
                                // Silently ignore
                            }
                        } else {
                            $error = 'Password does not match. Please try again. (Attempt ' . $attempts . '/3)';
                        }
                    } else {
                        $attemptsLeft = 3 - $attempts;
                        $error = 'Password does not match. Please try again. (' . $attemptsLeft . ' attempts left)';
                    }
                } elseif (strpos($errorMsg, 'EMAIL_NOT_FOUND') !== false) {
                    $error = 'Account does not exist. Please check your email or create a new account.';
                } elseif (strpos($errorMsg, 'USER_DISABLED') !== false) {
                    $error = 'This account has been disabled. Please contact support.';
                } elseif (strpos($errorMsg, 'TOO_MANY_ATTEMPTS_TRY_LATER') !== false) {
                    $error = 'Too many failed login attempts. Please try again later.';
                } else {
                    $error = 'Login failed. Please try again.';
                }
            } else {
                // Successful login - reset attempts counter
                try {
                    $db = getDatabase();
                    $sanitizedEmail = sanitizeEmailForFirebaseKey($email);
                    $loginAttemptsRef = $db->getReference('login_attempts');
                    $loginAttemptsRef->getChild($sanitizedEmail)->set(0);
                } catch (\Throwable $e) {
                    // Silently ignore attempt reset on successful login
                }
                $_SESSION['user'] = [
                    'uid' => $res['localId'],
                    'idToken' => $res['idToken'],
                    'email' => $email
                ];
                header('Location: dashboard.php');
                exit;
            }
        }
    }

    // Forgot password (modal) submit
    if (isset($_POST['action']) && $_POST['action'] === 'send_otp') {
        $resetEmail = filter_var($_POST['resetEmail'] ?? '', FILTER_SANITIZE_EMAIL);
        if (!filter_var($resetEmail, FILTER_VALIDATE_EMAIL)) {
            $error = 'Please enter a valid email address.';
        } else {
            // Check if user exists in Firebase Auth
            $auth = getAuth();
            try {
                $user = $auth->getUserByEmail($resetEmail);
                
                // Send OTP for forgot password using direct function
                $result = sendOtpDirect($resetEmail, 'forgot_password');
                
                if ($result['success']) {
                    $error = ''; // clear
                    $success = 'Password reset code sent. Check your email.';
                    $showOtpField = true;
                } else {
                    $error = $result['error'] ?? 'Failed to send OTP code.';
                }
                
            } catch (\Kreait\Firebase\Exception\Auth\UserNotFound $e) {
                $error = 'No account found with this email address.';
            } catch (\Throwable $e) {
                $error = 'Failed to send OTP code: ' . $e->getMessage();
            }
        }
    }

    // Verify OTP and reset password
    if (isset($_POST['action']) && $_POST['action'] === 'reset_password') {
        $resetEmail = filter_var($_POST['resetEmail'] ?? '', FILTER_SANITIZE_EMAIL);
        $otpCode = trim($_POST['otpCode'] ?? '');
        $newPassword = $_POST['newPassword'] ?? '';

        if (!filter_var($resetEmail, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email address.';
        } elseif (empty($otpCode)) {
            $error = 'Please enter the OTP code.';
        } elseif (strlen($newPassword) < 8) {
            $error = 'Password must be at least 8 characters long.';
        } else {
            // Verify OTP for forgot password
            $url = 'http://' . $_SERVER['HTTP_HOST'] . '/backend/verify_otp.php';
            $payload = http_build_query([
                'email' => $resetEmail, 
                'code' => $otpCode,
                'purpose' => 'forgot_password'
            ]);

            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
            $result = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($result === false) {
                $error = 'Failed to verify OTP.';
            } else {
                $data = json_decode($result, true);
                if (isset($data['error'])) {
                    $error = $data['error'];
                } else {
                    // OTP verified, reset password in Firebase Auth
                    $auth = getAuth();
                    try {
                        $user = $auth->getUserByEmail($resetEmail);
                        $auth->changeUserPassword($user->uid, $newPassword);
                        $error = ''; // clear
                        $success = 'Password reset successfully. You can now login with your new password.';
                        $showOtpField = false;
                    } catch (\Throwable $e) {
                        $error = 'Failed to reset password.';
                    }
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>User Login</title>

    <!-- Font Awesome for the eye icon -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">

    <!-- App stylesheet (updated design) -->
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>
    <div class="container">
        <div class="form-box" id="loginForm" role="main" aria-labelledby="loginTitle">
            <div class="logo">
            </div>

            <h2 id="loginTitle">LOG IN</h2>

            <?php if (!empty($error)): ?>
                <p class="error-message"><?= htmlspecialchars($error) ?></p>
            <?php elseif (!empty($success)): ?>
                <p class="success-message"><?= htmlspecialchars($success) ?></p>
            <?php endif; ?>

            <?php if (!empty($success) && isset($_POST['action']) && in_array($_POST['action'], ['send_otp', 'reset_password'])): ?>
                <script>
                    document.addEventListener('DOMContentLoaded', function() {
                        const modal = document.getElementById('forgotPasswordModal');
                        if (modal) {
                            modal.style.display = 'none';
                            modal.setAttribute('aria-hidden', 'true');
                        }
                    });
                </script>
            <?php endif; ?>

            <?php if (!empty($success) && isset($_POST['action']) && $_POST['action'] === 'verify_password_otp'): ?>
                <script>
                    setTimeout(function() {
                        window.location.href = 'user_login.php';
                    }, 2000);
                </script>
            <?php endif; ?>

            <form method="POST" action="">
                <?php if ($showPasswordVerificationOtp): ?>
                    <input type="hidden" name="action" value="verify_password_otp">
                    <div class="input-group">
                        <label for="emailDisplay">Email</label>
                        <div class="input-field">
                            <input id="emailDisplay" type="email" readonly value="<?= htmlspecialchars($email) ?>" style="background-color: #f0f0f0;">
                            <input type="hidden" name="email" value="<?= htmlspecialchars($email) ?>">
                        </div>
                    </div>

                    <div class="input-group">
                        <label for="passwordOtpCode">Verification Code</label>
                        <div class="input-field">
                            <input id="passwordOtpCode" type="text" name="passwordOtpCode" placeholder="Enter 6-digit code" required autofocus>
                        </div>
                    </div>

                    <button type="submit" class="submit-btn">Verify</button>
                    <div class="form-footer">
                        <p><a href="user_login.php" style="color: var(--primary-dark);">Back to Login</a></p>
                    </div>
                <?php else: ?>
                    <input type="hidden" name="action" value="login">
                    <div class="input-group">
                        <label for="email">Email</label>
                        <div class="input-field">
                            <input id="email" type="email" name="email" value="<?= htmlspecialchars($email) ?>" placeholder="Enter your email" required>
                        </div>
                    </div>

                    <div class="input-group">
                        <label for="password">Password</label>
                        <div class="input-field" style="position:relative;">
                            <input id="password" type="password" name="password" placeholder="Enter your password" required>
                            <button type="button" class="password-toggle" id="togglePassword" aria-label="Toggle password visibility">
                                <i class="fas fa-eye-slash" aria-hidden="true"></i>
                            </button>
                        </div>
                    </div>

                    <button type="submit" class="submit-btn">Login</button>
                    <div class="forgot-row">
                        <a href="#" class="forgot-password" id="openForgotModal">Forgot password?</a>
                    </div>

                    <div class="form-footer">
                        <p>Don't have an account? <a href="user_register.php">Create Account</a></p>
                    </div>
                <?php endif; ?>
            </form>
        </div>
    </div>

    <!-- Forgot Password Modal -->
    <div id="forgotPasswordModal" class="modal" role="dialog" aria-modal="true" aria-labelledby="forgotTitle" aria-hidden="true">
        <div class="modal-content" role="document">
            <button class="close" id="closeForgotModal" aria-label="Close">&times;</button>
            <div class="logo" style="text-align:center;margin-bottom:12px;">
            </div>
            <h2 id="forgotTitle">Forgot Password</h2>
            <p>Enter your email address and we'll send you a password reset code to reset your password.</p>

            <form id="forgotForm" method="post" action="">
                <input type="hidden" name="resetEmail" id="resetEmailInput" value="<?php echo isset($_POST['resetEmail']) ? htmlspecialchars($_POST['resetEmail']) : ''; ?>">
                
                <?php if (!$showOtpField): ?>
                <input type="hidden" name="action" value="send_otp">
                <div class="input-group">
                    <label for="resetEmail">Email Address</label>
                    <div class="input-field">
                        <input id="resetEmail" type="email" name="resetEmail" required placeholder="Enter your email" value="<?php echo isset($_POST['resetEmail']) ? htmlspecialchars($_POST['resetEmail']) : ''; ?>">
                    </div>
                </div>
                <button type="submit" id="sendResetBtn" class="submit-btn">Send Reset Code</button>
                <?php else: ?>
                <div class="input-group">
                    <label for="resetEmailDisplay">Email Address</label>
                    <div class="input-field">
                        <input id="resetEmailDisplay" type="email" readonly value="<?php echo htmlspecialchars($_POST['resetEmail'] ?? ''); ?>" style="background-color: #f0f0f0;">
                    </div>
                </div>

                <div class="input-group">
                    <label for="otpCode">Reset Code</label>
                    <div class="input-field">
                        <input id="otpCode" type="text" name="otpCode" required placeholder="Enter 6-digit code">
                    </div>
                </div>

                <div class="input-group">
                    <label for="newPassword">New Password</label>
                    <div class="input-field">
                        <input id="newPassword" type="password" name="newPassword" required placeholder="Enter new password (min. 8 characters)">
                    </div>
                </div>

                <input type="hidden" name="action" value="reset_password">
                <button type="submit" id="resetPasswordBtn" class="submit-btn">Reset Password</button>
                <?php endif; ?>

                <div style="text-align:center;margin-top:10px">
                    <a href="#" id="cancelForgot" style="color: var(--primary-dark);">Back to Login</a>
                </div>
            </form>
        </div>
    </div>

    <script>
    if (<?php echo (!empty($success) && ($_POST['action'] ?? '') === 'reset_password') ? 'true' : 'false'; ?>) {
        const modal = document.getElementById('forgotPasswordModal');
        if (modal) {
            modal.style.display = 'none';
            modal.setAttribute('aria-hidden', 'true');
        }
    }
    </script>

    <script>
    document.addEventListener('DOMContentLoaded', function () {
        const togglePassword = document.getElementById('togglePassword');
        const passwordInput = document.getElementById('password');

        togglePassword.addEventListener('click', function () {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            this.querySelector('i').classList.toggle('fa-eye-slash');
            this.querySelector('i').classList.toggle('fa-eye');
        });

        // Modal logic
        const openForgotModal = document.getElementById('openForgotModal');
        const forgotModal = document.getElementById('forgotPasswordModal');
        const closeForgotModal = document.getElementById('closeForgotModal');
        const cancelForgot = document.getElementById('cancelForgot');

        function openModal() {
            forgotModal.style.display = 'flex';
            forgotModal.setAttribute('aria-hidden', 'false');
            document.getElementById('resetEmail').focus();
        }
        function closeModal() {
            forgotModal.style.display = 'none';
            forgotModal.setAttribute('aria-hidden', 'true');
        }

        openForgotModal.addEventListener('click', function (e) {
            e.preventDefault();
            openModal();
        });
        closeForgotModal.addEventListener('click', function (e) {
            e.preventDefault();
            closeModal();
        });
        cancelForgot.addEventListener('click', function (e) {
            e.preventDefault();
            closeModal();
        });

        // Close modal on Escape
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') closeModal();
        });

        // Clicking outside modal-content closes it
        forgotModal.addEventListener('click', function (e) {
            if (e.target === forgotModal) closeModal();
        });

        // Keep modal open when OTP is sent successfully
        <?php if (!empty($success) && ($_POST['action'] ?? '') === 'send_otp'): ?>
        openModal();
        <?php endif; ?>
    });
    </script>
</body>
</html>