<?php
session_start();
require __DIR__ . '/firebase.php';

$message = '';
$emailError = $passwordError = $confirmError = '';
$verifiedEmail = false;
$registrationSuccess = false;

// Check if email was previously verified using new structure
if (!empty($_POST['email'])) {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $userData = getUserByEmail($email);
    
    if (!empty($userData['email_otps']['verified']) && 
        time() <= ($userData['email_otps']['expires_at'] ?? 0)) {
        $verifiedEmail = true;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'register') {
    $email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'] ?? '';
    $confirm = $_POST['confirm_password'] ?? '';

    // Check if email is verified using new structure
    $userData = getUserByEmail($email);
    if (!empty($userData['email_otps']['verified']) && 
        time() <= ($userData['email_otps']['expires_at'] ?? 0)) {
        $verifiedEmail = true;
    }

    // Validation
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $emailError = 'Please enter a valid email address.';
    } elseif (!$verifiedEmail) {
        $emailError = 'Email not verified. Please verify the code sent to your email first.';
    }

    // Password validation
    if (empty($password)) {
        $passwordError = 'Password is required.';
    } elseif (strlen($password) < 8) {
        $passwordError = 'Password must be at least 8 characters long.';
    }

    if (empty($confirm)) {
        $confirmError = 'Please confirm your password.';
    } elseif ($password !== $confirm) {
        $confirmError = 'Passwords do not match.';
    }

    // If all validations pass and email is verified
    if (!$emailError && !$passwordError && !$confirmError && $verifiedEmail) {
        $res = firebaseSignUp($email, $password);
        if (isset($res['error'])) {
            // Handle JWT token object conversion error
            if ($res['error'] instanceof \Lcobucci\JWT\Token\Plain) {
                $emailError = 'Registration failed. Please try again.';
            } else {
                // Convert Firebase error message to user-friendly message
                $errorMessage = (string)$res['error'];
                if (strpos($errorMessage, 'email address is already in use') !== false || 
                    strpos($errorMessage, 'EMAIL_EXISTS') !== false) {
                    $emailError = 'Email already exists.';
                } else {
                    $emailError = $errorMessage;
                }
            }
        } else {
            // Registration successful
            $registrationSuccess = true;
        }
    }
}

// Determine if password fields should be enabled
$enablePasswordFields = $verifiedEmail || (!empty($_POST['action']) && $_POST['action'] === 'register');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Register</title>
<link rel="stylesheet" href="../css/style.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
.error-text { color: red; font-size: 14px; margin-top: 4px; text-align: left; }
.success-text { color: green; font-size: 14px; margin-top: 4px; text-align: left; }
.disabled-field { background-color: #f0f0f0; cursor: not-allowed; }
.password-wrapper { position: relative; }
.toggle-password { 
    position: absolute; 
    right: 10px; 
    top: 30%; 
    transform: translateY(-50%); 
    background: transparent; 
    border: none; 
    cursor: pointer; 
    color: #666;
    font-size: 16px;
    padding: 0;
    width: 20px;
    height: 20px;
    display: flex;
    align-items: center;
    justify-content: center;
}
.toggle-password:hover, .toggle-password:active { color: #333; background: transparent; }
.modal {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.5);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 1000;
}
.modal-content {
    background-color: white;
    padding: 20px;
    border-radius: 8px;
    width: 90%;
    max-width: 400px;
    position: relative;
}
.close {
    position: absolute;
    top: 10px;
    right: 10px;
    background: transparent;
    border: none;
    font-size: 24px;
    cursor: pointer;
}
.close:hover, .close:active {
    background: transparent;
}
</style>
</head>
<body>
<main class="form-container" role="main">
    <header class="form-header">
        <h2>Create Account</h2>
    </header>

    <?php if ($registrationSuccess): ?>
    <div class="success-text" style="text-align: center; margin-bottom: 20px; padding: 10px; background-color: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px;">
        ✅ Successfully Registered! You can now proceed to login.
    </div>
    <script>
        setTimeout(function() {
            window.location.href = 'user_login.php';
        }, 2000);
    </script>
    <?php endif; ?>

    <form id="registerForm" method="post" novalidate>
        <input type="hidden" name="action" value="register">
        <div class="form-group">
            <label for="email">Email</label>
            <div class="input-wrapper">
                <input id="email" name="email" type="email" required placeholder="Enter your email" 
                    value="<?php echo isset($email) ? htmlspecialchars($email) : ''; ?>"
                    <?php echo $verifiedEmail ? 'readonly' : ''; ?>>
            </div>
            <?php if ($emailError): ?><div class="error-text"><?= htmlspecialchars($emailError) ?></div><?php endif; ?>
        </div>

        <div class="form-group">
            <label for="password">Password</label>
            <div class="input-wrapper password-wrapper">
                <input id="password" name="password" type="password" required placeholder="Enter your password"
                    <?php echo !$enablePasswordFields ? 'disabled class="disabled-field"' : ''; ?>>
                <button type="button" class="toggle-password" id="togglePassword">
                    <i class="fas fa-eye-slash"></i>
                </button>
            </div>
            <?php if ($passwordError): ?><div class="error-text"><?= htmlspecialchars($passwordError) ?></div><?php endif; ?>
        </div>

        <div class="form-group">
            <label for="confirm_password">Confirm Password</label>
            <div class="input-wrapper password-wrapper">
                <input id="confirm_password" name="confirm_password" type="password" required placeholder="Confirm password"
                    <?php echo !$enablePasswordFields ? 'disabled class="disabled-field"' : ''; ?>>
                <button type="button" class="toggle-password" id="toggleConfirmPassword">
                    <i class="fas fa-eye-slash"></i>
                </button>
            </div>
            <?php if ($confirmError): ?><div class="error-text"><?= htmlspecialchars($confirmError) ?></div><?php endif; ?>
        </div>

        <!-- Buttons -->
        <button id="verifyEmailBtn" type="button" class="submit-btn" <?php echo $verifiedEmail ? 'style="display:none;"' : ''; ?>>Verify Email</button>
        <button id="createAccountBtn" type="submit" class="submit-btn" style="display:<?php echo $verifiedEmail ? 'inline-block' : 'none'; ?>;" <?php echo $registrationSuccess ? 'disabled' : ''; ?>>Create Account</button>
    </form>

    <div class="form-footer">
        <p>Already have an account? <a href="user_login.php">Login</a></p>
    </div>
</main>

<!-- OTP Modal -->
<div id="otpModal" class="modal" role="dialog" aria-hidden="true" style="display:none;">
    <div class="modal-content">
        <button class="close" id="closeModal">&times;</button>
        <h2>Verify Email</h2>
        <p>We sent a 6-digit code to your email. It expires in 5 minutes.</p>
        <div class="form-group">
            <label for="otp">Code</label>
            <div class="input-wrapper">
                <input id="otp" type="text" inputmode="numeric" maxlength="6" placeholder="Enter code">
            </div>
        </div>
        <div style="display:flex;gap:8px;">
            <button id="resendBtn" class="submit-btn" type="button">Resend</button>
            <button id="verifyBtn" class="submit-btn" type="button">Verify</button>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function(){
    const verifyEmailBtn = document.getElementById('verifyEmailBtn');
    const createAccountBtn = document.getElementById('createAccountBtn');
    const emailInput = document.getElementById('email');
    const otpModal = document.getElementById('otpModal');
    const closeModal = document.getElementById('closeModal');
    const resendBtn = document.getElementById('resendBtn');
    const verifyBtn = document.getElementById('verifyBtn');
    const otpInput = document.getElementById('otp');
    const passwordInputs = [document.getElementById('password'), document.getElementById('confirm_password')];
    const togglePasswordBtn = document.getElementById('togglePassword');
    const toggleConfirmPasswordBtn = document.getElementById('toggleConfirmPassword');

    function openModal(){ otpModal.style.display='flex'; otpModal.setAttribute('aria-hidden','false'); otpInput.focus(); }
    function close(){ otpModal.style.display='none'; otpModal.setAttribute('aria-hidden','true'); }

    function enablePasswordFields() {
        passwordInputs.forEach(input => { 
            input.disabled = false; 
            input.classList.remove('disabled-field'); 
        });
        verifyEmailBtn.style.display = 'none';
        createAccountBtn.style.display = 'inline-block';
        togglePasswordBtn.style.display = 'flex';
        toggleConfirmPasswordBtn.style.display = 'flex';
    }

    function togglePasswordVisibility(input, button) {
        const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
        input.setAttribute('type', type);
        button.innerHTML = type === 'password' ? '<i class="fas fa-eye-slash"></i>' : '<i class="fas fa-eye"></i>';
    }

    // Toggle password visibility
    togglePasswordBtn.addEventListener('click', function() {
        togglePasswordVisibility(document.getElementById('password'), togglePasswordBtn);
    });

    toggleConfirmPasswordBtn.addEventListener('click', function() {
        togglePasswordVisibility(document.getElementById('confirm_password'), toggleConfirmPasswordBtn);
    });

    async function sendOtp(email){
        const fd = new FormData(); fd.append('email', email);
        const res = await fetch('send_otp.php', { method:'POST', body: fd });
        return res.json();
    }

    async function verifyOtp(email, code){
        const fd = new FormData(); fd.append('email', email); fd.append('code', code);
        const res = await fetch('verify_otp.php', { method:'POST', body: fd });
        return res.json();
    }

    verifyEmailBtn.addEventListener('click', async function(){
        const email = emailInput.value.trim();
        if (!email) { alert('Please enter your email'); return; }
        verifyEmailBtn.disabled = true;
        const data = await sendOtp(email);
        verifyEmailBtn.disabled = false;
        if (data.ok) openModal();
        else alert(data.error || 'Failed to send code.');
    });

    verifyBtn.addEventListener('click', async function(){
        const email = emailInput.value.trim();
        const code = otpInput.value.trim();
        if (!code) return;
        verifyBtn.disabled = true;
        const data = await verifyOtp(email, code);
        verifyBtn.disabled = false;
        if (data.ok) {
            close();
            enablePasswordFields();
            // Make email readonly after verification
            emailInput.readOnly = true;
        } else alert(data.error || 'Verification failed.');
    });

    closeModal.addEventListener('click', close);
    otpModal.addEventListener('click', (e)=> { if(e.target===otpModal) close(); });
    document.addEventListener('keydown', (e)=> { if(e.key==='Escape') close(); });
    
    // Check if password fields should be enabled on page load (for form submission with errors)
    <?php if ($enablePasswordFields && !$registrationSuccess): ?>
    enablePasswordFields();
    <?php endif; ?>
});
</script>
</body>
</html>