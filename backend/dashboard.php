<?php
session_start();
if (!isset($_SESSION['user'])) {
    header('Location: index.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Dashboard</title>
</head>
<body>
<h1>Welcome, <?= htmlspecialchars($_SESSION['user']['email']) ?></h1>
<a href="user_login.php">Logout</a>
</body>
</html>
