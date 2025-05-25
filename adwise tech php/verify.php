<?php
$host = "localhost";
$user = "root";
$password = "";
$dbname = "addwise";
$conn = new mysqli($host, $user, $password, $dbname);

if (isset($_GET['code'])) {
    $code = $_GET['code'];

    $stmt = $conn->prepare("SELECT id FROM users WHERE verification_code = ? AND is_verified = 0");
    $stmt->bind_param("s", $code);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows == 1) {
        $update = $conn->prepare("UPDATE users SET is_verified = 1, verification_code = NULL WHERE verification_code = ?");
        $update->bind_param("s", $code);
        if ($update->execute()) {
            echo "Your email has been successfully verified. <a href='login.php'>Login</a>";
        } else {
            echo "Error updating verification.";
        }
    } else {
        echo "Invalid or already verified.";
    }
}
?>
