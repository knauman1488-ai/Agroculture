<?php
session_start();
require '../db.php';

// Function to sanitize user input
function dataFilter($data)
{
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

// Process only POST requests
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Filtered input
    $name = dataFilter($_POST['name']);
    $mobile = dataFilter($_POST['mobile']);
    $user = dataFilter($_POST['uname']);
    $email = dataFilter($_POST['email']);
    $pass = password_hash($_POST['pass'], PASSWORD_BCRYPT);
    $hash = md5(rand(0, 1000));
    $category = dataFilter($_POST['category']);
    $addr = dataFilter($_POST['addr']);

    // Store in session
    $_SESSION['Email'] = $email;
    $_SESSION['Name'] = $name;
    $_SESSION['Password'] = $pass;
    $_SESSION['Username'] = $user;
    $_SESSION['Mobile'] = $mobile;
    $_SESSION['Category'] = $category;
    $_SESSION['Hash'] = $hash;
    $_SESSION['Addr'] = $addr;
    $_SESSION['Rating'] = 0;

    // Mobile number validation
    if (strlen($mobile) != 10 || !ctype_digit($mobile)) {
        $_SESSION['message'] = "Invalid Mobile Number!";
        header("Location: error.php");
        exit();
    }

    // Email format validation
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['message'] = "Invalid Email Format!";
        header("Location: error.php");
        exit();
    }

    // Choose table based on category
    if ($category == 1) {
        // Farmer Registration
        $check_sql = "SELECT * FROM farmer WHERE femail = ?";
$stmt = $conn->prepare($check_sql);
if (!$stmt) {
    die("SQL Prepare failed: " . $conn->error);
}
$stmt->bind_param("s", $email);

        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $_SESSION['message'] = "User with this email already exists!";
            header("Location: error.php");
            exit();
        }

        $insert_sql = "INSERT INTO farmer (fname, fusername, fpassword, fhash, fmobile, femail, faddress) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)";
        $stmt = $conn->prepare($insert_sql);
        $stmt->bind_param("sssssss", $name, $user, $pass, $hash, $mobile, $email, $addr);

        if ($stmt->execute()) {
            $_SESSION['Active'] = 0;
            $_SESSION['logged_in'] = true;
            $_SESSION['picStatus'] = 0;
            $_SESSION['picExt'] = 'png';

            // Fetch user ID
            $stmt = $conn->prepare("SELECT fid FROM farmer WHERE fusername = ?");
            $stmt->bind_param("s", $user);
            $stmt->execute();
            $result = $stmt->get_result();
            $User = $result->fetch_assoc();
            $_SESSION['id'] = $User['fid'];

            // Profile picture defaults
            if ($_SESSION['picStatus'] == 0) {
                $_SESSION['picId'] = 0;
                $_SESSION['picName'] = "profile0.png";
            } else {
                $_SESSION['picId'] = $_SESSION['id'];
                $_SESSION['picName'] = "profile" . $_SESSION['picId'] . "." . $_SESSION['picExt'];
            }

            // Email message
            $to = $email;
            $subject = "Account Verification (ArtCircle.com)";
            $message_body = "
            Hello $user,

            Thank you for signing up!

            Please click the link below to activate your account:
            http://localhost/AgroCulture/Login/verify.php?email=$email&hash=$hash
            ";

            // Uncomment to send verification email:
            // mail($to, $subject, $message_body);

            $_SESSION['message'] = "Confirmation link has been sent to $email, please verify your account!";
            header("Location: profile.php");
            exit();
        } else {
            $_SESSION['message'] = "Registration failed!";
            header("Location: error.php");
            exit();
        }
    } else {
        // Buyer Registration
        $check_sql = "SELECT * FROM buyer WHERE bemail = ?";
        $stmt = $conn->prepare($check_sql);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $_SESSION['message'] = "User with this email already exists!";
            header("Location: error.php");
            exit();
        }

        $insert_sql = "INSERT INTO buyer (bname, busername, bpassword, bhash, bmobile, bemail, baddress)
                       VALUES (?, ?, ?, ?, ?, ?, ?)";
        $stmt = $conn->prepare($insert_sql);
        $stmt->bind_param("sssssss", $name, $user, $pass, $hash, $mobile, $email, $addr);

        if ($stmt->execute()) {
            $_SESSION['Active'] = 0;
            $_SESSION['logged_in'] = true;

            // Fetch user ID
            $stmt = $conn->prepare("SELECT bid FROM buyer WHERE busername = ?");
            $stmt->bind_param("s", $user);
            $stmt->execute();
            $result = $stmt->get_result();
            $User = $result->fetch_assoc();
            $_SESSION['id'] = $User['bid'];

            // Email message
            $to = $email;
            $subject = "Account Verification (ArtCircle.com)";
            $message_body = "
            Hello $user,

            Thank you for signing up!

            Please click the link below to activate your account:
            http://localhost/AgroCulture/Login/verify.php?email=$email&hash=$hash
            ";

            // Uncomment to send verification email:
            // mail($to, $subject, $message_body);

            $_SESSION['message'] = "Confirmation link has been sent to $email, please verify your account!";
            header("Location: profile.php");
            exit();
        } else {
            $_SESSION['message'] = "Registration not successful!";
            header("Location: error.php");
            exit();
        }
    }
}
?>
