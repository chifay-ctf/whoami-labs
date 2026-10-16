                        <?php
// Configuración BD - Cantera Picapiedra S.A.
define('DB_HOST', 'localhost');
define('DB_USER', 'picapiedra_admin');
define('DB_PASS', 'BedR0ck_DB_2024!');
define('DB_NAME', 'cantera_db');
function getDBConnection() {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($conn->connect_error) {
        die("Error: " . $conn->connect_error);
    }
    return $conn;
}
?>
