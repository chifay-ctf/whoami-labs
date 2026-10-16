                        <?php
session_start();
if (!isset($_SESSION['usuario'])) {
    header('Location: empleados.php');
    exit;
}
$page = $_GET['page'] ?? 'inicio';
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Panel - Cantera Picapiedra</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="panel.php">🦴 Panel de Empleados</a>
            <div class="ms-auto text-white">
                <?php echo htmlspecialchars($_SESSION['nombre']); ?>
                <a href="logout.php" class="btn btn-sm btn-outline-light ms-3">Salir</a>
            </div>
        </div>
    </nav>
    <div class="container mt-5">
        <div class="row">
            <div class="col-md-3">
                <div class="card">
                    <div class="card-header bg-primary text-white"><h5>📂 Menú</h5></div>
                    <div class="list-group list-group-flush">
                        <a href="panel.php?page=inicio" class="list-group-item">🏠 Inicio</a>
                        <a href="panel.php?page=reportes" class="list-group-item">📊 Reportes</a>
                        <a href="panel.php?page=documentos" class="list-group-item">📄 Documentos</a>
                    </div>
                </div>
            </div>
            <div class="col-md-9">
                <div class="card">
                    <div class="card-body">
                        <?php
                        // LFI VULNERABLE
                        if (file_exists($page . '.php')) {
                            include($page . '.php');
                        } elseif (file_exists($page)) {
                            echo "<pre class='bg-light p-3'>";
                            echo htmlspecialchars(file_get_contents($page));
                            echo "</pre>";
                        } else {
                            echo "<div class='alert alert-warning'>Página no encontrada</div>";
                        }
                        ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
