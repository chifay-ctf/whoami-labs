                        <?php
$empleados = array(
    'pedro' => array(
        'password' => 'password123',
        'nombre' => 'Pedro Picapiedra',
        'nivel' => 'admin'
    ),
    'pablo' => array(
        'password' => 'admin123',
        'nombre' => 'Pablo Mármol',
        'nivel' => 'user'
    ),
    'fred' => array(
        'password' => 'yabbadabbadoo',
        'nombre' => 'Fred Flintstone',
        'nivel' => 'admin'
    )
);
function autenticar($usuario, $password) {
    global $empleados;
    if (isset($empleados[$usuario]) && $empleados[$usuario]['password'] === $password) {
        return $empleados[$usuario];
    }
    return false;
}
?>
