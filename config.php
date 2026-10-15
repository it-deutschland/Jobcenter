<?php
declare(strict_types=1);

date_default_timezone_set('Europe/Berlin');

if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (($_SERVER['SERVER_PORT'] ?? '') === '443'),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

function db(): PDO
{
    static $connection = null;
    if ($connection === null) {
        $host = getenv('EURO_DB_HOST') ?: '217.160.153.219';
        $port = getenv('EURO_DB_PORT') ?: '3306';
        $name = getenv('EURO_DB_NAME') ?: 'csa';
        $connection = new PDO(
            "mysql:host={$host};port={$port};dbname={$name};charset=utf8mb4",
            getenv('EURO_DB_USER') ?: 'root',
            getenv('EURO_DB_PASSWORD') ?: 'TheReal1337!',
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );
    }
    return $connection;
}

function h(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function csrf_token(): string
{
    if (!isset($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function require_csrf(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        http_response_code(405);
        header('Allow: POST');
        exit('Diese Aktion erfordert POST.');
    }
    $token = $_POST['csrf_token'] ?? null;
    if (!is_string($token) || !isset($_SESSION['csrf_token'])
        || !is_string($_SESSION['csrf_token'])
        || !hash_equals($_SESSION['csrf_token'], $token)) {
        http_response_code(403);
        exit('Ungültige Sicherheitsprüfung. Bitte lade das Formular erneut.');
    }
}

function current_user(): ?array
{
    $id = $_SESSION['userid'] ?? null;
    if ((!is_int($id) && !is_string($id)) || !ctype_digit((string) $id) || (int) $id < 1) {
        return null;
    }
    $statement = db()->prepare('SELECT * FROM users WHERE id = ?');
    $statement->execute([$id]);
    $user = $statement->fetch();
    if (!$user) {
        unset($_SESSION['userid'], $_SESSION['username']);
        return null;
    }
    return $user;
}

function require_login(): array
{
    $user = current_user();
    if ($user === null) {
        header('Location: index.php');
        exit;
    }
    return $user;
}

function post_string(string $key): string
{
    return isset($_POST[$key]) && is_string($_POST[$key]) ? $_POST[$key] : '';
}

function safe_avatar_url(mixed $value): string
{
    if (!is_string($value) || $value === '' || !filter_var($value, FILTER_VALIDATE_URL)) {
        return '';
    }
    return in_array(strtolower((string) parse_url($value, PHP_URL_SCHEME)), ['http', 'https'], true)
        ? $value : '';
}
