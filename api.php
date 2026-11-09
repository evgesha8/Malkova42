<?php
// Серверная часть «Книги записи». Хранит клиентов, услуги и записи в MySQL.
// Все ответы в формате JSON. Доступ только после входа по логину и паролю.

ini_set('display_errors', '0');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

const KINDS = ['clients', 'visits', 'appts'];

function out($data, $code = 200) {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function fail($err, $code = 400) {
    out(['ok' => false, 'error' => $err], $code);
}

function load_config() {
    foreach ([__DIR__ . '/config.php', __DIR__ . '/../config.php'] as $f) {
        if (file_exists($f)) {
            return require $f;
        }
    }
    return null;
}

function db() {
    static $pdo = null;
    global $cfg;
    if ($pdo === null) {
        $pdo = new PDO(
            'mysql:host=' . $cfg['db_host'] . ';dbname=' . $cfg['db_name'] . ';charset=utf8mb4',
            $cfg['db_user'],
            $cfg['db_pass'],
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );
    }
    return $pdo;
}

function is_https() {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
}

function need_post() {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        fail('bad_request', 405);
    }
    // Защита от запросов с чужих сайтов: такой заголовок чужая страница отправить не может.
    if (($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') !== 'fetch') {
        fail('forbidden', 403);
    }
}

function body() {
    static $b = null;
    if ($b === null) {
        $raw = file_get_contents('php://input');
        if ($raw === false || strlen($raw) > 1048576) {
            fail('bad_request');
        }
        $b = json_decode($raw, true);
        if (!is_array($b)) {
            $b = [];
        }
    }
    return $b;
}

function token_from_cookie() {
    $tok = $_COOKIE['sid'] ?? '';
    return (is_string($tok) && preg_match('/^[a-f0-9]{64}$/', $tok)) ? $tok : '';
}

function current_user() {
    static $u = false;
    if ($u !== false) {
        return $u;
    }
    $u = null;
    global $cfg;
    if (!empty($cfg['open_access'])) {
        // Режим «без пароля»: любой, кто открыл сайт, работает с данными.
        $u = ['id' => 0, 'login' => '', 'role' => 'open'];
        return $u;
    }
    $tok = token_from_cookie();
    if ($tok !== '') {
        $st = db()->prepare('SELECT u.id, u.login, u.role FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires > ?');
        $st->execute([hash('sha256', $tok), time()]);
        $row = $st->fetch();
        if ($row) {
            $u = ['id' => (int)$row['id'], 'login' => $row['login'], 'role' => $row['role']];
        }
    }
    return $u;
}

function need_user() {
    $u = current_user();
    if (!$u) {
        fail('unauthorized', 401);
    }
    return $u;
}

function need_owner() {
    $u = need_user();
    if ($u['role'] !== 'owner') {
        fail('forbidden', 403);
    }
    return $u;
}

function set_sid_cookie($tok, $expires) {
    setcookie('sid', $tok, [
        'expires' => $expires,
        'path' => '/',
        'secure' => is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function valid_password($p) {
    return is_string($p) && strlen($p) >= 8 && strlen($p) <= 200;
}

try {
    $cfg = load_config();
    if (!$cfg) {
        fail('server', 500);
    }
    $r = $_GET['r'] ?? '';

    switch ($r) {
        case 'me':
            out(['ok' => true, 'user' => current_user()]);

        case 'login':
            need_post();
            $in = body();
            $login = trim((string)($in['login'] ?? ''));
            $pass = (string)($in['password'] ?? '');
            $ip = substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
            $login = substr($login, 0, 64);
            db()->prepare('DELETE FROM attempts WHERE ts < ?')->execute([time() - 900]);
            $st = db()->prepare('SELECT COUNT(*) FROM attempts WHERE ip = ? OR login = ?');
            $st->execute([$ip, $login]);
            if ((int)$st->fetchColumn() >= 8) {
                fail('too_many', 429);
            }
            $st = db()->prepare('SELECT id, login, role, pass_hash FROM users WHERE login = ?');
            $st->execute([$login]);
            $u = $st->fetch();
            if (!$u || !password_verify($pass, $u['pass_hash'])) {
                db()->prepare('INSERT INTO attempts (ip, login, ts) VALUES (?, ?, ?)')->execute([$ip, $login, time()]);
                usleep(400000);
                fail('bad_login', 401);
            }
            db()->prepare('DELETE FROM attempts WHERE ip = ? OR login = ?')->execute([$ip, $login]);
            db()->prepare('DELETE FROM sessions WHERE expires < ?')->execute([time()]);
            $tok = bin2hex(random_bytes(32));
            $exp = time() + 30 * 86400;
            db()->prepare('INSERT INTO sessions (token_hash, user_id, expires) VALUES (?, ?, ?)')->execute([hash('sha256', $tok), (int)$u['id'], $exp]);
            set_sid_cookie($tok, $exp);
            out(['ok' => true, 'user' => ['id' => (int)$u['id'], 'login' => $u['login'], 'role' => $u['role']]]);

        case 'logout':
            need_post();
            $tok = token_from_cookie();
            if ($tok !== '') {
                db()->prepare('DELETE FROM sessions WHERE token_hash = ?')->execute([hash('sha256', $tok)]);
            }
            set_sid_cookie('', time() - 3600);
            out(['ok' => true]);

        case 'data':
            need_user();
            $res = ['clients' => [], 'visits' => [], 'appts' => []];
            foreach (db()->query('SELECT kind, doc_id, body FROM docs') as $row) {
                $d = json_decode($row['body'], true);
                if (is_array($d) && isset($res[$row['kind']])) {
                    $d['id'] = $row['doc_id'];
                    $res[$row['kind']][] = $d;
                }
            }
            out(array_merge(['ok' => true], $res));

        case 'put':
            need_post();
            need_user();
            $in = body();
            $kind = $in['kind'] ?? '';
            $id = $in['id'] ?? '';
            $doc = $in['doc'] ?? null;
            if (!is_string($kind) || !in_array($kind, KINDS, true)
                || !is_string($id) || !preg_match('/^[A-Za-z0-9_-]{1,40}$/', $id)
                || !is_array($doc) || !$doc) {
                fail('bad_request');
            }
            unset($doc['id']);
            $json = json_encode($doc, JSON_UNESCAPED_UNICODE);
            if ($json === false || strlen($json) > 20000) {
                fail('bad_request');
            }
            db()->prepare('INSERT INTO docs (kind, doc_id, body, updated_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE body = VALUES(body), updated_at = VALUES(updated_at)')
                ->execute([$kind, $id, $json, time()]);
            out(['ok' => true]);

        case 'del':
            need_post();
            need_user();
            $in = body();
            $kind = $in['kind'] ?? '';
            $id = $in['id'] ?? '';
            if (!is_string($kind) || !in_array($kind, KINDS, true) || !is_string($id) || !preg_match('/^[A-Za-z0-9_-]{1,40}$/', $id)) {
                fail('bad_request');
            }
            db()->prepare('DELETE FROM docs WHERE kind = ? AND doc_id = ?')->execute([$kind, $id]);
            out(['ok' => true]);

        case 'change_password':
            need_post();
            $me = need_user();
            $in = body();
            $old = (string)($in['old'] ?? '');
            $new = $in['new'] ?? '';
            if (!valid_password($new)) {
                fail('weak_password');
            }
            $st = db()->prepare('SELECT pass_hash FROM users WHERE id = ?');
            $st->execute([$me['id']]);
            $hash = $st->fetchColumn();
            if (!$hash || !password_verify($old, $hash)) {
                fail('bad_password');
            }
            db()->prepare('UPDATE users SET pass_hash = ? WHERE id = ?')->execute([password_hash($new, PASSWORD_DEFAULT), $me['id']]);
            // Остальные устройства придётся авторизовать заново.
            db()->prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?')->execute([$me['id'], hash('sha256', token_from_cookie())]);
            out(['ok' => true]);

        case 'users':
            need_owner();
            $list = [];
            foreach (db()->query('SELECT id, login, role FROM users ORDER BY id') as $row) {
                $list[] = ['id' => (int)$row['id'], 'login' => $row['login'], 'role' => $row['role']];
            }
            out(['ok' => true, 'users' => $list]);

        case 'user_add':
            need_post();
            need_owner();
            $in = body();
            $login = trim((string)($in['login'] ?? ''));
            $pass = $in['password'] ?? '';
            if (!preg_match('/^[A-Za-z0-9_.@-]{3,64}$/', $login)) {
                fail('bad_request');
            }
            if (!valid_password($pass)) {
                fail('weak_password');
            }
            $st = db()->prepare('SELECT COUNT(*) FROM users WHERE login = ?');
            $st->execute([$login]);
            if ((int)$st->fetchColumn() > 0) {
                fail('exists', 409);
            }
            db()->prepare('INSERT INTO users (login, pass_hash, role, created_at) VALUES (?, ?, ?, ?)')
                ->execute([$login, password_hash($pass, PASSWORD_DEFAULT), 'staff', time()]);
            out(['ok' => true]);

        case 'user_del':
            need_post();
            $me = need_owner();
            $in = body();
            $id = (int)($in['id'] ?? 0);
            if ($id <= 0 || $id === $me['id']) {
                fail('bad_request');
            }
            db()->prepare('DELETE FROM sessions WHERE user_id = ?')->execute([$id]);
            db()->prepare('DELETE FROM users WHERE id = ?')->execute([$id]);
            out(['ok' => true]);

        case 'user_pass':
            need_post();
            need_owner();
            $in = body();
            $id = (int)($in['id'] ?? 0);
            $pass = $in['password'] ?? '';
            if ($id <= 0) {
                fail('bad_request');
            }
            if (!valid_password($pass)) {
                fail('weak_password');
            }
            $st = db()->prepare('UPDATE users SET pass_hash = ? WHERE id = ?');
            $st->execute([password_hash($pass, PASSWORD_DEFAULT), $id]);
            db()->prepare('DELETE FROM sessions WHERE user_id = ?')->execute([$id]);
            out(['ok' => true]);

        default:
            fail('not_found', 404);
    }
} catch (Throwable $e) {
    error_log('salon api: ' . $e->getMessage());
    fail('server', 500);
}
