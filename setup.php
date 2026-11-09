<?php
// Одноразовая установка: создаёт таблицы и учётную запись владельца.
// После успешной установки файл удаляет сам себя.

ini_set('display_errors', '0');
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');

function h($s) {
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

function page($title, $body) {
    echo '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<meta name="robots" content="noindex,nofollow"><title>' . h($title) . '</title>'
        . '<style>body{font:16px/1.5 system-ui,sans-serif;max-width:480px;margin:40px auto;padding:0 16px;color:#14211f}'
        . 'label{display:block;font-size:14px;color:#586966}'
        . 'input{width:100%;padding:10px;margin:4px 0 14px;box-sizing:border-box;font:inherit}'
        . 'button{padding:10px 18px;font:inherit;cursor:pointer}.e{color:#b3402a}code{background:#eef2f1;padding:1px 5px}</style>'
        . '</head><body>' . $body . '</body></html>';
    exit;
}

$cfg = null;
foreach ([__DIR__ . '/config.php', __DIR__ . '/../config.php'] as $f) {
    if (file_exists($f)) {
        $cfg = require $f;
        break;
    }
}
if (!$cfg) {
    page('Установка', '<h1>Не найден config.php</h1><p>Загрузите файл <code>config.php</code> в ту же папку, где лежит <code>setup.php</code>, и обновите страницу.</p>');
}

$key = (string)($cfg['setup_key'] ?? '');
if (strlen($key) < 12 || strpos($key, 'ПРИДУМАЙТЕ') === 0) {
    page('Установка', '<h1>Заполните config.php</h1><p>В файле <code>config.php</code> нужно указать данные базы и придумать <code>setup_key</code> длиной не меньше 12 символов. Затем загрузите файл заново и обновите страницу.</p>');
}

try {
    $pdo = new PDO(
        'mysql:host=' . $cfg['db_host'] . ';dbname=' . $cfg['db_name'] . ';charset=utf8mb4',
        $cfg['db_user'],
        $cfg['db_pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
    );
} catch (Throwable $e) {
    error_log('salon setup: ' . $e->getMessage());
    page('Установка', '<h1>Нет связи с базой данных</h1><p>Проверьте в <code>config.php</code> имя базы, пользователя, пароль и адрес сервера базы.</p>');
}

$tables = [
    'CREATE TABLE IF NOT EXISTS users (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        login VARCHAR(64) NOT NULL UNIQUE,
        pass_hash VARCHAR(255) NOT NULL,
        role VARCHAR(10) NOT NULL DEFAULT \'staff\',
        created_at INT UNSIGNED NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
    'CREATE TABLE IF NOT EXISTS docs (
        kind VARCHAR(16) NOT NULL,
        doc_id VARCHAR(40) NOT NULL,
        body MEDIUMTEXT NOT NULL,
        updated_at INT UNSIGNED NOT NULL,
        PRIMARY KEY (kind, doc_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
    'CREATE TABLE IF NOT EXISTS sessions (
        token_hash CHAR(64) NOT NULL PRIMARY KEY,
        user_id INT UNSIGNED NOT NULL,
        expires INT UNSIGNED NOT NULL,
        KEY idx_user (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
    'CREATE TABLE IF NOT EXISTS attempts (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        ip VARCHAR(45) NOT NULL,
        login VARCHAR(64) NOT NULL,
        ts INT UNSIGNED NOT NULL,
        KEY idx_ip (ip),
        KEY idx_login (login)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
];

$open = !empty($cfg['open_access']); // режим «без пароля»: логин и пароль не создаются
$err = '';
$login = '';

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $postKey = (string)($_POST['key'] ?? '');
    $login = trim((string)($_POST['login'] ?? ''));
    $p1 = (string)($_POST['p1'] ?? '');
    $p2 = (string)($_POST['p2'] ?? '');

    if (!hash_equals($key, $postKey)) {
        $err = 'Неверный ключ установки. Он записан в config.php в строке setup_key.';
    } elseif (!$open && !preg_match('/^[A-Za-z0-9_.@-]{3,64}$/', $login)) {
        $err = 'Логин: от 3 до 64 символов, только латинские буквы, цифры и знаки _ . @ -';
    } elseif (!$open && strlen($p1) < 8) {
        $err = 'Пароль должен быть не короче 8 символов.';
    } elseif (!$open && $p1 !== $p2) {
        $err = 'Пароли не совпадают.';
    } else {
        try {
            foreach ($tables as $sql) {
                $pdo->exec($sql);
            }
            $n = (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
            if (!$open && $n > 0) {
                @unlink(__FILE__);
                page('Установка', '<h1>Уже установлено</h1><p>Владелец уже создан. Файл <code>setup.php</code> нужно удалить с сайта, если он ещё на месте.</p><p><a href="index.html">Открыть сайт</a></p>');
            }
            if (!$open) {
                $st = $pdo->prepare('INSERT INTO users (login, pass_hash, role, created_at) VALUES (?, ?, ?, ?)');
                $st->execute([$login, password_hash($p1, PASSWORD_DEFAULT), 'owner', time()]);
            }
            $moved = 0;
            $seedFile = __DIR__ . '/seed-data.php';
            if (file_exists($seedFile)) {
                $seed = require $seedFile;
                $ins = $pdo->prepare('INSERT INTO docs (kind, doc_id, body, updated_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE body = VALUES(body), updated_at = VALUES(updated_at)');
                foreach (['clients', 'visits', 'appts'] as $k) {
                    foreach (((is_array($seed) ? ($seed[$k] ?? []) : [])) as $sid => $sdoc) {
                        if (is_array($sdoc) && preg_match('/^[A-Za-z0-9_-]{1,40}$/', (string)$sid)) {
                            $ins->execute([$k, (string)$sid, json_encode($sdoc, JSON_UNESCAPED_UNICODE), time()]);
                            $moved++;
                        }
                    }
                }
                @unlink($seedFile);
            }
            @unlink(__FILE__);
            $gone = !file_exists(__FILE__);
            page('Готово', '<h1>Готово</h1><p>Таблицы созданы. '
                . ($open ? 'Сайт открывается без пароля.' : 'Владелец <b>' . h($login) . '</b> добавлен.') . '</p>'
                . ($moved ? '<p>Перенесено записей из прежней версии: ' . (int)$moved . '.</p>' : '')
                . ($gone
                    ? '<p>Файл <code>setup.php</code> удалён автоматически.</p>'
                    : '<p class="e"><b>Важно:</b> удалите файл <code>setup.php</code> с сайта вручную через файловый менеджер.</p>')
                . '<p><a href="index.html">' . ($open ? 'Открыть сайт' : 'Открыть сайт и войти') . '</a></p>');
        } catch (Throwable $e) {
            error_log('salon setup: ' . $e->getMessage());
            $err = 'Не удалось создать таблицы. Проверьте, что у пользователя базы есть права на создание таблиц.';
        }
    }
}

page('Установка', '<h1>Установка «Книги записи»</h1>'
    . ($open
        ? '<p>Сайт настроен без пароля (open_access в config.php). Введите только ключ установки.</p>'
        : '<p>Придумайте логин и пароль владельца. Эти данные нужны для входа на сайт.</p>')
    . ($err !== '' ? '<p class="e">' . h($err) . '</p>' : '')
    . '<form method="post" autocomplete="off">'
    . '<label for="key">Ключ установки (из config.php, строка setup_key)</label><input id="key" name="key" type="password" required>'
    . ($open ? '' :
        '<label for="login">Логин владельца (латиница, цифры)</label><input id="login" name="login" type="text" value="' . h($login) . '" required>'
        . '<label for="p1">Пароль (от 8 символов)</label><input id="p1" name="p1" type="password" required>'
        . '<label for="p2">Повторите пароль</label><input id="p2" name="p2" type="password" required>')
    . '<button type="submit">Установить</button></form>');
