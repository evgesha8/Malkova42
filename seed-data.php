<?php
// Данные из прежней версии. Установщик перенесёт их в базу и удалит этот файл.
$data = <<<'JSONEND'
{
 "clients": {
  "mw7itjcboh6eo": {
   "name": "Надежда",
   "phone": "89089654444",
   "note": "",
   "createdAt": 1794123519275
  }
 },
 "visits": {
  "mw7ixp20ogchi": {
   "clientId": "mw7itjcboh6eo",
   "comment": "Окрашивание ( 100г краски длинна 50мм)",
   "createdAt": 1794123713304,
   "date": "2026-11-08",
   "price": 10000
  }
 },
 "appts": {
  "mw7itjcbt1jsb": {
   "clientId": "mw7itjcboh6eo",
   "createdAt": 1794123519611,
   "date": "2026-11-08",
   "done": true,
   "dur": 240,
   "name": "Надежда",
   "phone": "89089654444",
   "service": "Окрашивание",
   "time": "17:00"
  }
 }
}
JSONEND;
return json_decode($data, true);
