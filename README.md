## DokuWiki auth backend for PLD Linux Wiki

### Setup instructions
- copy all files to `lib/plugins/authpld`
- setup `groups`, `passwd` and `users` files in `DOKU_LOCAL/pld`
  (`/etc/webapps/dokuwiki/pld` in PLD packages). When `DOKU_LOCAL` is not defined,
  the plugin uses `DOKU_CONF/pld` (`conf/pld` in a standard DokuWiki installation).
- set `$conf['authtype'] = 'authpld';` in `local.php` or `local.protected.php`
  in that configuration directory

Targets DokuWiki 2026-07-14c (Mort). The backend advertises read-only access;
account changes must be made in the PLD files.

### File formats

- `passwd`: `login:password-hash:groups[:metadata[:name[:status]]]`.
  Groups are dot-separated; `cvs` is mapped to `user`. The name is URL-decoded
  and defaults to an empty string. An absent or empty status, or `Enable`,
  permits login; other statuses and logins starting with `builder` are excluded.
- `users` (optional): `login:mail:name[:jid]`. Nonempty names override the name
  from `passwd`; JID is optional. Mail remains `login@pld-linux.org`.
- `groups` (optional): `login:group1,group2`. These groups supplement those from
  `passwd`; `readonly` removes `user` when applying the entry.

Blank lines and `#` comments are ignored. Records missing required columns are
skipped; only accounts present in `passwd` can receive additional data or groups.

### Tests

Tests use DokuWiki's PHPUnit runner and the real `authplain` base class.
Install this checkout as `lib/plugins/authpld` in a DokuWiki source checkout,
then run:

```sh
cd /path/to/dokuwiki/_test
composer install
php vendor/bin/phpunit --group plugin_authpld
```
