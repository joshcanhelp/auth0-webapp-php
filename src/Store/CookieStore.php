<?php

namespace Auth0\Auth\Store;

class CookieStore implements StoreInterface
{
    public function set($key, $value) : bool
    {
        return setcookie($this->getKeyName($key), $value, time() + 5 * 60, '/', '', false, true);
    }

    public function get($key, $default = null)
    {
        return $_COOKIE[$this->getKeyName($key)] ?? $default;
    }

    public function delete( $key ) : bool
    {
        unset( $_COOKIE[$this->getKeyName($key)] );
        return setcookie($this->getKeyName($key), '', 0, '/');
    }

    public function getKeyName( string $key ) : string
    {
        return self::BASE_NAME.$key;
    }
}
