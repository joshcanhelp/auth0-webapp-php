<?php

namespace Auth0\Auth\Store;

class CookieStore implements StoreInterface
{
    const BASE_NAME = 'auth0_';

    public function set($key, $value)
    {
        setcookie($this->getKeyName($key), $value, time() + 5 * 60, '/', '', false, true);
    }

    public function get($key, $default = null)
    {
        return $_COOKIE[$this->getKeyName($key)] ?? $default;
    }

    public function delete( $key )
    {
        setcookie($this->getKeyName($key), '', 0, '/');
    }

    public function getKeyName( string $key )
    {
        return self::BASE_NAME.$key;
    }
}
