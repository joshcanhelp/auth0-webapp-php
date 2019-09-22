<?php

namespace Auth0\Auth\Store;

class SessionStore implements StoreInterface
{
    public function __construct()
    {
        if (! session_id()) {
            session_start();
        }
    }

    public function set($key, $value)
    {
        $_SESSION[$this->getKeyName($key)] = $value;
    }

    public function get($key, $default = null)
    {
        return $_SESSION[$this->getKeyName($key)] ?? $default;
    }

    public function delete( $key )
    {
        unset($_SESSION[$this->getKeyName($key)]);
    }

    public function getKeyName( string $key ) : string
    {
        return self::BASE_NAME.$key;
    }
}
