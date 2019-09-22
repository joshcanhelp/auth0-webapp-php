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

    public function set( string $key, $value )
    {
        $_SESSION[$this->getKeyName($key)] = $value;
    }

    public function get( string $key, $default = null )
    {
        return $_SESSION[$this->getKeyName($key)] ?? $default;
    }

    public function delete( string $key )
    {
        unset($_SESSION[$this->getKeyName($key)]);
    }

    public function clear()
    {
        foreach ( array_keys( $_SESSION ) as $key ) {
            if ( StoreInterface::BASE_NAME === substr( $key, 0, strlen( StoreInterface::BASE_NAME ) ) ) {
                $this->delete( $key );
            }
        }
    }

    public function getKeyName( string $key ) : string
    {
        return self::BASE_NAME.$key;
    }
}
