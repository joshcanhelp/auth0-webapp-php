<?php

namespace Auth0\Auth\Store;

class CookieStore implements StoreInterface
{
    public function set( string $key, $value ) : bool
    {
        return setcookie($this->getKeyName($key), $value, time() + 5 * 60, '/', '', false, true);
    }

    public function get( string $key, $default = null )
    {
        return $_COOKIE[$this->getKeyName($key)] ?? $default;
    }

    public function delete( string $key ) : bool
    {
        unset( $_COOKIE[$this->getKeyName($key)] );
        return setcookie($this->getKeyName($key), '', 0, '/');
    }

    public function clear()
    {
        foreach ( array_keys( $_COOKIE ) as $key ) {
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
