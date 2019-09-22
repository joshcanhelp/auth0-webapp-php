<?php
namespace Auth0\Auth\Store;

interface StoreInterface
{
    const BASE_NAME = 'auth0_';

    public function set( string $key, $value );

    public function get( string $key, $default = null );

    public function delete( string $key );

    public function clear();

    public function getKeyName( string $key ) : string;
}
