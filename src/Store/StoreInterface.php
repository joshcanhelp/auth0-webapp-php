<?php
namespace Auth0\Auth\Store;

interface StoreInterface
{
    const BASE_NAME = 'auth0_';

    public function set($key, $value);

    public function get($key, $default = null);

    public function delete($key);

    public function getKeyName( string $key ) : string;
}
