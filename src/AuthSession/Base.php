<?php
declare(strict_types=1);

namespace Auth0\Auth\AuthSession;

use Auth0\Auth\Store\StoreInterface;

abstract class Base
{
    const KEY_PREFIX = 'auth0_';

    protected $store;

    public function __construct( StoreInterface $store )
    {
        $this->store = $store;
    }

    abstract protected function getKey() : string;

    public function createNonce( int $bytes = 32 ) : string
    {
        try {
            $nonce_bits = random_bytes($bytes);
        } catch ( \Exception $e ) {
            $nonce_bits = openssl_random_pseudo_bytes($bytes);
        }

        return bin2hex($nonce_bits);
    }

    public function get()
    {
        $value = $this->store->get($this->getKey());
        $this->set('');
        return $value;
    }

    public function set( string $value )
    {
        $this->store->set($this->getKey(), $value);
    }
}
