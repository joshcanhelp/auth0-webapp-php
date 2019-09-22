<?php
declare(strict_types=1);

namespace Auth0\Auth\AuthSession;

use Auth0\Auth\Store\StoreInterface;

abstract class Base
{
    protected $store;
    protected $value;

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

    public function get() : string
    {
        if ( ! $this->value ) {
            $this->value = $this->store->get($this->getKey(), '');
        }
        $this->store->delete($this->getKey());
        return $this->value;
    }

    public function set( string $value ) : void
    {
        $this->store->set($this->getKey(), $value);
    }
}
