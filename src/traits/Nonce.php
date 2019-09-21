<?php
namespace Auth0\Auth\Traits;

trait Nonce
{

    protected function getNonceKey() : string
    {
        return 'auth0_nonce';
    }

    protected function createNonce( int $bytes = 32 ) : string
    {
        try {
            $nonce_bits = random_bytes($bytes);
        } catch ( \Exception $e ) {
            $nonce_bits = openssl_random_pseudo_bytes($bytes);
        }

        return bin2hex($nonce_bits);
    }

    protected function getNonce() : string
    {
        $nonce = $_COOKIE[$this->getNonceKey()] ?? '';
        $this->setNonce('');
        return $nonce;
    }

    protected function setNonce( string $value ) : bool
    {
        $cookie_exp = $value ? time() + 5 * 60 : 0;
        return setcookie($this->getNonceKey(), $value, $cookie_exp, '/', '', false, true);
    }
}
