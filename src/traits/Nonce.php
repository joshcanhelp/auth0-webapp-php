<?php
namespace Auth0\Auth\Traits;

trait Nonce {

    protected function getNonceKey() {
        return 'auth0_nonce';
    }

    protected function createNonce( $bytes = 32 ) {
        try {
            $nonce_bits = random_bytes( $bytes );
        } catch ( \Exception $e ) {
            $nonce_bits = openssl_random_pseudo_bytes( $bytes );
        }

        return bin2hex( $nonce_bits );
    }

    protected function getNonce() {
        $nonce = $_COOKIE[$this->getNonceKey()] ?? null;
        $this->setNonce('');
        return $nonce;
    }

    protected function setNonce( $value ) {
        $cookie_exp = $value ? time() + 5 * 60 : 0;
        return setcookie( $this->getNonceKey(), $value, $cookie_exp, '/', '', false, true );
    }
}
