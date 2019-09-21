<?php
declare(strict_types=1);

namespace Auth0\Auth\Traits;

trait AuthSession
{

    protected function getNonceKey() : string
    {
        return self::SESSION_BASE_NAME . 'auth_nonce';
    }

    protected function getStateKey() : string
    {
        return self::SESSION_BASE_NAME . 'auth_state';
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

    protected function createState( array $state ) : string
    {
        $state['nonce'] = $this->createNonce();
        return base64_encode( json_encode( $state ) );
    }

    protected function getNonce() : string
    {
        return $this->getAuthSession( $this->getNonceKey() );
    }

    /**
     * @param string $received_state
     *
     * @return string
     * @throws \Exception
     */
    protected function getValidState( string $received_state ) : string
    {
        $stored_state = $this->getAuthSession( $this->getStateKey() );
        if ( $received_state !== $stored_state ) {
            throw new \Exception( 'Invalid state' );
        }
        return $stored_state;
    }

    protected function getAuthSession( string $key ) : string
    {
        $nonce = $_COOKIE[$key] ?? '';
        $this->setNonce('');
        return $nonce;
    }

    protected function setNonce( string $value ) : bool
    {
        return $this->setAuthSession( $this->getNonceKey(), $value );
    }

    protected function setState( string $value ) : bool
    {
        return $this->setAuthSession( $this->getStateKey(), $value );
    }

    protected function setAuthSession( string $key, string $value ) : bool
    {
        $cookie_exp = $value ? time() + 5 * 60 : 0;
        return setcookie($key, $value, $cookie_exp, '/', '', false, true);
    }
}
