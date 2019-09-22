<?php
declare(strict_types=1);

namespace Auth0\Auth\AuthSession;

class State extends Base
{

    protected function getKey() : string
    {
        return 'auth_state';
    }

    public function create( array $state ) : string
    {
        $state['nonce'] = $this->createNonce();
        return base64_encode(json_encode($state));
    }

    /**
     * @param string $received_state
     *
     * @return string
     * @throws \Exception
     */
    public function getValidState( string $received_state ) : string
    {
        $stored_state = $this->get();
        if ( $received_state !== $stored_state ) {
            throw new \Exception('Invalid state');
        }
        return $stored_state;
    }
}
