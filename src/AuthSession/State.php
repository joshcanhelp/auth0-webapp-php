<?php
declare(strict_types=1);

namespace Auth0\Auth\AuthSession;

class State extends Base
{

    protected function getKey() : string
    {
        return self::KEY_PREFIX . 'auth_state';
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
        if ($received_state !== $this->get() ) {
            throw new \Exception('Invalid state');
        }
        return $this->get();
    }
}
