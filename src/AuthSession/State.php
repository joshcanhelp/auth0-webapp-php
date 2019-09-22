<?php
declare(strict_types=1);

namespace Auth0\Auth\AuthSession;

use Auth0\Auth\Exception\Auth0Exception;
use \stdClass;

class State extends Base
{

    protected function getKey() : string
    {
        return 'auth_state';
    }

    public function create( array $state ) : string
    {
        $state['nonce'] = $this->createNonce();
        return self::encode($state);
    }

    /**
     * @param null|string $received_state
     *
     * @return string
     *
     * @throws Auth0Exception
     */
    public function getValidState( ?string $received_state ) : string
    {
        $stored_state = $this->get();
        if ($received_state !== $stored_state ) {
            throw new Auth0Exception('Invalid state');
        }
        return $stored_state;
    }

    public static function encode( array $state ) : string
    {
        return base64_encode(json_encode($state));
    }

    public static function decode( string $state ) : stdClass
    {
        return json_decode(base64_decode($state));
    }
}
