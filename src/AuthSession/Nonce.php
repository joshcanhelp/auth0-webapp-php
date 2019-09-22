<?php
declare(strict_types=1);

namespace Auth0\Auth\AuthSession;

class Nonce extends Base
{

    protected function getKey() : string
    {
        return self::KEY_PREFIX . 'auth_nonce';
    }
}
