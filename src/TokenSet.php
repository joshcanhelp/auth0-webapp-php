<?php
namespace Auth0\Auth;

use Auth0\Auth\AuthSession\State;
use \stdClass;

final class TokenSet
{

    private $idToken;
    private $claims;
    private $accessToken;
    private $accessTokenScopes;
    private $accessTokenExpiresIn;
    private $refreshToken;
    private $state;

    public function __construct( ?stdClass $tokenObject = null )
    {
        $tokenObject        = $tokenObject ?? new stdClass();
        $this->idToken      = $tokenObject->id_token ?? null;
        $this->claims       = $tokenObject->claims ?? new stdClass;
        $this->accessToken  = $tokenObject->access_token ?? null;
        $this->refreshToken = $tokenObject->refresh_token ?? null;
    }

    public function getClaim( ?string $claim ): ?string
    {
        return (string) $this->claims->$claim ?? null;
    }

    public function getClaims(): stdClass
    {
        return $this->claims;
    }

    public function setAccessToken( stdClass $tokens ): void
    {
        $this->accessToken = $tokens->access_token ?? null;
        $this->accessTokenExpiresIn = intval($tokens->expires_in ?? 0);
        $this->accessTokenScopes = $tokens->scopes ?? null;
    }

    public function getAccessToken() : string
    {
        return $this->accessToken;
    }

    public function getAccessTokenExpiresIn() : int
    {
        return $this->accessTokenExpiresIn;
    }

    public function getAccessTokenScopes() : string
    {
        return $this->accessTokenScopes;
    }

    public function setRefreshToken( stdClass $tokens ) : void
    {
        $this->refreshToken = $tokens->refresh_token ?? null;
    }

    public function getRefreshToken() : string
    {
        return $this->refreshToken;
    }

    public function setState( string $state ) : void
    {
        $this->state = $state;
    }

    public function getState() : stdClass
    {
        $decoded_state = State::decode($this->state);
        return $decoded_state ?? new stdClass();
    }
}
