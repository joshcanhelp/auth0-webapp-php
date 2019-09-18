<?php
namespace Auth0\Auth;

use \stdClass;

final class TokenSet
{

    private $idToken;
    private $idTokenClaims;
    private $accessToken;
    private $refreshToken;

    public function __construct( stdClass $tokenObject )
    {
        $this->idToken = $tokenObject->id_token ?? null;
        $this->idTokenClaims = $tokenObject->id_token_claims ?? new stdClass;
        $this->accessToken = $tokenObject->access_token ?? null;
        $this->refreshToken = $tokenObject->refresh_token ?? null;
    }

    public function getClaim( string $claim = null ): string
    {
        return (string) $this->idTokenClaims->$claim ?? null;
    }

    public function setAccessToken( $access_token ): void
    {
        $this->accessToken = $access_token;
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function setRefreshToken( $refresh_token ): void
    {
        $this->refreshToken = $refresh_token;
    }

    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }
}
