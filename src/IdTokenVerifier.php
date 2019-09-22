<?php

namespace Auth0\Auth;

use Auth0\Auth\Exception\IdTokenException;
use Auth0\Auth\Exception\ConfigurationException;
use Firebase\JWT\JWT;

class IdTokenVerifier
{

    /**
     * @var string
     */
    protected $algorithm;

    /**
     * @var string
     */
    protected $signature_key;


    /**
     * @var string
     */
    protected $client_id;

    /**
     * @var string
     */
    protected $issuer;

    /**
     * IdTokenVerifier constructor.
     *
     * @param array $config
     *
     * @throws ConfigurationException
     */
    public function __construct( array $config )
    {
        // Token algorithm to verify signature.
        if (empty($config['algorithm']) || ! in_array($config['algorithm'], [ 'HS256', 'RS256' ])) {
            throw new ConfigurationException('Config key "algorithm" is required to be HS256 or RS256');
        }

        $this->algorithm = (string) $config['algorithm'];

        // Need a signature key or JwksFetcher to verify token signature.
        if (empty($config['signature_key'])) {
            throw new ConfigurationException('Config key "signature_key" is required');
        }

        $this->signature_key = $config['signature_key'];

        // Client ID to validate aud and azp claim.
        if (empty($config['client_id'])) {
            throw new ConfigurationException('Config key "client_id" is required');
        }

        $this->client_id = (string) $config['client_id'];

        // Issuer to validate where the token came from.
        if (empty($config['issuer'])) {
            throw new ConfigurationException('Config key "issuer" is required');
        }

        $this->issuer = (string) $config['issuer'];
    }

    /**
     * @param string $jwt
     * @param string $nonce
     *
     * @return TokenSet
     *
     * @throws IdTokenException
     */
    public function decode( string $jwt, string $nonce ) : TokenSet
    {
        try {
            $jwt_obj = $this->decodeToken($jwt, $this->signature_key);
        } catch (\Exception $e) {
            throw new IdTokenException($e->getMessage(), $e->getCode(), $e->getPrevious());
        }

        // Check if nonce is valid.
        if (empty($jwt_obj->nonce) || $jwt_obj->nonce !== $nonce ) {
            throw new IdTokenException('Invalid token nonce');
        }
        unset($jwt_obj->nonce);

        // Check if expiration is missing.
        if (empty($jwt_obj->exp)) {
            throw new IdTokenException('Missing token exp');
        }

        // Check if issued-at is missing.
        if (empty($jwt_obj->iat)) {
            throw new IdTokenException('Missing token iat');
        }

        // Check if issuer is missing.
        if (empty($jwt_obj->iss) || $jwt_obj->iss !== $this->issuer) {
            throw new IdTokenException('Invalid token iss');
        }

        // Check if audience is missing.
        if (empty($jwt_obj->aud)) {
            throw new IdTokenException('Missing token aud');
        }

        // Check if the token audience is allowed.
        $token_aud = is_array($jwt_obj->aud) ? $jwt_obj->aud : [$jwt_obj->aud];
        if (! in_array($this->client_id, $token_aud)) {
            throw new IdTokenException('Invalid token aud');
        }

        // Check token azp value if token contains multiple audiences.
        if (count($token_aud) > 1 && (empty($jwt_obj->azp) || $jwt_obj->azp !== $this->client_id)) {
            throw new IdTokenException('Invalid token azp');
        }

        return new TokenSet((object) [ 'id_token' => $jwt, 'claims' => $jwt_obj ]);
    }

    /**
     * Wrapper for JWT::decode().
     *
     * @param string       $jwt    JWT to decode.
     * @param string|array $secret Secret to use.
     *
     * @return mixed
     *
     * @codeCoverageIgnore
     */
    protected function decodeToken( string $jwt, $secret ) : \stdClass
    {
        return JWT::decode($jwt, $secret, [ $this->algorithm ]);
    }
}
