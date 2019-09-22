<?php
namespace Auth0\Auth;

use Auth0\Auth\Traits;
use Psr\SimpleCache\CacheInterface;

class Issuer
{
    use Traits\HttpRequests;

    protected $issuerBaseUrl;
    protected $cache;

    public function __construct( ?string $issuerBaseUrl, CacheInterface $cache )
    {
        if ( ! filter_var( $issuerBaseUrl, FILTER_VALIDATE_URL ) ) {
            throw new \Exception( '"issuerBaseUrl" must be a valid URL.' );
        }

        $this->issuerBaseUrl = $issuerBaseUrl;
        $this->cache = $cache;
    }

    public function getDiscoveryProp( string $key )
    {
        $openid_config = $this->cache->get( 'openid_configuration' );
        if ($openid_config) {
            return $openid_config->$key;
        }

        $discovery_url = $this->issuerBaseUrl . '/.well-known/openid-configuration';
        $openid_config = $this->httpGet($discovery_url);
        $this->cache->set( 'openid_configuration', $openid_config );
        return $openid_config->$key ?? null;
    }

    public function getJwks() : array
    {
        $jwks = $this->cache->get( 'jwks' );
        if ($jwks) {
            return $jwks;
        }

        $jwks_uri = $this->getDiscoveryProp('jwks_uri');
        $jwks = $this->httpGet($jwks_uri);
        $jwks = $this->prepareJwks($jwks);
        $this->cache->set( 'jwks', $jwks );
        return $jwks;
    }

    public function validateParams( array $params ) {
        $response_types = $this->getDiscoveryProp( 'response_types_supported' );
        if ( ! is_iterable( $response_types ) || ! in_array( $params['response_type'], $response_types ) ) {
            throw new \Exception( sprintf( 'Response type %s not supported.', $params['response_type'] ) );
        }

        $response_modes = $this->getDiscoveryProp( 'response_modes_supported' );
        if ( ! is_iterable( $response_modes ) || ! in_array( $params['response_mode'], $response_modes ) ) {
            throw new \Exception( sprintf( 'Response mode %s not supported.', $params['response_mode'] ) );
        }
    }

    public function validateIdTokenAlg( string $alg ) {
        $id_token_signing_algs = $this->getDiscoveryProp( 'id_token_signing_alg_values_supported' );
        if ( ! is_iterable( $id_token_signing_algs ) || ! in_array( $alg, $id_token_signing_algs ) ) {
            throw new \Exception( sprintf( 'ID token alg %s not supported.', $alg ) );
        }
    }

    protected function prepareJwks( \stdClass $jwks ) : array
    {
        if (empty($jwks->keys) && ! is_iterable($jwks->keys) ) {
            return [];
        }

        $prepared_jwks = [];
        foreach ( $jwks->keys as $jwk ) {
            $prepared_jwks[$jwk->kid] = $this->convertCertToPem(current($jwk->x5c));
        }

        return $prepared_jwks;
    }

    protected function convertCertToPem( string $cert ) : string
    {
        $split_string = chunk_split($cert, 64, PHP_EOL);
        return sprintf('-----BEGIN CERTIFICATE-----%s%s-----END CERTIFICATE-----%s', PHP_EOL, $split_string, PHP_EOL);
    }
}
