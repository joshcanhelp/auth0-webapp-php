<?php
namespace Auth0\Auth;

use Auth0\Auth\Exception\ConfigurationException;
use Auth0\Auth\Exception\HttpException;
use Auth0\Auth\Exception\IssuerException;
use Psr\SimpleCache\CacheInterface;

class Issuer
{
    use Traits\HttpRequests;

    protected $issuerBaseUrl;
    protected $cache;

    /**
     * Issuer constructor.
     *
     * @param null|string    $issuerBaseUrl
     * @param CacheInterface $cache
     *
     * @throws ConfigurationException
     */
    public function __construct( ?string $issuerBaseUrl, CacheInterface $cache )
    {
        if (! filter_var($issuerBaseUrl, FILTER_VALIDATE_URL) ) {
            throw new ConfigurationException('"issuerBaseUrl" must be a valid URL.');
        }

        $this->issuerBaseUrl = $issuerBaseUrl;
        $this->cache = $cache;
    }

    /**
     * @param string $key
     *
     * @return string|array|null
     * @throws IssuerException
     */
    public function getDiscoveryProp( string $key )
    {
        $openid_config = $this->cache->get('openid_configuration');
        if ($openid_config) {
            return $openid_config->$key ?? null;
        }

        $discovery_url = $this->issuerBaseUrl . '/.well-known/openid-configuration';
        try {
            $openid_config = $this->httpGet($discovery_url);
        } catch ( HttpException $e ) {
            $error_msg = 'HTTP error encountered while getting discovery document: ' . $e->getMessage();
            throw new IssuerException($error_msg, $e->getCode(), $e->getPrevious());
        }

        $this->cache->set('openid_configuration', $openid_config);
        return $openid_config->$key ?? null;
    }

    /**
     * @param array $params
     *
     * @throws IssuerException
     */
    public function validateParams( array $params )
    {
        if (empty($params['response_type'])) {
            throw new IssuerException('Response type parameter is missing.');
        }

        $response_types = $this->getDiscoveryProp('response_types_supported');
        if (! is_iterable($response_types) || ! in_array($params['response_type'], $response_types) ) {
            throw new IssuerException(sprintf('Response type %s not supported.', $params['response_type']));
        }

        if (empty($params['response_mode'])) {
            throw new IssuerException('Response mode parameter is missing.');
        }

        $response_modes = $this->getDiscoveryProp('response_modes_supported');
        if (! is_iterable($response_modes) || ! in_array($params['response_mode'], $response_modes) ) {
            throw new IssuerException(sprintf('Response mode %s not supported.', $params['response_mode']));
        }
    }

    /**
     * @param string $alg
     *
     * @throws IssuerException
     */
    public function validateIdTokenAlg( string $alg )
    {
        $id_token_signing_algs = $this->getDiscoveryProp('id_token_signing_alg_values_supported');
        if (! is_iterable($id_token_signing_algs) || ! in_array($alg, $id_token_signing_algs) ) {
            throw new IssuerException(sprintf('ID token alg %s not supported.', $alg));
        }
    }

    /**
     * @return array
     *
     * @throws IssuerException
     */
    public function getJwks() : array
    {
        $jwks = $this->cache->get('jwks');
        if ($jwks) {
            return $jwks;
        }

        try {
            $jwks_uri = $this->getDiscoveryProp('jwks_uri');
            $jwks = $this->httpGet($jwks_uri);
            $jwks = $this->prepareJwks($jwks);
        } catch ( \Exception $e ) {
            $error_msg = 'Problem getting JWKS: ' . $e->getMessage();
            throw new IssuerException($error_msg, $e->getCode(), $e->getPrevious());
        }


        $this->cache->set('jwks', $jwks);
        return $jwks;
    }

    /**
     * @param \stdClass $jwks
     *
     * @return array
     *
     * @throws IssuerException
     */
    protected function prepareJwks( \stdClass $jwks ) : array
    {
        if (empty($jwks->keys) && ! is_iterable($jwks->keys) ) {
            throw new IssuerException('No keys found in JWKS.');
        }

        $prepared_jwks = [];
        foreach ( $jwks->keys as $jwk ) {
            $prepared_jwks[$jwk->kid] = $this->convertCertToPem(current($jwk->x5c));
        }

        return $prepared_jwks;
    }

    /**
     * @param string $cert
     *
     * @return string
     */
    protected function convertCertToPem( string $cert ) : string
    {
        $split_string = chunk_split($cert, 64, PHP_EOL);
        return sprintf('-----BEGIN CERTIFICATE-----%s%s-----END CERTIFICATE-----%s', PHP_EOL, $split_string, PHP_EOL);
    }
}
