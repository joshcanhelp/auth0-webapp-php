<?php
namespace Auth0\Auth;

use Auth0\Auth\Traits;

class Issuer
{
    use Traits\HttpRequests;

    protected $jwks;
    protected $issuerBaseUrl;protected $discoveryDoc;

    public function __construct( string $issuerBaseUrl )
    {
        $this->issuerBaseUrl = $issuerBaseUrl;
    }

    /**
     * @param $key
     *
     * @return mixed
     *
     * @throws \Exception
     * @throws \Http\Client\Exception
     */
    public function getDiscoveryValue( string $key ) : string
    {
        // TODO: Caching
        if ($this->discoveryDoc ) {
            return $this->discoveryDoc->$key;
        }

        // TODO: Config value testing
        // TODO: HTTP error handling
        $discovry_url = $this->issuerBaseUrl . '/.well-known/openid-configuration';
        $this->discoveryDoc = $this->httpRequest($discovry_url);
        return $this->discoveryDoc->$key ?? null;
    }

    /**
     * @return mixed
     *
     * @throws \Exception
     * @throws \Http\Client\Exception
     */
    public function getJwks() : array
    {
        // TODO: Caching
        if ($this->jwks ) {
            return $this->jwks;
        }

        // TODO: Config value testing
        // TODO: HTTP error handling
        $jwks_uri = $this->getDiscoveryValue('jwks_uri');
        $jwks = $this->httpRequest($jwks_uri);
        $this->jwks = $this->prepareJwks($jwks);
        return $this->jwks;
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
