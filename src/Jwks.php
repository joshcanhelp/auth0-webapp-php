<?php
namespace Auth0\Auth;

use Auth0\Auth\Traits;

class Jwks
{
    use Traits\DiscoveryDoc;
    use Traits\HttpRequests;

    protected $jwks;
    protected $issuerBaseUrl;

    public function __construct( $issuerBaseUrl )
    {
        $this->issuerBaseUrl = $issuerBaseUrl;
    }

    /**
     * @return mixed
     *
     * @throws \Exception
     * @throws \Http\Client\Exception
     */
    public function get()
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

    protected function prepareJwks( $jwks )
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

    protected function convertCertToPem($cert)
    {
        $split_string = chunk_split($cert, 64, PHP_EOL);
        return sprintf('-----BEGIN CERTIFICATE-----%s%s-----END CERTIFICATE-----%s', PHP_EOL, $split_string, PHP_EOL);
    }
}
