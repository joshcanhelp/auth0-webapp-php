<?php
namespace Auth0\Auth\Traits;

trait Jwks {

    protected $jwks;

    /**
     * @return mixed
     *
     * @throws \Exception
     * @throws \Http\Client\Exception
     */
    protected function getJwks()
    {
        // TODO: Caching
        if ( $this->jwks ) {
            return $this->jwks;
        }

        // TODO: Config value testing
        // TODO: HTTP error handling
        $jwks_uri = $this->getDiscoveryValue( 'jwks_uri' );
        $jwks = $this->httpRequest( $jwks_uri );
        $this->jwks = $this->prepareJwks( $jwks );
        return $this->jwks;
    }

    protected function prepareJwks( $jwks ) {
        if ( empty( $jwks->keys ) && ! is_iterable( $jwks->keys ) ) {
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
        return sprintf(
            '-----BEGIN CERTIFICATE-----%s%s-----END CERTIFICATE-----%s',
            PHP_EOL,
            chunk_split($cert, 64, PHP_EOL),
            PHP_EOL
        );
    }
}
