<?php
namespace Auth0\Auth\Traits;

trait DiscoveryDoc
{

    protected $discoveryDoc;

    /**
     * @param $key
     *
     * @return mixed
     *
     * @throws \Exception
     * @throws \Http\Client\Exception
     */
    protected function getDiscoveryValue( $key )
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
}
