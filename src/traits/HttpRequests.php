<?php
namespace Auth0\Auth\Traits;

use Http\Discovery\HttpClientDiscovery;
use Http\Discovery\MessageFactoryDiscovery;
use \stdClass;

trait HttpRequests
{

    protected $httpClient;
    protected $httpMessageFactory;

    /**
     * @param $url
     * @param string $method
     * @param array  $body
     *
     * @return mixed
     * @throws \Exception
     * @throws \Http\Client\Exception
     */
    protected function httpRequest( string $url, string $method = 'GET', array $body = null ): stdClass
    {
        if (! $this->httpClient ) {
            $this->httpClient = HttpClientDiscovery::find();
        }

        if (! $this->httpMessageFactory ) {
            $this->httpMessageFactory = MessageFactoryDiscovery::find();
        }

        $message = $this->httpMessageFactory->createRequest($method, $url, [], $body);
        $response = $this->httpClient->sendRequest($message)->getBody();
        return json_decode($response);
    }
}
