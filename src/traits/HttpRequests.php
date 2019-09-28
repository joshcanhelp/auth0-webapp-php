<?php
namespace Auth0\Auth\Traits;

use Auth0\Auth\Exception\HttpException;
use Auth0\Auth\TokenSet;
use GuzzleHttp\Client;

trait HttpRequests
{

    protected $httpClient;
    protected $httpMessageFactory;

    /**
     * @param string        $url
     * @param TokenSet|null $token_set
     *
     * @return \stdClass
     *
     * @throws HttpException
     */
    protected function httpGet( string $url, ?TokenSet $token_set = null ) : \stdClass
    {
        $headers = $token_set ? [ 'Authorization' => 'Bearer ' . $token_set->getAccessToken() ] : [];
        return $this->httpRequest('GET', $url, $headers);
    }

    /**
     * @param string $url
     * @param array  $body
     *
     * @return \stdClass
     * @throws HttpException
     */
    protected function httpPost( string $url, array $body ) : \stdClass
    {
        $headers = [ 'Content-Type' => 'application/json' ];
        return $this->httpRequest('POST', $url, $headers, $body);
    }

    /**
     * @param string $method
     * @param string $url
     * @param array  $headers
     * @param array  $body
     *
     * @return \stdClass
     *
     * @throws HttpException
     */
    protected function httpRequest( string $method, string $url, array $headers = [], array $body = [] ) : \stdClass
    {
        if (! $this->httpClient ) {
            $this->httpClient = new Client();
        }

        $body = json_encode($body);

        $request_options = [
            'headers' => $headers,
            'body' => $body,
        ];

        try {
            $response = $this->httpClient->request($method, $url, $request_options);
            $body = (string) $response->getBody();
            if (strpos($response->getHeaderLine('content-type'), 'json') !== false) {
                $body = json_decode($body);
            }
        } catch (\Exception $e) {
            throw new HttpException($e->getMessage(), $e->getCode(), $e->getPrevious());
        }

        return $body;
    }
}
