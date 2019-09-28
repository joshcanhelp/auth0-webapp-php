<?php
namespace Auth0\Auth\Traits;

use Auth0\Auth\Exception\HttpException;
use Auth0\Auth\Exception\IssuerException;
use Auth0\Auth\Issuer;
use Auth0\Auth\TokenSet;
use GuzzleHttp\Client;

trait HttpRequests
{

    /**
     * @var Client
     */
    protected $httpClient;

    /**
     * @var Issuer
     */
    protected $issuer;

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
     * @param string $code
     *
     * @return \stdClass
     * @throws HttpException
     * @throws IssuerException
     */
    protected function httpExchangeCode( string $code ) : \stdClass
    {
        $token_ep_url = $this->issuer->getDiscoveryProp('token_endpoint');
        $body = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
            'code' => $code,
            'grant_type' => 'authorization_code'
        ];
        return $this->httpPost($token_ep_url, $body);
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
