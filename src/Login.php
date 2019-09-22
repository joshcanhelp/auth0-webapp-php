<?php
declare(strict_types=1);

/**
 * Contains class Login.
 *
 * @package Auth0\Auth
 */
namespace Auth0\Auth;

use Auth0\Auth\AuthSession\Nonce;
use Auth0\Auth\AuthSession\State;
use Auth0\Auth\Cache\MemoryCache;
use Auth0\Auth\Exception\Auth0Exception;
use Auth0\Auth\Exception\ConfigurationException;
use Auth0\Auth\Exception\HttpException;
use Auth0\Auth\Exception\IdTokenException;
use Auth0\Auth\Exception\IssuerException;
use Auth0\Auth\Store\CookieStore;
use Auth0\Auth\Store\StoreInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Class Login
 *
 * @package Auth0\Auth
 */
class Login
{
    use Traits\HttpRequests;

    const DEFAULT_ID_TOKEN_ALG = 'RS256';

    protected $issuerBaseUrl;
    protected $clientId;
    protected $redirectUri;
    protected $clientSecret;
    protected $idTokenAlg;
    protected $issuer;
    protected $stateStore;
    protected $nonceStore;
    protected $stateHandler;
    protected $nonceHandler;
    protected $tokenStore;
    protected $cache;

    /**
     * Login constructor.
     *
     * @param array $config
     *
     * @throws ConfigurationException
     * @throws IssuerException
     */
    public function __construct( array $config )
    {
        $this->issuerBaseUrl = $config['issuer_base_url'] ?? $_ENV['AUTH0_ISSUER_BASE_URL'] ?? null;
        if (! $this->issuerBaseUrl ) {
            throw new ConfigurationException('Issuer base URL is required.');
        }

        $this->clientId = $config['client_id'] ?? $_ENV['AUTH0_CLIENT_ID'] ?? null;
        if (! $this->clientId ) {
            throw new ConfigurationException('Client ID is required.');
        }

        $this->redirectUri = $config['redirect_uri'] ?? $_ENV['AUTH0_REDIRECT_URI'] ?? null;
        if (! $this->redirectUri ) {
            throw new ConfigurationException('"redirectUri" is required.');
        }

        $this->idTokenAlg = $config['id_token_alg'] ?? $_ENV['AUTH0_ID_TOKEN_ALG'] ?? self::DEFAULT_ID_TOKEN_ALG;

        $this->clientSecret = $config['client_secret'] ?? $_ENV['AUTH0_CLIENT_SECRET'] ?? null;
        if ('HS256' === $this->idTokenAlg && !$this->clientSecret) {
            throw new ConfigurationException('"clientSecret" is required when ID token algorithm is HS256.');
        }

        $stateStore = isset($config['auth_state_store']) && $config['auth_state_store'] instanceof StoreInterface ?
            $config['auth_state_store'] :
            new CookieStore();
        $this->stateHandler = new State($stateStore);

        $nonceStore = isset($config['auth_nonce_store']) && $config['auth_nonce_store'] instanceof StoreInterface ?
            $config['auth_nonce_store'] :
            new CookieStore();
        $this->nonceHandler = new Nonce($nonceStore);

        $cache = isset($config['cache']) && $config['cache'] instanceof CacheInterface ?
            $config['cache'] :
            new MemoryCache();

        $this->issuer = new Issuer($this->issuerBaseUrl, $cache);
        $this->issuer->validateIdTokenAlg($this->idTokenAlg);
    }

    /**
     * @param array $config
     *
     * @throws IssuerException
     */
    final public function loginWithRedirect( array $config = [] ): void
    {
        $auth0_login_url = $this->getAuthorizeUrl($config);
        header('Location: '.$auth0_login_url);
        exit;
    }

    /**
     * @param array $config
     *
     * @return string
     *
     * @throws IssuerException
     */
    final public function getAuthorizeUrl( array $config = [] ): string
    {
        $auth_ep_url = $this->issuer->getDiscoveryProp('authorization_endpoint');
        $auth_params = $this->prepareAuthParams($config);

        $this->nonceHandler->set($auth_params['nonce']);
        $this->stateHandler->set($auth_params['state']);

        return $auth_ep_url.'?'.http_build_query($auth_params);
    }

    /**
     * @return TokenSet|null
     *
     * @throws Auth0Exception
     */
    final public function callbackHandleIdToken() : ?TokenSet
    {
        $id_token = $_POST['id_token'] ?? '';
        if (!$id_token ) {
            return null;
        }

        $valid_state = $this->stateHandler->getValidState($_POST['state'] ?? null);
        $token_set = $this->decodeIdToken($id_token);
        $token_set->setState($valid_state);
        return $token_set;
    }

    /**
     * @return TokenSet|null
     *
     * @throws Auth0Exception
     * @throws HttpException
     */
    final public function callbackHandleCode() : ?TokenSet
    {
        $code = $_GET['code'] ?? $_POST['code'] ?? null;
        if (!$code) {
            return null;
        }

        $state = $_GET['state'] ?? $_POST['state'] ?? null;
        $valid_state = $this->stateHandler->getValidState($state);

        $token_ep_url = $this->issuer->getDiscoveryProp('token_endpoint');
        $code_exchange = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
            'code' => $code,
            'grant_type' => 'authorization_code'
        ];

        $token_obj = $this->httpPost($token_ep_url, $code_exchange);

        if (! empty($token_obj->error) ) {
            throw new Auth0Exception($token_obj->error_description ?? $token_obj->error);
        }

        $token_set = $token_obj->id_token ?$this->decodeIdToken($token_obj->id_token) : new TokenSet();
        $token_set->setAccessToken($token_obj);
        $token_set->setRefreshToken($token_obj);
        $token_set->setState($valid_state);

        return $token_set;
    }

    /**
     * @param string $id_token
     *
     * @return TokenSet
     * @throws IdTokenException
     */
    final public function decodeIdToken( string $id_token ) : TokenSet
    {
        $token_validator = new IdTokenVerifier(
            [
                'algorithm' => $this->idTokenAlg,
                'signature_key' => $this->getSignatureKey(),
                'client_id' => $this->clientId,
                'issuer' => $this->issuer->getDiscoveryProp('issuer'),
             ]
        );

        return $token_validator->decode($id_token, $this->nonceHandler->get());
    }

    final public function logoutWithRedirect( $federated = false ) : void
    {
        $this->logout();
        $auth0_logout_url = sprintf(
            '%s/vs/logout?client_id=%s',
            $this->issuerBaseUrl,
            $this->clientId,
            $federated ? '&federated' : ''
        );
        header('Location: '.$auth0_logout_url);
    }

    /**
     * @param array $config
     *
     * @return array
     *
     * @throws IssuerException
     */
    public function prepareAuthParams( array $config ): array
    {
        $audience    = $config['audience'] ?? null;
        $auth_params = [
            'client_id'     => $this->clientId,
            'redirect_uri'  => $this->redirectUri,
            'audience'      => $audience,
            'connection'    => $config['connection'] ?? null,
            'nonce'         => $this->nonceHandler->createNonce(),
            'state'         => $this->stateHandler->create($config['state'] ?? []),
            'prompt'        => $config['prompt'] ?? null,
            'response_mode' => $config['response_mode'] ?? 'form_post',
            'response_type' => $config['response_type'] ?? ( $audience ? 'code id_token' : 'id_token' ),
            'scope'         => $config['scope'] ?? 'openid profile email',
        ];
        $auth_params = array_filter($auth_params);
        $this->issuer->validateParams($auth_params);
        return $auth_params;
    }

    public function logout()
    {
        // TODO: Clear session
    }

    public function getSignatureKey()
    {
        switch( $this->idTokenAlg ) {
        case 'RS256':
            return $this->issuer->getJwks();

        case 'HS256':
            return $this->clientSecret;
        }

        return null;
    }

    public function isAuthenticated() : bool
    {
        return false;
    }

    public function getUser()
    {
    }
}
