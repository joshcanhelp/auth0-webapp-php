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
use Auth0\Auth\Store\CookieStore;
use Auth0\Auth\Store\SessionStore;
use Auth0\Auth\Store\StoreInterface;
use Auth0\Auth\Traits\HttpRequests;
use Psr\SimpleCache\CacheInterface;

/**
 * Class Login
 *
 * @package Auth0\Auth
 */
class Login
{
    use HttpRequests;

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

    public function __construct( array $config )
    {
        $this->issuerBaseUrl = $config['issuer_base_url'] ?? $_ENV['AUTH0_ISSUER_BASE_URL'] ?? null;
        if (! $this->issuerBaseUrl ) {
            throw new \Exception('Issuer base URL is required.');
        }

        $this->clientId = $config['client_id'] ?? $_ENV['AUTH0_CLIENT_ID'] ?? null;
        if (! $this->clientId ) {
            throw new \Exception('Client ID is required.');
        }

        $this->redirectUri = $config['redirect_uri'] ?? $_ENV['AUTH0_REDIRECT_URI'] ?? null;
        if (! $this->redirectUri ) {
            throw new \Exception('"redirectUri" is required.');
        }

        $this->idTokenAlg = $config['id_token_alg'] ?? $_ENV['AUTH0_ID_TOKEN_ALG'] ?? self::DEFAULT_ID_TOKEN_ALG;

        $this->clientSecret = $config['client_secret'] ?? $_ENV['AUTH0_CLIENT_SECRET'] ?? null;
        if ('HS256' === $this->idTokenAlg && !$this->clientSecret) {
            throw new \Exception('"clientSecret" is required when ID token algorithm is HS256.');
        }

        $stateStore = isset( $config['auth_state_store'] ) && $config['auth_state_store'] instanceof StoreInterface ?
            $config['auth_state_store'] :
            new CookieStore();
        $this->stateHandler = new State( $stateStore );

        $nonceStore = isset( $config['auth_nonce_store'] ) && $config['auth_nonce_store'] instanceof StoreInterface ?
            $config['auth_nonce_store'] :
            new CookieStore();
        $this->nonceHandler = new Nonce( $nonceStore );

        $cache = isset( $config['cache'] ) && $config['cache'] instanceof CacheInterface ?
            $config['cache'] :
            new MemoryCache();

        $this->issuer = new Issuer($this->issuerBaseUrl, $cache);
        $this->issuer->validateIdTokenAlg( $this->idTokenAlg );
    }

    final public function loginWithRedirect( array $config = [] ): void
    {
        $auth0_login_url = $this->getAuthorizeUrl($config);
        header('Location: '.$auth0_login_url);
        exit;
    }

    final public function getAuthorizeUrl( array $config = [] ): string
    {
        $auth_ep_url = $this->issuer->getDiscoveryProp('authorization_endpoint');
        $auth_params = $this->prepareAuthParams($config);

        $this->nonceHandler->set($auth_params['nonce']);
        $this->stateHandler->set($auth_params['state']);

        return $auth_ep_url.'?'.http_build_query($auth_params);
    }

    final public function callbackHandleIdToken() : TokenSet
    {
        $id_token = $_POST['id_token'] ?? '';
        if (!$id_token ) {
            return new TokenSet();
        }

        return $this->decodeIdToken($id_token);
    }

    final public function callbackHandleCode() : TokenSet
    {
        $tokens = new TokenSet();

        // TODO: What about GET?
        $code = $_POST['code'] ?? null;
        if (!$code) {
            return $tokens;
        }

        $valid_state = $this->stateHandler->getValidState($_POST['state'] ?? '');

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
            throw new \Exception($token_obj->error_description ?? $token_obj->error);
        }

        if ($token_obj->id_token ) {
            $tokens = $this->decodeIdToken($token_obj->id_token);
        }

        $tokens->setAccessToken($token_obj);
        $tokens->setRefreshToken($token_obj);
        $tokens->setState($valid_state);

        return $tokens;
    }

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
        $this->issuer->validateParams( $auth_params );
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
