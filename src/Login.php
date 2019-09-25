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
use Auth0\Auth\Exception\AuthException;
use Auth0\Auth\Exception\ConfigurationException;
use Auth0\Auth\Exception\HttpException;
use Auth0\Auth\Exception\IdTokenException;
use Auth0\Auth\Exception\IssuerException;
use Auth0\Auth\Store\CookieStore;
use Auth0\Auth\Store\SessionStore;
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
    protected $idTokenAlg;
    protected $clientSecret;
    protected $defaultAuthParams;
    protected $getClaimsFromUserinfo;
    protected $issuer;
    protected $userStore;
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

        $this->defaultAuthParams = [
            'response_type' => 'id_token',
            'response_mode' => 'form_post',
            'scope' => 'openid profile email',
        ];

        if ( ! empty( $config['authorization_params'] ) && is_iterable( $config['authorization_params'] ) ) {
            $this->defaultAuthParams = array_replace( $this->defaultAuthParams, (array) $config['authorization_params'] );
        }

        /*
         * Get the user profile from the userinfo endpoint.
         * Requires a response_type including "code" when logging in.
         */
        $this->getClaimsFromUserinfo = $config['get_claims_from_userinfo'] ?? false;

        /*
         * This sets the storage engine for persisting the user profile returned from the issuer.
         */
        if ( $config['persist_user'] ?? true ) {
            $this->userStore = isset($config['user_store']) && $config['user_store'] instanceof StoreInterface ?
                $config['user_store'] :
                new SessionStore();
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
        $this->issuer->validateParams($this->defaultAuthParams);
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
     * @throws AuthException
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
     * @throws AuthException
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

        if ( $this->userStore ) {
            $this->userStore->set( 'user', $token_set->getClaims() );
        }

        return $token_set;
    }

    /**
     * @return TokenSet|null
     *
     * @throws AuthException
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
            throw new AuthException( $token_obj->error_description ?? $token_obj->error);
        }

        $token_set = ! empty( $token_obj->id_token ) ? $this->decodeIdToken($token_obj->id_token) : new TokenSet();
        $token_set->setAccessToken($token_obj);
        $token_set->setRefreshToken($token_obj);
        $token_set->setState($valid_state);

        if ( $this->getClaimsFromUserinfo && $token_set->getAccessToken() ) {
            $userinfo_ep = $this->issuer->getDiscoveryProp( 'userinfo_endpoint' );
            $userinfo_claims = $this->httpGet( $userinfo_ep, $token_set );
            $token_set->setClaims( $userinfo_claims );
            $this->userStore->set( 'user', $token_set->getClaims() );
        }

        // TODO: Do we need to set this higher?
        if ( ! $this->isAuthenticated() && $this->userStore ) {
            $this->userStore->set( 'user', $token_set->getClaims() );
        }

        return $token_set;
    }

    /**
     * @param string $id_token
     *
     * @return TokenSet
     *
     * @throws IdTokenException
     * @throws IssuerException
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
            '%s/v2/logout?client_id=%s',
            $this->issuerBaseUrl,
            $this->clientId,
            $federated ? '&federated' : ''
        );
        header('Location: '.$auth0_logout_url);
        exit;
    }

    /**
     * @param array $config
     *
     * @return array
     *
     * @throws AuthException
     * @throws IssuerException
     */
    public function prepareAuthParams( array $config ): array
    {
        $auth_params = array_replace( $this->defaultAuthParams, $config );
        $auth_params['client_id'] = $this->clientId;
        $auth_params['redirect_uri'] = $this->redirectUri;
        $auth_params['nonce'] = $this->nonceHandler->createNonce();

        $state   = is_iterable( $config['state'] ) ? (array) $config['state'] : [];
        $auth_params['state'] = $this->stateHandler->create($state);

        $auth_params = array_filter($auth_params);
        $this->issuer->validateParams($auth_params);

        $response_type_excludes_code = ( FALSE === strpos( $auth_params['response_type'], 'code' ) );

        if ( isset( $auth_params['audience'] ) && $response_type_excludes_code ) {
            throw new AuthException( 'Cannot get an access token without a response_type including "code".' );
        }

        if ( $this->getClaimsFromUserinfo && $response_type_excludes_code ) {
            throw new AuthException( 'Cannot use the userinfo endpoint without a response_type including "code".' );
        }

        return $auth_params;
    }

    public function logout()
    {
        $this->userStore->delete('user');
    }

    /**
     * @return array|string|null
     *
     * @throws IssuerException
     */
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
        $user = $this->userStore->get( 'user' );
        return ! empty( $user->sub );
    }

    public function getUser()
    {
        return $this->isAuthenticated() ? $this->userStore->get( 'user' ) : null;
    }
}
