<?php
declare(strict_types=1);

/**
 * Contains class Login.
 *
 * @package Auth0\Auth
 */
namespace Auth0\Auth;

use Auth0\Auth\Traits;

/**
 * Class Login
 *
 * @package Auth0\Auth
 */
class Login
{
    use Traits\HttpRequests;
    use Traits\AuthSession;

    const DEFAULT_ID_TOKEN_ALG = 'RS256';
    const SESSION_BASE_NAME = 'auth0_';

    protected $issuerBaseUrl;
    protected $clientId;
    protected $redirectUri;
    protected $clientSecret;
    protected $idTokenAlg;
    protected $issuer;

    /**
     * Login constructor.
     *
     * @param array $config
     *
     * @throws \Exception
     */
    public function __construct( array $config )
    {
        $this->issuerBaseUrl = $config['issuer_base_url'] ?? $_ENV['AUTH0_ISSUER_BASE_URL'] ?? '';
        if (! $this->issuerBaseUrl ) {
            throw new \Exception('Issuer base URL is required.');
        }

        $this->clientId = $config['client_id'] ?? $_ENV['AUTH0_CLIENT_ID'] ?? null;
        if (! $this->clientId ) {
            throw new \Exception('Client ID is required.');
        }

        $this->redirectUri = $config['redirect_uri'] ?? $_ENV['AUTH0_REDIRECT_URI'] ?? null;
        if (! $this->redirectUri ) {
            throw new \Exception('Redirect URI is required.');
        }

        $this->clientSecret = $config['client_secret'] ?? $_ENV['AUTH0_CLIENT_SECRET'] ?? null;
        $this->idTokenAlg = $config['id_token_alg'] ?? $_ENV['AUTH0_ID_TOKEN_ALG'] ?? self::DEFAULT_ID_TOKEN_ALG;

        $this->issuer = new Issuer($this->issuerBaseUrl);
    }

    /**
     * @param array $config
     *
     * @throws \Exception
     * @throws \Http\Client\Exception
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
     * @throws \Exception
     * @throws \Http\Client\Exception
     */
    final public function getAuthorizeUrl( array $config = [] ): string
    {
        $auth_ep_url = $this->issuer->getDiscoveryValue('authorization_endpoint');
        $auth_params = $this->prepareAuthParams($config);

        $this->setNonce($auth_params['nonce']);
        $this->setState($auth_params['state']);

        return $auth_ep_url.'?'.http_build_query($auth_params);
    }

    public function prepareAuthParams( array $config ): array
    {
        $audience    = $config['audience'] ?? null;
        $auth_params = [
            'client_id'     => $this->clientId,
            'redirect_uri'  => $this->redirectUri,
            'audience'      => $audience,
            'connection'    => $config['connection'] ?? null,
            'nonce'         => $this->createNonce(),
            'state'         => $this->createState($config['state'] ?? []),
            'prompt'        => $config['prompt'] ?? null,
            'response_mode' => $config['response_mode'] ?? 'form_post',
            'response_type' => $config['response_type'] ?? ( $audience ? 'id_token code' : 'id_token' ),
            'scope'         => $config['scope'] ?? 'openid profile email',
        ];
        return array_filter($auth_params);
    }

    /**
     * @return TokenSet
     * @throws \Exception
     * @throws \Http\Client\Exception
     */
    final public function callbackHandleIdToken() : TokenSet
    {
        $id_token = $_POST['id_token'] ?? '';
        if (!$id_token ) {
            return new TokenSet();
        }

        return $this->decodeIdToken($id_token);
    }

    /**
     * @return TokenSet
     * @throws \Exception
     * @throws \Http\Client\Exception
     */
    final public function callbackHandleCode() : TokenSet
    {
        $tokens = new TokenSet();

        // TODO: What about GET?
        $code = $_POST['code'] ?? null;
        if (!$code) {
            return $tokens;
        }

        $valid_state = $this->getValidState($_POST['state'] ?? '');

        $token_ep_url = $this->issuer->getDiscoveryValue('token_endpoint');
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

    /**
     * @param $id_token
     *
     * @return TokenSet
     * @throws \Exception
     * @throws \Http\Client\Exception
     */
    final public function decodeIdToken( string $id_token ) : TokenSet
    {
        $token_validator = new IdTokenVerifier(
            [
                'algorithm' => $this->idTokenAlg,
                'signature_key' => $this->getSignatureKey(),
                'client_id' => $this->clientId,
                'issuer' => $this->issuer->getDiscoveryValue('issuer'),
             ]
        );

        return $token_validator->decode($id_token, $this->getNonce());
    }

    /**
     * @param bool $federated
     */
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

    public function logout()
    {
        // TODO: Clear session
    }

    /**
     * @return string|array|null
     *
     * @throws \Exception
     * @throws \Http\Client\Exception
     */
    public function getSignatureKey()
    {
        switch( $this->idTokenAlg ) {
        case 'RS256':
            $jwks = new Issuer($this->issuerBaseUrl);
            return $jwks->getJwks();
                    break;

        case 'HS256':
            return $this->clientSecret;
                    break;

        default:
            return null;
        }
    }

    public function isAuthenticated() : bool
    {
        return false;
    }

    public function getUser()
    {
    }
}
