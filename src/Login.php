<?php
/**
 * Contains class Login.
 *
 * @package Auth0\Auth
 */
namespace Auth0\Auth;

use Auth0\Auth\Traits;
use \stdClass;

/**
 * Class Login
 *
 * @package Auth0\Auth
 */
class Login
{
    use Traits\HttpRequests;
    use Traits\Nonce;

    const DEFAULT_ID_TOKEN_ALG = 'RS256';

    protected $issuerBaseUrl;
    protected $clientId;
    protected $redirectUri;
    protected $clientSecret;
    protected $idTokenAlg;
    protected $issuer;

    /**
     * Login constructor.
     *
     * @param array $config - See method body for config options used.
     */
    public function __construct( array $config )
    {
        $this->issuerBaseUrl = $config['issuer_base_url'] ?? $_ENV['AUTH0_ISSUER_BASE_URL'] ?? null;
        $this->clientId = $config['client_id'] ?? $_ENV['AUTH0_CLIENT_ID'] ?? null;
        $this->clientSecret = $config['client_secret'] ?? $_ENV['AUTH0_CLIENT_SECRET'] ?? null;
        $this->redirectUri = $config['redirect_uri'] ?? $_ENV['AUTH0_REDIRECT_URI'] ?? null;
        $this->idTokenAlg = $config['id_token_alg'] ?? $_ENV['AUTH0_ID_TOKEN_ALG'] ?? self::DEFAULT_ID_TOKEN_ALG;

        $this->issuer = new Issuer( $this->issuerBaseUrl );
    }

    /**
     * Redirect to the authorize endpoint.
     *
     * @param array $config Array of configuration options.
     *
     * @throws \Exception
     * @throws \Http\Client\Exception
     */
    final public function loginWithRedirect( array $config = [] ): void
    {
        $auth_ep_url = $this->issuer->getDiscoveryValue('authorization_endpoint');
        $config['nonce'] = $this->createNonce();
        $auth_params = $this->prepareAuthParams($config);
        $auth0_login_url = $auth_ep_url.'?'.http_build_query($auth_params);
        $this->setNonce($config['nonce']);
        header('Location: '.$auth0_login_url);
    }

    /**
     * @return TokenSet
     * @throws \Exception
     * @throws \Http\Client\Exception
     */
    final public function callbackHandleIdToken(): TokenSet
    {
        $id_token = $_POST['id_token'] ?? null;
        if (!$id_token ) {
            return null;
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
        $tokens = new TokenSet(new stdClass);
        $code = $_POST['code'] ?? null;
        if (!$code ) {
            return $tokens;
        }

        $token_ep_url = $this->issuer->getDiscoveryValue('token_endpoint');
        $code_exchange = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
            'code' => $code,
            'grant_type' => 'authorization_code'
        ];
        $token_obj = $this->httpRequest($token_ep_url, 'POST', json_encode( $code_exchange ) );

        // TODO: Remove debugging
        echo '<pre>' . print_r( $token_obj, TRUE ) . '</pre>'; die();
        if ( $token_obj->id_token ) {
            $tokens = $this->decodeIdToken($token_obj->id_token);
        }

        $tokens->setAccessToken($token_obj);
        $tokens->setRefreshToken($token_obj);

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

    public function prepareAuthParams( array $config ): array
    {
        $audience = $config['audience'] ?? null;
        $auth_params = [
            'audience' => $audience,
            'client_id' => $this->clientId,
            'connection' => $config['connection'] ?? null,
            'nonce' => $config['nonce'],
            'prompt' => $config['prompt'] ?? null,
            'redirect_uri' => $this->redirectUri,
            'response_mode' => 'form_post',
            'response_type' => $audience ? 'id_token code' : 'id_token',
            'scope' => $config['scope'] ?? 'openid profile email',
        ];
        return array_filter($auth_params);
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
    }

    public function getUser()
    {
    }
}
