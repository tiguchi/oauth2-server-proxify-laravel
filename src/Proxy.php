<?php

/**
 * @package   manukn/oauth2-server-proxify-laravel
 * @author    Michele Andreoli <michi.andreoli[at]gmail.com>
 * @copyright Copyright (c) Michele Andreoli
 * @author    Rik Schreurs <rik.schreurs[at]mail.com>
 * @copyright Copyright (c) Rik Schreurs
 * @license   http://mit-license.org/
 * @link      https://github.com/manukn/oauth2-server-proxify-laravel
 */

namespace Manukn\LaravelProxify;

use Log;

use Manukn\LaravelProxify\Exceptions\CookieExpiredException;
use Manukn\LaravelProxify\Exceptions\UnauthorizedException;
use Manukn\LaravelProxify\Exceptions\ProxyMissingParamException;
use Manukn\LaravelProxify\Managers\CookieManager;
use Manukn\LaravelProxify\Managers\RequestManager;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;

class Proxy
{
    const CLIENT_ACCESS_TOKEN_CACHE_KEY = 'PROXIFY_CLIENT_ACCESS_TOKEN';

    private $callMode = null;
    private $uriParam = null;
    private $skipParam = null;
    private $redirectUri = null;
    private $clientSecrets = null;
    private $cookieManager = null;
    private $guestAccessTokens = null;
    private $clientApiHosts = null;
    private $useHeader = false;

    /**
     * @param $params
     */
    public function __construct($params)
    {
        $this->skipParam = $params['skip_param'];
        $this->redirectUri = $params['redirect_login'];
        $this->clientSecrets = $params['client_secrets'];
        $this->useHeader = $params['use_header'];
        $this->clientApiHosts = $params['client_api_hosts'];
        $this->guestAccessTokens = $params['guest_access_tokens'];
        $this->cookieManager = new CookieManager($params['cookie_info']);
    }

    /**
     * Make request
     *
     * @param Request $request
     * @param $url
     * @return Response
     * @throws \Exception
     */
    public function makeRequest(Request $request, $url)
    {
        $this->uri = $url;
        $inputs = $request->all();

        //Retrieve the call mode from input parameters
        $this->callMode = $this->getRequestMode($inputs);

        //Remove parameters from inputs
        $inputs = ProxyAux::removeQueryValue($inputs, $this->uriParam);
        $inputs = ProxyAux::removeQueryValue($inputs, $this->skipParam);

        //Read the cookie if exists
        $parsedCookie = null;
        $isGuestAccess = false;
        
        if ($this->callMode !== ProxyAux::MODE_SKIP && $this->callMode !== ProxyAux::MODE_LOGIN) {
            try {
                $parsedCookie = $this->cookieManager->tryParseCookie($this->callMode);
            } catch (CookieExpiredException $ex) {
                $parsedCookie = $this->getGuestAccessToken($url);
                $isGuestAccess = true;

                if (!$parsedCookie) {
                    if (isset($this->redirectUri) && !empty($this->redirectUri)) {
                        return \Redirect::to($this->redirectUri);
                    }

                    throw $ex;
                }
            }
        }

        //Create the new request
        $requestManager = new RequestManager($this->uri, $request, $this->clientSecrets, $this->callMode, $this->cookieManager);
        if ($this->useHeader) {
            $requestManager->enableHeader();
        }
        $proxyResponse = $requestManager->executeRequest($inputs, $parsedCookie);

        $wrappedResponse = $proxyResponse['response'];

        if ($isGuestAccess && $wrappedResponse->getStatusCode() == 401) {
            Log::warning('Guest access token has expired');
            $parsedCookie = $this->getGuestAccessToken($url, true);
            $proxyResponse = $requestManager->executeRequest($inputs, $parsedCookie);
        }

        return $this->setApiResponse($wrappedResponse, $proxyResponse['cookie']);
    }

    /**
     * @param $inputs
     * @return string
     */
    private function getRequestMode($inputs)
    {
        $grantType = ProxyAux::getQueryValue($inputs, ProxyAux::GRANT_TYPE);
        $skip = ProxyAux::getQueryValue($inputs, $this->skipParam);
        $mode = ProxyAux::MODE_TOKEN;

        if (isset($grantType)) {
            if ($grantType === ProxyAux::PASSWORD_GRANT || $grantType === ProxyAux::AUTHORIZATION_GRANT) {
                $mode = ProxyAux::MODE_LOGIN;
            }
        } elseif (isset($skip) && strtolower($skip) === 'true') {
            $mode = ProxyAux::MODE_SKIP;
        }

        return $mode;
    }

    /**
     * @param $proxyResponse
     * @param $cookie
     * @return Response
     */
    private function setApiResponse($proxyResponse, $cookie)
    {
        $response = new Response($proxyResponse->getContent(), $proxyResponse->getStatusCode());

        if ($this->callMode === ProxyAux::MODE_LOGIN && $proxyResponse->getStatusCode() === 200) {
            $response->setContent(json_encode($this->successAccessToken()));
        }
        if (isset($cookie)) {
            $response->withCookie($cookie);
        }

        return $response;
    }
    
    /**
     * Tries to retrieve a guest access token for anonymous access, if possible.
     */ 
    private function getGuestAccessToken($url, $force = false) {
        $hostName = parse_url($url, PHP_URL_HOST);
        if (!isset($this->clientApiHosts[$hostName])) return null;
        $clientId = $this->clientApiHosts[$hostName];
        $success = false;
        $cacheKey = self::CLIENT_ACCESS_TOKEN_CACHE_KEY.'_'.$clientId;
        $accessToken = apcu_fetch($cacheKey, $success);
        
        if ($force || !$success || !$accessToken) {
            Log::info("Requesting client access token from API for client ID ".$clientId);
            $accessToken = $this->requestClientAccessToken($clientId);
            apcu_store($cacheKey, $accessToken);
        }
        
        if (!$accessToken) {
            Log::error("Could not retrieve client access token for client ID ".$clientId);
        }
        
        return $accessToken;
    }
    
    private function requestClientAccessToken($clientId) {
        $tokenUrl = $this->guestAccessTokens[$clientId];
        $clientSecret = $this->clientSecrets[$clientId];
        $client = new Client();

        $response = $client->post($tokenUrl, [
            'form_params' => [
                ProxyAux::CLIENT_ID => $clientId,
                ProxyAux::CLIENT_SECRET => $clientSecret,
                ProxyAux::GRANT_TYPE => ProxyAux::CLIENT_CREDENTIALS
            ]
        ]);
        
        if ($response->getStatusCode() != 200) {
            Log::error('Cannot get access token for '.$clientId.'. Server responds with status code '.$response->getStatusCode());
            abort($response->getStatusCode());
            return;
        }
        
        return RequestManager::getResponseContent($response);
    }

    /**
     * @return array
     */
    private function successAccessToken()
    {
        return array(
            'success_code' => 'access_token_ok',
            'success_message' => \Lang::get('api-proxy-laravel::messages.access_token_ok')
        );
    }
}
