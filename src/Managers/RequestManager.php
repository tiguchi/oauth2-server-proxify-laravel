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

namespace Manukn\LaravelProxify\Managers;

use Log;

use Manukn\LaravelProxify\ProxyAux;
use Manukn\LaravelProxify\Models\ProxyResponse;
use Illuminate\Http\Request;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use Manukn\LaravelProxify\Exceptions\MissingClientSecretException;

class RequestManager
{

    private $uri = null;
    private $request = null;
    private $method = null;
    private $callMode = null;
    private $clientSecrets = null;
    private $cookieManager = null;
    private $useHeader = false;

    /**
     * @param string $callMode
     * @param CookieManager $cookieManager
     */
    public function __construct($uri, Request $request, $clientSecrets, $callMode, $cookieManager)
    {
        $this->uri = $uri;
        $this->method = $request->method();
        $this->request = $request;
        $this->clientSecrets = $clientSecrets;
        $this->callMode = $callMode;
        $this->cookieManager = $cookieManager;
    }

    public function enableHeader()
    {
        $this->useHeader = true;
    }

    /**
     * @param $inputs
     * @param $parsedCookie
     * @return array
     */
    public function executeRequest($inputs, $parsedCookie)
    {
        $cookie = null;
        $contentType = explode(';', $this->request->header('Content-Type'));
        $contentType = trim($contentType[0]);

        switch ($this->callMode) {
            case ProxyAux::MODE_LOGIN:
                $inputs = $this->addLoginExtraParams($inputs);
                $proxyResponse = $this->replicateRequest($this->method, $this->uri, $inputs, $contentType);

                $clientId = (array_key_exists(ProxyAux::CLIENT_ID, $inputs)) ? $inputs[ProxyAux::CLIENT_ID] : null;
                $content = $proxyResponse->getContent();
                $content = ProxyAux::addQueryValue($content, ProxyAux::COOKIE_URI, $this->uri);
                $content = ProxyAux::addQueryValue($content, ProxyAux::COOKIE_METHOD, $this->method);
                $content = ProxyAux::addQueryValue($content, ProxyAux::CLIENT_ID, $clientId);

                $cookie = $this->cookieManager->createCookie($content);
                break;
            case ProxyAux::MODE_TOKEN:
                $inputs = $this->addTokenExtraParams($inputs, $parsedCookie);
                $proxyResponse = $this->replicateRequest($this->method, $this->uri, $inputs, $contentType);

                //Get a new access token from refresh token if exists
                $cookie = null;
                
                if ($proxyResponse->getStatusCode() == 401) {
                    if (array_key_exists(ProxyAux::REFRESH_TOKEN, $parsedCookie)) {
                        $ret = $this->tryRefreshToken($inputs, $parsedCookie, $contentType);
                    } else {
                        $cookie = $this->cookieManager->destroyCookie();
                    }
                }

                $proxyResponse = (isset($ret)) ? $ret['response'] : $proxyResponse;
                $cookie = (isset($ret)) ? $ret['cookie'] : $cookie;
                break;
            default:
                $proxyResponse = $this->replicateRequest($this->method, $this->uri, $inputs, $contentType);
        }

        return array(
            'response' => $proxyResponse,
            'cookie' => $cookie
        );
    }

    /**
     * @param $inputs
     * @param $parsedCookie
     * @return array
     */
    private function tryRefreshToken($inputs, $parsedCookie, $contentType)
    {
        $this->callMode = ProxyAux::MODE_REFRESH;

        //Get a new access token from refresh token
        $inputs = $this->removeTokenExtraParams($inputs);
        $params = $this->addRefreshExtraParams(array(), $parsedCookie);
        $proxyResponse = $this->replicateRequest($parsedCookie[ProxyAux::COOKIE_METHOD], $parsedCookie[ProxyAux::COOKIE_URI], $params, 'application/x-www-form-urlencoded');
        $content = $proxyResponse->getContent();

        if ($proxyResponse->getStatusCode() === 200 && array_key_exists(ProxyAux::ACCESS_TOKEN, $content)) {
            $this->callMode = ProxyAux::MODE_TOKEN;
            $parsedCookie[ProxyAux::ACCESS_TOKEN] = $content[ProxyAux::ACCESS_TOKEN];
            $parsedCookie[ProxyAux::REFRESH_TOKEN] = $content[ProxyAux::REFRESH_TOKEN];

            $inputs = $this->addTokenExtraParams($inputs, $parsedCookie);
            //Set a new cookie with updated access token and refresh token
            $cookie = $this->cookieManager->createCookie($parsedCookie);

            // Retry original request that failed with 401
            $proxyResponse = $this->replicateRequest($this->method, $this->uri, $inputs, $contentType);
        } else {
            $cookie = $this->cookieManager->destroyCookie();
        }

        return array(
            'response' => $proxyResponse,
            'cookie' => $cookie
        );
    }

    /**
     * @param $method
     * @param $uri
     * @param $inputs
     * @return ProxyResponse
     */
    private function replicateRequest($method, $uri, $inputs, $contentType)
    {
        $guzzleResponse = $this->sendGuzzleRequest($method, $uri, $inputs, $contentType);
        $proxyResponse = new ProxyResponse($guzzleResponse->getStatusCode(), $guzzleResponse->getReasonPhrase(), $guzzleResponse->getProtocolVersion(), self::getResponseContent($guzzleResponse));

        return $proxyResponse;
    }

    /**
     * @param \GuzzleHttp\Message\ResponseInterface $response
     * @return mixed
     */
    public static function getResponseContent($response)
    {
        switch ($response->getHeaderLine('content-type')) {
            case 'application/json':
                return json_decode($response->getBody(), true);
//            case 'text/xml':
//            case 'application/xml':
//                return $response->xml();
            default:
                return $response->getBody();
        }
    }
    
    private function createForwardedForString() {
        $ips = array();

        // Pass on original client and proxy IP address info if available.
        // Warning: can be easily forged. API should use this additional info with caution.
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $proxyIps = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            
            foreach ($proxyIps as $pIp) {
                $pIp = trim($pIp);
                
                if (filter_var($pIp, FILTER_VALIDATE_IP)) {
                    $ips []= $pIp;
                }
            }
        }

        // Add the real client IP address that made the currently processed request
        $ips []= $_SERVER['REMOTE_ADDR'];
        
        return implode(', ', $ips);
    }

    /**
     * @param $method
     * @param $uriVal
     * @param $inputs
     * @return \GuzzleHttp\Message\ResponseInterface
     */
    private function sendGuzzleRequest($method, $uriVal, $inputs, $contentType)
    {
        $options = array('headers' => [
            'X-Forwarded-For' => $this->createForwardedForString()
        ]);
        $client = new Client();

        if ($this->callMode === ProxyAux::MODE_TOKEN && $this->useHeader === true) {
            $accessToken = ProxyAux::getQueryValue($inputs, ProxyAux::ACCESS_TOKEN);
            $inputs = ProxyAux::removeQueryValue($inputs, ProxyAux::ACCESS_TOKEN);
            $options['headers'][ProxyAux::HEADER_AUTH] = 'Bearer ' . $accessToken;
        }

        if ($method === 'GET') {
            $options = array_add($options, 'query', $inputs);
        } else {
            if (Request::matchesType($contentType, 'application/json')) {
                $options = array_add($options, 'json', $inputs);
            } else if (Request::matchesType($contentType, 'application/x-www-form-urlencoded')) {
              $options = array_add($options, 'form_params', $inputs);
            } else if (Request::matchesType($contentType, 'multipart/form-data')) {
                $options['multipart'] = [];

                // filter through all file inputs instances and append them to guzzle multipart option
                foreach (request()->files as $inputName => $files) {
                    // Each request->file is an array
                    
                    foreach ($files as $file) {
                        $options['multipart'][] = [
                            'name' => $inputName,
                            'contents' => fopen($file->getRealPath(), 'r'),
                            'filename' => $file->getClientOriginalName()
                        ];
                    }
                }
            } else {
            
                $options = array_add($options, 'headers', [
                    'Content-Type' => $contentType
                ]);
                $options = array_add($options, 'body', $inputs);
            }
        }

        try {
            return $client->request($method, $uriVal, $options);
        } catch (ClientException $ex) {
            Log::warning("Got error response from API ".$ex->getMessage());
            
            return $ex->getResponse();
        }
    }

    /**
     * @param $clientId
     * @return array
     * @throws MissingClientSecretException
     */
    private function getClientInfo($clientId)
    {
        $info = ['id' => null, 'secret' => null];

        if (isset($clientId)) {
            if (!array_key_exists($clientId, $this->clientSecrets)) {
                throw new MissingClientSecretException($clientId);
            }
            $info['id'] = $clientId;
            $info['secret'] = $this->clientSecrets[$clientId];
        } elseif (count($this->clientSecrets) >= 1) {
            $firstKey = key($this->clientSecrets);
            $info['id'] = $firstKey;
            $info['secret'] = $this->clientSecrets[$firstKey];
        }

        return $info;
    }

    /**
     * @param $inputs
     * @return array
     */
    private function addLoginExtraParams($inputs)
    {
        //Get client secret key
        $clientId = (array_key_exists(ProxyAux::CLIENT_ID, $inputs)) ? $inputs[ProxyAux::CLIENT_ID] : null;
        $clientInfo = $this->getClientInfo($clientId);

        if (isset($clientInfo['id'])) {
            $inputs = ProxyAux::addQueryValue($inputs, ProxyAux::CLIENT_ID, $clientInfo['id']);
        }
        if (isset($clientInfo['secret'])) {
            $inputs = ProxyAux::addQueryValue($inputs, ProxyAux::CLIENT_SECRET, $clientInfo['secret']);
        }

        return $inputs;
    }

    /**
     * @param $inputs
     * @param $parsedCookie
     * @return array
     */
    private function addTokenExtraParams($inputs, $parsedCookie)
    {
        if (isset($parsedCookie[ProxyAux::ACCESS_TOKEN])) {
            $inputs = ProxyAux::addQueryValue($inputs, ProxyAux::ACCESS_TOKEN, $parsedCookie[ProxyAux::ACCESS_TOKEN]);
        }

        return $inputs;
    }

    /**
     * @param $inputs
     * @param $parsedCookie
     * @return array
     */
    private function addRefreshExtraParams($inputs, $parsedCookie)
    {
        $inputs = ProxyAux::addQueryValue($inputs, ProxyAux::GRANT_TYPE, ProxyAux::REFRESH_TOKEN);
        $inputs = ProxyAux::addQueryValue($inputs, ProxyAux::REFRESH_TOKEN, $parsedCookie[ProxyAux::REFRESH_TOKEN]);
        if (isset($parsedCookie[ProxyAux::CLIENT_ID])) {
            $clientInfo = $this->getClientInfo($parsedCookie[ProxyAux::CLIENT_ID]);
            if (isset($clientInfo['id'])) {
                $inputs = ProxyAux::addQueryValue($inputs, ProxyAux::CLIENT_ID, $clientInfo['id']);
            }
            if (isset($clientInfo['secret'])) {
                $inputs = ProxyAux::addQueryValue($inputs, ProxyAux::CLIENT_SECRET, $clientInfo['secret']);
            }
        }

        return $inputs;
    }

    /**
     * @param $inputs
     * @return array
     */
    private function removeTokenExtraParams($inputs)
    {
        $inputs = ProxyAux::removeQueryValue($inputs, ProxyAux::ACCESS_TOKEN);

        return $inputs;
    }
}
