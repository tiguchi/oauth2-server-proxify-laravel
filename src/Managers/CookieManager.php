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

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Contracts\Encryption\DecryptException;

use Manukn\LaravelProxify\Exceptions\CookieExpiredException;
use Manukn\LaravelProxify\Exceptions\CookieInvalidException;
use Manukn\LaravelProxify\ProxyAux;


class CookieManager
{

    const COOKIE_NAME = 'name';
    const COOKIE_TIME = 'time';
    private $info = null;

    private static $previouslyCreatedCookie = null;

    public function __construct($info)
    {
        $this->info = $info;
    }

    /**
     * @param $callMode
     * @return mixed|string
     * @throws CookieExpiredException
     * @throws CookieInvalidException
     */
    public function tryParseCookie($callMode)
    {
        if (self::$previouslyCreatedCookie) {
            return self::$previouslyCreatedCookie;
        }

        $encryptedCookie = Cookie::get($this->info[CookieManager::COOKIE_NAME]);
        if (!$encryptedCookie) return false;

        try { 
            $decryptedCookie = Crypt::decrypt($encryptedCookie);
        } catch (DecryptException $e) {
            throw new CookieInvalidException("Cannot decrypt cookie.", $e);
        }

        $parsedCookie = json_decode($decryptedCookie, true);

        if (isset($parsedCookie)) {
            $this->validateCookie($parsedCookie);
        } else {
            if ($callMode !== ProxyAux::MODE_LOGIN) {
                throw new CookieExpiredException();
            }
        }

        // At this point we have a valid cookie.
        // Let's check if a concurrent Proxify request had to refresh the access token while we're still dealing
        // with the old access token. In this case we need to prevent that we try to re-retrieve a new access token
        $concurrentlyRefreshedToken = $this->getConcurrentlyRefreshedToken($parsedCookie);

        if ($concurrentlyRefreshedToken) {
            $parsedCookie = self::$previouslyCreatedCookie = $concurrentlyRefreshedToken;
        }

        return $parsedCookie;
    }
    
    public function exists()
    {
        return Cookie::has($this->info[CookieManager::COOKIE_NAME]);
    }

    /**
     * @param array $content
     * @return mixed
     */
    public function createCookie($content)
    {
        self::$previouslyCreatedCookie = $content;

        $jsonString = json_encode((array) $content, true);
        $encryptedJsonString = Crypt::encrypt($jsonString);

        if (!isset($this->info[CookieManager::COOKIE_TIME]) || $this->info[CookieManager::COOKIE_TIME] == null) {
            $cookie = Cookie::forever($this->info[CookieManager::COOKIE_NAME], $encryptedJsonString);
        } else {
            $cookie = Cookie::make($this->info[CookieManager::COOKIE_NAME], $encryptedJsonString, $this->info[CookieManager::COOKIE_TIME]);
        }

        Cookie::queue($cookie);
        return $cookie;
    }

    /**
     * @return mixed
     */
    public function destroyCookie()
    {
        return Cookie::forget($this->info[CookieManager::COOKIE_NAME]);
    }

    /**
     * @param $parsedCookie
     * @return bool
     * @throws CookieInvalidException
     */
    public function validateCookie($parsedCookie)
    {
        if (!isset($parsedCookie) || !array_key_exists(ProxyAux::ACCESS_TOKEN, $parsedCookie)) {
            throw new CookieInvalidException(ProxyAux::ACCESS_TOKEN);
        }
        if (!array_key_exists(ProxyAux::TOKEN_TYPE, $parsedCookie)) {
            throw new CookieInvalidException(ProxyAux::TOKEN_TYPE);
        }
        if (!array_key_exists(ProxyAux::TOKEN_EXPIRES, $parsedCookie)) {
            throw new CookieInvalidException(ProxyAux::TOKEN_EXPIRES);
        }
        if (!array_key_exists(ProxyAux::COOKIE_URI, $parsedCookie)) {
            throw new CookieInvalidException(ProxyAux::COOKIE_URI);
        }
        if (!array_key_exists(ProxyAux::CLIENT_ID, $parsedCookie)) {
            throw new CookieInvalidException(ProxyAux::CLIENT_ID);
        }

        return true;
    }

    public function storeRefreshedTokenInMemory($oldAccessToken, $newParsedCookie) {
        // 20 Seconds should be generous
        apcu_store($oldAccessToken, $newParsedCookie, 20);
    }

    /**
     * Checks if an access token has been already refreshed by a concurrently running request on behalf of the same
     * user.
     *
     * @param $parsedCookie The user's parsed access token cookie data.
     */
    public function getConcurrentlyRefreshedToken($parsedCookie)
    {
        $accessToken = $parsedCookie[ProxyAux::ACCESS_TOKEN];
        return apcu_fetch($accessToken);
    }
}

