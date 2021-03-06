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

namespace Manukn\LaravelProxify\Models;

class ProxyResponse
{

    private $statusCode = null;
    private $reasonPhrase = null;
    private $protocolVersion = null;
    private $content = null;
    private $parsedContent = null;

    public function __construct($statusCode, $reasonPhrase, $protoVersion, $content, $contentType, $headers)
    {
        $this->statusCode = $statusCode;
        $this->reasonPhrase = $reasonPhrase;
        $this->protocolVersion = $protoVersion;
        $this->content = $content;
        $this->contentType = $contentType;
        $this->headers = $headers;
    }

    public function setStatusCode($status)
    {
        $this->statusCode = $status;
    }

    public function setReasonPhrase($phrase)
    {
        $this->reasonPhrase = $phrase;
    }

    public function setProtoVersion($proto)
    {
        $this->protocolVersion = $proto;
    }

    public function setContent($content)
    {
        $this->content = $content;
    }

    public function getStatusCode()
    {
        return $this->statusCode;
    }

    public function getReasonPhrase()
    {
        return $this->reasonPhrase;
    }

    public function getProtoVersion()
    {
        return $this->protocolVersion;
    }

    public function getContentType()
    {
        return $this->contentType;
    }

    public function getContent()
    {
        return $this->content;
    }

    public function getHeaders()
    {
        return $this->headers;
    }

    public static function parseContent($contentType, $content)
    {
        switch ($contentType) {
            case 'application/json':
                return json_decode($content, true);

            default:
                return $content;
        }
    }

    public function getParsedContent()
    {
        if ($this->parsedContent === null) {
            $this->parsedContent = self::parseContent($this->contentType, $this->content);
        }

        return $this->parsedContent;
    }
}
