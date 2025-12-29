<?php

declare(strict_types=1);

namespace Y2KaoZ\PhpFormToken;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Y2KaoZ\PhpSulid\Sulid;

/** @api */
final class JsonFormToken
{
  private const string Algorithm = 'HS256';

  private static function GetKey(null|string $salt = null): string
  {
    if (is_null($salt)) {
      if (session_status() !== PHP_SESSION_ACTIVE) {
        throw new \Exception("Session is required if no salt is provided.");
      }
      $salt = session_id();
      if ($salt === false || empty($salt)) {
        throw new \Exception('Failure getting session id.');
      }
    }
    return sha1($salt . md5(date('Y-m-d')));
  }

  public static function GetUrl(): string
  {
    $url = '';
    $host = $_SERVER['HTTP_HOST'] ?? null;
    if (is_string($host)) {
      $protocol = ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
      $url .= "{$protocol}://{$host}";
    }
    $uri = $_SERVER['REQUEST_URI'] ?? null;
    if (is_string($uri)) {
      $url .= $uri;
    }
    return $url;
  }

  /** @param array<string,scalar> $extra */
  public static function Generate(null|string $issuer = null, array $extra = [], null|string $salt = null): string
  {
    $payload = array_merge($extra, [
      'exp' => new \DateTimeImmutable("tomorrow")->getTimestamp(),
      'iat' => time(),
      'iss' => $issuer ?? self::GetUrl(),
      'jti' => strval(Sulid::generate()),
    ]);
    return JWT::encode($payload, self::GetKey($salt), self::Algorithm);
  }

  /** @return array{exp:int,iat:int,iss:string,jti:string,...} */
  public static function Validate(string $jwt, null|string $salt = null): array
  {
    $payload = (array)JWT::decode($jwt, new Key(self::GetKey($salt), self::Algorithm));
    assert(isset($payload['exp']) && is_int($payload['exp']));
    assert(isset($payload['iat']) && is_int($payload['iat']));
    assert(isset($payload['iss']) && is_string($payload['iss']));
    assert(isset($payload['jti']) && is_string($payload['jti']));
    return $payload;
  }

  public function __toString()
  {
    return self::Generate();
  }
}
