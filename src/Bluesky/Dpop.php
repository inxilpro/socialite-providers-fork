<?php

namespace SocialiteProviders\Bluesky;

class Dpop
{
	protected static $key = null;
	
	public static function sign(string $endpoint, ?string $nonce)
	{
		// Generate a key pair (you'd normally want to store these)
		$config = [
			"curve_name" => "prime256v1", // P-256 curve
			"private_key_type" => OPENSSL_KEYTYPE_EC,
		];
		
		// ugh
		static::$key ??= openssl_pkey_new($config);
		$res = static::$key;
		
		openssl_pkey_export($res, $privKey);
		
		$keyDetails = openssl_pkey_get_details($res);
		
		dump(['details' => $keyDetails]);
		
		$pubKey = openssl_pkey_get_details($res)['key'];
		
		// Create DPoP proof JWT header and payload
		$header = [
			'typ' => 'dpop+jwt',
			'alg' => 'ES256',
			'jwk' => [
				'kty' => 'EC',
				'crv' => 'P-256',
				'x' => static::b64url($keyDetails['ec']['x']),
				'y' => static::b64url($keyDetails['ec']['y'])
			]
		];
		
		$payload = [
			'jti' => bin2hex(random_bytes(16)),
			'htm' => 'POST',
			'htu' => $endpoint,
			'iat' => time(),
		];
		
		if ($nonce) {
			$payload['nonce'] = $nonce;
		}
		
		// Create JWT
		$base64Header = static::b64url(json_encode($header));
		$base64Payload = static::b64url(json_encode($payload));
		$signatureInput = "$base64Header.$base64Payload";
		openssl_sign($signatureInput, $signature, $privKey, OPENSSL_ALGO_SHA256);
		
		$base64Signature = static::b64url(static::convertDERtoRS($signature));
		
		return "$base64Header.$base64Payload.$base64Signature";
	}
	
	public static function signRsa(string $endpoint)
	{
		// Generate a key pair (you'd normally want to store these)
		$config = [
			"digest_alg" => "sha256",
			"private_key_bits" => 2048,
			"private_key_type" => OPENSSL_KEYTYPE_RSA,
		];
		
		$res = openssl_pkey_new($config);
		openssl_pkey_export($res, $privKey);
		
		dump(['details' => openssl_pkey_get_details($res)]);
		
		$pubKey = openssl_pkey_get_details($res)['key'];
		
		// Create DPoP proof JWT header and payload
		$header = [
			'typ' => 'dpop+jwt',
			'alg' => 'RS256',
			'jwk' => [ // Simplified JWK from public key
				'kty' => 'RSA',
				'e' => 'AQAB',
				'n' => trim(base64_encode(openssl_pkey_get_details($res)['n']), '='),
			],
		];
		
		$payload = [
			'jti' => bin2hex(random_bytes(16)),
			'htm' => 'POST',
			'htu' => $endpoint,
			'iat' => time(),
		];
		
		// Create JWT
		$base64Header = base64_encode(json_encode($header));
		$base64Payload = base64_encode(json_encode($payload));
		$signatureInput = "$base64Header.$base64Payload";
		openssl_sign($signatureInput, $signature, $privKey, OPENSSL_ALGO_SHA256);
		$base64Signature = base64_encode($signature);
		
		return "$base64Header.$base64Payload.$base64Signature";
	}
	
	protected static function convertDERtoRS($der)
	{
		$pos = 0;
		$size = strlen($der);
		
		// Sequence tag and length
		if (ord($der[$pos++]) !== 0x30) {
			return false;
		}
		$total = ord($der[$pos++]);
		if ($total + 2 !== $size) {
			return false;
		}
		
		// R value
		if (ord($der[$pos++]) !== 0x02) {
			return false;
		}
		$rlen = ord($der[$pos++]);
		$r = substr($der, $pos, $rlen);
		$pos += $rlen;
		
		// S value
		if (ord($der[$pos++]) !== 0x02) {
			return false;
		}
		$slen = ord($der[$pos++]);
		$s = substr($der, $pos, $slen);
		
		// Pad R and S to 32 bytes each
		$r = str_pad($r, 32, "\x00", STR_PAD_LEFT);
		$s = str_pad($s, 32, "\x00", STR_PAD_LEFT);
		
		return $r.$s;
	}
	
	protected static function b64url($data)
	{
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}
}
