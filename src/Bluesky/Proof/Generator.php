<?php

namespace SocialiteProviders\Bluesky\Proof;

use Illuminate\Support\Facades\Date;

class Generator
{
	public function __construct(
		public Key $key,
		public string $endpoint,
		public ?string $nonce = null,
		public string $method = 'POST',
	) {
	}
	
	public function proof(): string
	{
		$data = "{$this->header()}.{$this->payload()}";
		
		$signature = $this->sign($data);
		
		return "{$data}.{$signature}";
	}
	
	public function hasNonce(): bool
	{
		return null !== $this->nonce;
	}
	
	public function withNonce($nonce): static
	{
		$this->nonce = $nonce;
		
		return $this;
	}
	
	protected function sign(string $input): string
	{
		openssl_sign($input, $signature, $this->key->private_key, OPENSSL_ALGO_SHA256);
		
		return $this->encode($this->rsFormat($signature));
	}
	
	protected function header(): string
	{
		return $this->encode([
			'typ' => 'dpop+jwt',
			'alg' => 'ES256',
			'jwk' => [
				'kty' => 'EC',
				'crv' => 'P-256',
				'x' => $this->encode($this->key->details['ec']['x']),
				'y' => $this->encode($this->key->details['ec']['y']),
				'use' => 'sig',
			],
		]);
	}
	
	protected function payload(): string
	{
		return $this->encode(array_filter([
			'jti' => bin2hex(random_bytes(16)),
			'htm' => $this->method,
			'htu' => $this->endpoint,
			'iat' => Date::now()->unix(),
			'nonce' => $this->nonce,
		]));
	}
	
	protected function encode($data): string
	{
		if (is_array($data)) {
			$data = json_encode($data, JSON_THROW_ON_ERROR);
		}
		
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}
	
	protected function decode($data): string
	{
		return base64_decode(strtr($data, '-_', '+/'));
	}
	
	protected function rsFormat(string $der): bool|string
	{
		$pos = 0;
		$size = strlen($der);
		
		if (ord($der[$pos++]) !== 0x30) {
			return false;
		}
		$total = ord($der[$pos++]);
		if ($total + 2 !== $size) {
			return false;
		}
		
		if (ord($der[$pos++]) !== 0x02) {
			return false;
		}
		$rlen = ord($der[$pos++]);
		$r = substr($der, $pos, $rlen);
		$pos += $rlen;
		
		if (ord($der[$pos++]) !== 0x02) {
			return false;
		}
		$slen = ord($der[$pos++]);
		$s = substr($der, $pos, $slen);
		
		// Remove leading zeros
		$r = ltrim($r, "\x00");
		$s = ltrim($s, "\x00");
		
		// Ensure 32 byte length
		$r = str_pad($r, 32, "\x00", STR_PAD_LEFT);
		$s = str_pad($s, 32, "\x00", STR_PAD_LEFT);
		
		return $r.$s;
	}
}
