<?php

namespace SocialiteProviders\Bluesky\Proof;

use DateInterval;
use Illuminate\Support\Facades\Cache;

class Key
{
	public static function restore()
	{
		if ($cached = Cache::get(static::class)) {
			[$private_key, $details] = $cached;
			return new static($private_key, $details);
		}
		
		return static::make();
	}
	
	public static function make()
	{
		$key = openssl_pkey_new([
			"curve_name" => "prime256v1", // P-256 curve
			"private_key_type" => OPENSSL_KEYTYPE_EC,
		]);
		
		openssl_pkey_export($key, $private_key);
		
		$details = openssl_pkey_get_details($key);
		
		return new static($private_key, $details);
	}
	
	public function __construct(
		public string $private_key,
		public array $details,
	) {
		Cache::put(static::class, [$this->private_key, $this->details], new DateInterval('P1M'));
	}
}
