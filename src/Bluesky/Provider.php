<?php

namespace SocialiteProviders\Bluesky;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\RequestOptions;
use Illuminate\Http\Response;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\URL;
use SocialiteProviders\Bluesky\Proof\Generator;
use SocialiteProviders\Bluesky\Proof\Key;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;
use Throwable;

class Provider extends AbstractProvider
{
	public const IDENTIFIER = 'BLUESKY';
	
	protected $scopeSeparator = ' ';
	
	protected $usesPKCE = true;
	
	protected $scopes = [
		'atproto',
		// 'transition:generic',
	];
	
	protected ?Generator $generator = null;
	
	public function clientMetadata()
	{
		$metadata = array_filter([
			'application_type' => 'web',
			'client_id' => $this->clientId,
			'client_name' => Config::get('app.name'),
			'client_uri' => URL::to('/'),
			'dpop_bound_access_tokens' => true, // bsky says must be true
			'grant_types' => ['authorization_code', 'refresh_token'],
			'redirect_uris' => [$this->redirectUrl],
			'response_types' => ['code'],
			'scope' => 'atproto transition:generic',
			'token_endpoint_auth_method' => 'none',
			'logo_uri' => Config::get('services.bluesky.logo_uri'),
			'tos_uri' => Config::get('services.bluesky.tos_uri'),
			'policy_uri' => Config::get('services.bluesky.policy_uri'),
		]);
		
		return new Response(json_encode($metadata), headers: ['Content-Type' => 'application/json']);
	}
	
	protected function getAuthUrl($state)
	{
		return $this->buildAuthUrlFromBase('https://bsky.social/oauth/authorize', $state);
	}
	
	public function getAccessTokenResponse($code): array
	{
		$this->generator ??= new Generator(Key::restore(), $this->getTokenUrl());
		
		$url = $this->getTokenUrl();
		$options = [
			RequestOptions::HEADERS => $this->getTokenHeaders($code),
			RequestOptions::FORM_PARAMS => $this->getTokenFields($code),
		];
		
		try {
			$response = $this->getHttpClient()->post($url, $options);
		} catch (RequestException $e) {
			// FIXME: Do this on `use_dpop_nonce`
			
			if ($this->generator->hasNonce()) {
				throw  $e;
			}
			
			$nonce = Arr::wrap($e->getResponse()->getHeader('DPoP-Nonce'))[0];
			$options[RequestOptions::HEADERS]['DPoP'] = $this->generator->withNonce($nonce)->proof();
			$response = $this->getHttpClient()->post($url, $options);
		}
		
		return json_decode($response->getBody(), true);
	}
	
	public function getTokenHeaders($code)
	{
		$this->generator ??= new Generator(Key::restore(), $this->getTokenUrl());
		
		$headers = [
			'DPoP' => $this->generator->proof(),
			'Accept' => 'application/json',
		];
		
		return $headers;
	}
	
	protected function getTokenUrl()
	{
		return 'https://bsky.social/oauth/token';
	}
	
	protected function getUserByToken($token)
	{
		$introspection = $this->getOauthIntrospection($token);
		
		$response = $this->getHttpClient()->get('https://bsky.social/xrpc/app.bsky.actor.getProfile', [
			RequestOptions::QUERY => [
				'actor' => $introspection['username'],
			],
			RequestOptions::HEADERS => [
				'Accept' => 'application/json',
				'Authorization' => 'Bearer '.$token,
			],
		]);
		
		return json_decode((string) $response->getBody(), true);
	}
	
	protected function mapUserToObject(array $user)
	{
		return (new User())->setRaw($user)->map([
			'id' => $user['did'],
			'nickname' => $user['handle'],
			'name' => $user['displayName'] ?? null,
			'email' => null,
			'avatar' => $user['avatar'] ?? null,
		]);
	}
	
	protected function getOauthIntrospection(string $token): array
	{
		// See: https://github.com/bluesky-social/atproto/blob/09656d6db548d18da88ff580aab70a848613584f/packages/oauth/oauth-provider/src/oauth-provider.ts#L1281
		// Also: https://github.com/bluesky-social/atproto/blob/09656d6db548d18da88ff580aab70a848613584f/packages/oauth/oauth-provider/src/client/client.ts#L113
		// This is the current issue: https://github.com/bluesky-social/atproto/blob/09656d6db548d18da88ff580aab70a848613584f/packages/oauth/oauth-provider/src/oauth-provider.ts#L924
		
		// $this->generator ??= new Generator(Key::restore(), $this->getTokenUrl());
		//
		// $headers = [
		// 	'DPoP' => $this->generator->proof(),
		// ];
		
		$options = [
			RequestOptions::FORM_PARAMS => [
				'client_id' => $this->clientId,
				'token' => $token,
			],
			RequestOptions::HEADERS => [
				'Content-Type' => 'application/x-www-form-urlencoded',
				'Accept' => 'application/json',
				'Authorization' => 'Bearer '.$token,
			],
		];
		
		dump(['options' => $options]);
		
		$introspection = $this->getHttpClient()->post('https://bsky.social/oauth/introspect', $options);
		
		$body = (string) $introspection->getBody();
		dump(['body' => $body]);
		
		return json_decode($body, true);
	}
}
