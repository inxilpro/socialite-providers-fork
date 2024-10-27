<?php

namespace SocialiteProviders\Bluesky;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\RequestOptions;
use Illuminate\Http\Response;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\URL;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
	public const IDENTIFIER = 'BLUESKY';
	
	protected $scopeSeparator = ' ';
	
	protected $usesPKCE = true;
	
	protected $scopes = [
		'atproto',
		'transition:generic',
	];
	
	protected ?string $nonce = null;
	
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
	
	public function getAccessTokenResponse($code)
	{
		try {
			return parent::getAccessTokenResponse($code);
		} catch (RequestException $e) {
			// FIXME: Do this on `use_dpop_nonce`
			
			if (null === $this->nonce) {
				$this->nonce = Arr::wrap($e->getResponse()->getHeader('DPoP-Nonce'))[0];
				dump(['saved nonce' => $this->nonce]);
				return $this->getAccessTokenResponse($code);
			}
			
			throw $e;
		}
	}
	
	protected function getTokenFields($code)
	{
		$fields = parent::getTokenFields($code);
		
		dump(['fields' => $fields]);
		
		return $fields;
	}
	
	public function getTokenHeaders($code)
	{
		$headers = [
			'DPoP' => Dpop::sign($this->getTokenUrl(), $this->nonce),
			'Accept' => 'application/json',
		];
		
		dump(['headers' => $headers]);
		
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
		$introspection = $this->getHttpClient()->get('https://bsky.social/oauth/introspect', [
			RequestOptions::HEADERS => [
				'Accept' => 'application/json',
				'Authorization' => 'Bearer '.$token,
			],
		]);
		
		return json_decode((string) $introspection->getBody(), true);
	}
}
