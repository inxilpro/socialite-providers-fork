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

class Provider extends AbstractProvider
{
	public const IDENTIFIER = 'BLUESKY';
	
	protected $scopeSeparator = ' ';
	
	protected $usesPKCE = true;
	
	protected $scopes = [
		'atproto',
		'transition:generic',
	];
	
	protected ?Generator $generator = null;
	
	protected string $did;
	
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
		
		$data = json_decode($response->getBody(), true);
		
		$this->did = data_get($data, 'sub');
		
		return $data;
	}
	
	public function getTokenHeaders($code)
	{
		$this->generator ??= new Generator(Key::restore(), $this->getTokenUrl());
		
		return [
			'DPoP' => $this->generator->proof(),
			'Accept' => 'application/json',
		];
	}
	
	protected function getTokenUrl()
	{
		return 'https://bsky.social/oauth/token';
	}
	
	protected function getUserByToken($token)
	{
		$options = [
			RequestOptions::QUERY => [
				'actor' => $this->did,
			],
			RequestOptions::HEADERS => [
				'Accept' => 'application/json',
			],
		];
		
		$response = $this->getHttpClient()->get('https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile', $options);
		
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
	
	protected function lookUpDid(string $did)
	{
		// TODO:
		// https://plc.directory/did:plc:...
	}
}
