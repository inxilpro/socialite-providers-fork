<?php

namespace SocialiteProviders\Bluesky;

use SocialiteProviders\Manager\SocialiteWasCalled;

class BlueskyExtendSocialite
{
	public function handle(SocialiteWasCalled $socialiteWasCalled): void
	{
		$socialiteWasCalled->extendSocialite('bluesky', Provider::class);
	}
}
