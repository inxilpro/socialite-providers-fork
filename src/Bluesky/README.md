# Bluesky

```bash
composer require socialiteproviders/bluesky
```

### Create the metadata endpoint

```php
Route::get('/auth/bluesky/client-metadata.json', function () {
    return Socialite::driver('bluesky')->clientMetadata();
});
```

### Add configuration to `config/services.php`

```php
'bluesky' => [    
    'client_id' => url('/auth/bluesky/client-metadata.json'),
    'redirect' => env('BLUESKY_REDIRECT_URI'),
    'logo_uri' => env('BLUESKY_LOGO_URI'),
    'tos_uri' => env('BLUESKY_TOS_URI'),
    'policy_uri' => env('BLUESKY_POLICY_URI'),
],
```
