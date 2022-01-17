<?php
/*!
* Hybridauth
* https://hybridauth.github.io | https://github.com/hybridauth/hybridauth
*  (c) 2017 Hybridauth authors | https://hybridauth.github.io/license.html
*/

namespace Hybridauth\Provider;

use Hybridauth\Adapter\OAuth2;
use Hybridauth\Exception\UnexpectedApiResponseException;
use Hybridauth\Data;
use Hybridauth\User;

/**
 * Google OAuth2 provider adapter.
 *
 * Example:
 *
 *   $config = [
 *       'callback' => Hybridauth\HttpClient\Util::getCurrentUrl(),
 *       'keys' => ['id' => '', 'secret' => ''],
 *       'scope' => 'https://www.googleapis.com/auth/userinfo.profile',
 *
 *        // google's custom auth url params
 *       'authorize_url_parameters' => [
 *              'approval_prompt' => 'force', // to pass only when you need to acquire a new refresh token.
 *              'access_type' => ..,      // is set to 'offline' by default
 *              'hd' => ..,
 *              'state' => ..,
 *              // etc.
 *       ]
 *   ];
 *
 *   $adapter = new Hybridauth\Provider\Google($config);
 *
 *   try {
 *       $adapter->authenticate();
 *
 *       $userProfile = $adapter->getUserProfile();
 *       $tokens = $adapter->getAccessToken();
 *       $contacts = $adapter->getUserContacts(['max-results' => 75]);
 *   } catch (\Exception $e) {
 *       echo $e->getMessage() ;
 *   }
 */
class Google extends OAuth2
{
    /**
     * {@inheritdoc}
     */
    // phpcs:ignore
    protected $scope = 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email';

    /**
     * {@inheritdoc}
     */
    protected $apiBaseUrl = 'https://people.googleapis.com/';

    /**
     * {@inheritdoc}
     */
    protected $authorizeUrl = 'https://accounts.google.com/o/oauth2/v2/auth';

    /**
     * {@inheritdoc}
     */
    protected $accessTokenUrl = 'https://oauth2.googleapis.com/token';

    /**
     * {@inheritdoc}
     */
    protected $apiDocumentation = 'https://developers.google.com/identity/protocols/OAuth2';

    /**
     * {@inheritdoc}
     */
    protected function initialize()
    {
        parent::initialize();

        $this->AuthorizeUrlParameters += [
            'access_type' => 'offline'
        ];

        if ($this->isRefreshTokenAvailable()) {
            $this->tokenRefreshParameters += [
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret
            ];
        }
    }

    /**
     * {@inheritdoc}
     *
     * See: https://developers.google.com/identity/protocols/OpenIDConnect#obtainuserinfo
     */
    public function getUserProfile()
    {
        $parameters = [
            'personFields' => 'names,emailAddresses,birthdays,coverPhotos,locales,phoneNumbers'
        ];

        $response = $this->apiRequest('v1/people/me', 'GET', $parameters);

        $data = new Data\Collection($response);

        if (empty($response->resourceName)) {
            throw new UnexpectedApiResponseException('Provider API returned an unexpected response.');
        }

        $userProfile = new User\Profile();

        $userProfile->identifier = $response->names[0]->metadata->source->id;
        $userProfile->firstName = $response->names[0]->givenName;
        $userProfile->lastName = $response->names[0]->familyName;
        $userProfile->displayName = $response->names[0]->displayName;
        $userProfile->photoURL = $response->coverPhotos[0]->url;
        $userProfile->language = $response->locales[0]->value;
        $userProfile->email = $response->emailAddresses[0]->value;
        $userProfile->emailVerified = $response->emailAddresses[0]->metadata->verified ? $userProfile->email : '';
        $userProfile->birthDay = $response->birthdays[0]->date->day;
        $userProfile->birthMonth = $response->birthdays[0]->date->month;
        $userProfile->birthYear = $response->birthdays[0]->date->year;
        $userProfile->phone = $response->phoneNumbers[0]->value;

        if ($this->config->get('photo_size')) {
            $userProfile->photoURL .= '?sz=' . $this->config->get('photo_size');
        }

        return $userProfile;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserContacts($parameters = [])
    {
        $parameters = ['max-results' => 500] + $parameters;

        // Google Gmail and Android contacts
        if (false !== strpos($this->scope, '/m8/feeds/') || false !== strpos($this->scope, '/auth/contacts.readonly')) {
            return $this->getGmailContacts($parameters);
        }

        return [];
    }

    /**
     * Retrieve Gmail contacts
     *
     * @param array $parameters
     *
     * @return array
     *
     * @throws \Exception
     */
    protected function getGmailContacts($parameters = [])
    {
        $url = 'https://www.google.com/m8/feeds/contacts/default/full?'
            . http_build_query(array_replace(['alt' => 'json', 'v' => '3.0'], (array)$parameters));

        $response = $this->apiRequest($url);

        if (!$response) {
            return [];
        }

        $contacts = [];

        if (isset($response->feed->entry)) {
            foreach ($response->feed->entry as $idx => $entry) {
                $uc = new User\Contact();

                $uc->email = isset($entry->{'gd$email'}[0]->address)
                    ? (string)$entry->{'gd$email'}[0]->address
                    : '';

                $uc->displayName = isset($entry->title->{'$t'}) ? (string)$entry->title->{'$t'} : '';
                $uc->identifier = ($uc->email != '') ? $uc->email : '';
                $uc->description = '';

                if (property_exists($response, 'website')) {
                    if (is_array($response->website)) {
                        foreach ($response->website as $w) {
                            if ($w->primary == true) {
                                $uc->webSiteURL = $w->value;
                            }
                        }
                    } else {
                        $uc->webSiteURL = $response->website->value;
                    }
                } else {
                    $uc->webSiteURL = '';
                }

                $contacts[] = $uc;
            }
        }

        return $contacts;
    }
}
