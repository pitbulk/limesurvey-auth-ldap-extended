<?php
/*
 * AuthLDAPExtended Authentication plugin for LimeSurvey
 * Copyright (C) 2025 Sixto Pablo Martin Garcia <sixto.martin.garcia@gmail.com>
 */


// Dynamically include AuthLDAP base plugin
$authLdapPath = Yii::getPathOfAlias('application.core.plugins.AuthLDAP') . '/AuthLDAP.php';
if (file_exists($authLdapPath)) {
    require_once($authLdapPath);
} else {
    throw new Exception("AuthLDAP.php not found at expected path.");
}

require_once "auth_ldap_hooks.php";

class AuthLDAPExtended extends AuthLDAP
{

    const ERROR_NOT_EXISTING_USER_JIT_DISABLED = 900;

    protected static $description = 'LDAP authentication with more capabilities';
    protected static $name = 'LDAPExtended';

    public function getPluginSettings($getValues = true)
    {
        $parentSettings = parent::getPluginSettings($getValues);

        $extendedSettings = [
            'extended_settings' => [
                'type' => 'info',
                'label' => 'Extended Settings:'
            ],
            'auto_update_users' => [
                'type' => 'checkbox',
                'label' => 'Auto update users',
                'default' => true,
                'help' => 'If enabled, the plugin will update at Limesurvey the email address and the full name of the user, during the LDAP login process '
            ],
            'auto_create_group' => [
                'type' => 'checkbox',
                'label' => 'Auto create groups',
                'default' => false,
                'help' => "Enable it in order to allow the plugin to create new groups provided by the LDAP entry that don't exists on LimeSurvey"
            ],
            'sync_group' => [
                'type' => 'checkbox',
                'label' => 'Sync group info',
                'default' => false,
                'help' => 'Enable it in order to sync user groups. User will have the groups provided by the LDAP entry. Old assigned groups will be removed.'
            ],
            'auto_create_role' => [
                'type' => 'checkbox',
                'label' => 'Auto create roles',
                'default' => false,
                'help' => "Enable it in order to allow the plugin to create new roles provided by the LDAP entry that don't exists on LimeSurvey"
            ],
            'sync_role' => [
                'type' => 'checkbox',
                'label' => 'Sync role info',
                'default' => false,
                'help' => 'Enable it in order to sync user roles. User will have the roles provided by the LDAP entry. Old assigned roles will be removed.'
            ],
            'audit' => [
                'type' => 'checkbox',
                'label' => 'Enable logger',
                'default' => false,
                'help' => 'Enable it to store in logs actions of the AuthLDAPExtended plugin.'
            ],
            'groupattribute' => [
                'type' => 'string',
                'label' => 'LDAP attribute of group'
            ],
            'roleattribute' => [
                'type' => 'string',
                'label' => 'LDAP attribute of role'
            ],
        ];

        // Optional: load current values if $getValues is true
        if ($getValues) {
            foreach ($extendedSettings as $key => &$setting) {
                $setting['current'] = $this->get($key);
            }
        }

        return array_merge($parentSettings, $extendedSettings);
    }

    public function newUserSession()
    {
        $audit = $this->get('audit', null, null, false);

        // Do nothing if this user is not AuthLDAP type
        $identity = $this->getEvent()->get('identity');
        if ($identity->plugin != 'AuthLDAPExtended') {
            return;
        }

        $newUserSessionEvent =  $this->getEvent();
        /* unsubscribe from beforeHasPermission, else updating event */
        $this->unsubscribe('beforeHasPermission');
        // Here we do the actual authentication
        $username = $this->getUsername();
        $password = $this->getPassword();

        $ldapmode = $this->get('ldapmode');
        $autoCreateFlag = false;
        $user = $this->api->getUserByName($username);

        // No user found!
        if ($user === null) {
            // If ldap mode is searchandbind and autocreation is enabled we can continue
            if ($this->get('autocreate', null, null, false) == true) {
                $autoCreateFlag = true;
            } else {
                // If the user doesn't exist in the LS database, he can not login
                $this->setAuthFailure(self::ERROR_USERNAME_INVALID); // Error shown : user or password invalid
                if ($audit) {
                    $this->log($username. " user doesn't exist in the LS database and autocreate is disabled", \CLogger::LEVEL_ERROR);
                }
                return;
            }
        }
        if ($user !== null) {

            //If user cannot login via LDAP: setAuthFailure
            if (
                ($user->uid == 1 && !$this->get('allowInitialUser'))
                || !Permission::model()->hasGlobalPermission('auth_ldap', 'read', $user->uid)
            ) {
                $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID);  // Error shown : user or password invalid - swe how a generic message to prevent disclosure if user exists or not
                if ($audit) {
                    $this->log($username. " user cannot login via LDAP.", \CLogger::LEVEL_ERROR);
                }
                return;
            }
        }

        if (empty($password)) {
            // If password is null or blank reject login
            // This is necessary because in simple bind ldap server authenticates with blank password
            $this->setAuthFailure(self::ERROR_PASSWORD_INVALID); // Error shown : user or password invalid
            if ($audit) {
                $this->log($username. " user login failed. Password provided was null or blank.", \CLogger::LEVEL_ERROR);
            }
            return;
        }

        // Get configuration settings:
        $suffix             = $this->get('domainsuffix');
        $prefix             = $this->get('userprefix');
        $searchuserattribute = $this->get('searchuserattribute');
        $extrauserfilter = $this->get('extrauserfilter');
        $usersearchbase = $this->get('usersearchbase');
        $binddn = $this->get('binddn');
        $bindpwd = $this->get('bindpwd');
        $groupsearchbase        = $this->get('groupsearchbase');
        $groupsearchfilter      = $this->get('groupsearchfilter');

        /* Get the conexion, createConnection return an error in array, never return false */
        $ldapconn = $this->createConnection();
        if (is_array($ldapconn)) {
            $this->setAuthFailure($ldapconn['errorCode'], gT($ldapconn['errorMessage']));
            if ($audit) {
                $this->log($username. " user login failed. LDAP connection error. Error code: " . $ldapconn['errorCode']. " Error Message: " . $ldapconn['errorMessage'], \CLogger::LEVEL_ERROR);
            }
            return;
        }

        if (empty($ldapmode) || $ldapmode == 'simplebind') {
            // in simple bind mode we know how to construct the userDN from the username
            $ldapbind = @ldap_bind($ldapconn, $prefix . $username . $suffix, $password);
        } else {
            // in search and bind mode we first do a LDAP search from the username given
            // to foind the userDN and then we procced to the bind operation
            if (empty($binddn)) {
                // There is no account defined to do the LDAP search,
                // let's use anonymous bind instead
                $ldapbindsearch = @ldap_bind($ldapconn);
            } else {
                // An account is defined to do the LDAP search, let's use it
                $ldapbindsearch = @ldap_bind($ldapconn, $binddn, $bindpwd);
            }
            if (!$ldapbindsearch) {
                $this->setAuthFailure(100, ldap_error($ldapconn));
                if ($audit) {
                    $this->log($username. " user login failed. ldapbindsearch found no entry.", \CLogger::LEVEL_ERROR);
                }
                ldap_close($ldapconn); // all done? close connection
                return;
            }
            // Now prepare the search fitler
            if ($extrauserfilter != "") {
                $usersearchfilter = "(&($searchuserattribute=$username)$extrauserfilter)";
            } else {
                $usersearchfilter = "($searchuserattribute=$username)";
            }
            // Search for the user
            $userentry = false;
            foreach (explode(";", $usersearchbase) as $usb) {
                $dnsearchres = ldap_search($ldapconn, $usb, $usersearchfilter, array($searchuserattribute));
                $rescount = ldap_count_entries($ldapconn, $dnsearchres);
                if ($rescount == 1) {
                    $userentry = ldap_get_entries($ldapconn, $dnsearchres);
                    $userdn = $userentry[0]["dn"];
                }
            }
            if (!$userentry) {
                // if no entry or more than one entry returned
                // then deny authentication
                $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
                if ($audit) {
                    $this->log($username. " user login failed. No entry or more than one entry returned", \CLogger::LEVEL_ERROR);
                }
                ldap_close($ldapconn); // all done? close connection
                return;
            }

            // If specified, check group membership
            if ($groupsearchbase != '' && $groupsearchfilter != '') {
                $keywords = array('$username', '$userdn');
                $substitutions = array($username, ldap_escape($userdn, "", LDAP_ESCAPE_FILTER));
                $filter = str_replace($keywords, $substitutions, $groupsearchfilter);
                $groupsearchres = ldap_search($ldapconn, $groupsearchbase, $filter);
                $grouprescount = ldap_count_entries($ldapconn, $groupsearchres);
                if ($grouprescount < 1) {
                    $this->setAuthFailure(
                        self::ERROR_USERNAME_INVALID,
                        gT('Valid username but not authorized by group restriction')
                    );
                    if ($audit) {
                        $this->log($username. " user login failed. Valid username but not authorized by group restriction", \CLogger::LEVEL_ERROR);
                    }
                    ldap_close($ldapconn); // all done? close connection
                    return;
                }
            }

            // binding to ldap server with the userDN and provided credentials
            $ldapbind = @ldap_bind($ldapconn, $userdn, $password);
        }

        // verify user binding
        if (!$ldapbind) {
            $this->setAuthFailure(100, ldap_error($ldapconn));
            if ($audit) {
                $this->log($username. " user login failed. ldap_bind failed", \CLogger::LEVEL_ERROR);
            }
            ldap_close($ldapconn); // all done? close connection
            return;
        }

        ldap_close($ldapconn); // all done? close connection

        // Finally, if user didn't exist and auto creation (i.e. autoCreateFlag == true) is enabled, we create it
        if ($user === null) {
            if ($autoCreateFlag) {
                if (($iNewUID = $this->ldapCreateNewUser($newUserSessionEvent, $username, $password)) && $this->get('automaticsurveycreation', null, null, false)) {
                    Permission::model()->setGlobalPermission($iNewUID, 'surveys', array('create_p'));
                }
                $user = $this->api->getUserByName($username);
                if ($user === null) {
                    $errorCode = $newUserSessionEvent->get('errorCode');
                    if (empty($errorCode)) {
                        $errorCode = self::ERROR_USERNAME_INVALID;
                    }
                    $message = gT('Credentials are valid, but we failed to create a user.');
                    if ($newUserSessionEvent->get('errorMessageTitle')) {
                        $message .= $newUserSessionEvent->get('errorMessageTitle');
                    }
                    if ($newUserSessionEvent->get('errorMessageBody')) {
                        $message .= $newUserSessionEvent->get('errorMessageBody');
                    }
                    $this->setAuthFailure($errorCode, $message);
                    return;
                }
            }
            $updating = false;
        } else {
            $updating = true;

            $this->ldapUpdateUser($newUserSessionEvent, $user, $username, $password);
            $user = $this->api->getUserByName($user->users_name);
        }

        $user = auth_ldap_hook_before_successfully_login($this, $user, $updating);

        // If we made it here, authentication was a success and we do have a valid user
        $this->pluginManager->dispatchEvent(new PluginEvent('newUserLogin', $this));
        /* Set the username as found in LimeSurvey */
        $this->setUsername($user->users_name);
        $this->setAuthSuccess($user);
        if ($audit) {
            $this->log($user->users_name. " user logged", \CLogger::LEVEL_TRACE);
        }
    }

    protected function retrieveUserDataFromLDAP($oEvent, $new_user, $password = null) {
        $ldapmode = $this->get('ldapmode');
        $searchuserattribute = $this->get('searchuserattribute');
        $extrauserfilter = $this->get('extrauserfilter');
        $usersearchbase = $this->get('usersearchbase');
        $binddn         = $this->get('binddn');
        $bindpwd        = $this->get('bindpwd');
        $mailattribute = $this->get('mailattribute');
        $fullnameattribute = $this->get('fullnameattribute');
        $groupattribute = $this->get('groupattribute');
        $roleattribute = $this->get('roleattribute');
        $suffix             = $this->get('domainsuffix');
        $prefix             = $this->get('userprefix');

        // Try to connect
        $ldapconn = $this->createConnection();
        if (is_array($ldapconn)) {
            $oEvent->set('errorCode', self::ERROR_LDAP_CONNECTION);
            $oEvent->set('errorMessageTitle', '');
            $oEvent->set('errorMessageBody', $ldapconn['errorMessage']);
            if ($audit) {
                $this->log($method." error: Connection error: ".$ldapconn['errorMessage'], \CLogger::LEVEL_ERROR);
            }
            return null;
        }

        // Search email address and full name
        if (empty($ldapmode) || $ldapmode == 'simplebind') {
            // Use the user's account for LDAP search
            $ldapbindsearch = @ldap_bind($ldapconn, $prefix . $new_user . $suffix, $password);
        } elseif (empty($binddn)) {
            // There is no account defined to do the LDAP search,
            // let's use anonymous bind instead
            $ldapbindsearch = @ldap_bind($ldapconn);
        } else {
            // An account is defined to do the LDAP search, let's use it
            $ldapbindsearch = @ldap_bind($ldapconn, $binddn, $bindpwd);
        }
        if (!$ldapbindsearch) {
            $oEvent->set('errorCode', self::ERROR_LDAP_NO_BIND);
            $oEvent->set('errorMessageTitle', gT('Could not connect to LDAP server.'));
            $oEvent->set('errorMessageBody', gT(ldap_error($ldapconn)));

            if ($audit) {
                $this->log($method." error: Connection error: No bind. ".ldap_error($ldapconn), \CLogger::LEVEL_ERROR);
            }
            ldap_close($ldapconn); // all done? close connection
            return null;
        }
        // Now prepare the search fitler
        if ($extrauserfilter != "") {
            $usersearchfilter = "(&($searchuserattribute=$new_user)$extrauserfilter)";
        } else {
            $usersearchfilter = "($searchuserattribute=$new_user)";
        }

        $user_data = [];

        // Search for the user
        $userentry = false;
        // try each semicolon-separated search base in order
        foreach (explode(";", $usersearchbase) as $usb) {
            $dnsearchres = ldap_search($ldapconn, $usb, $usersearchfilter, array($mailattribute, $fullnameattribute, $groupattribute, $roleattribute));
            $rescount = ldap_count_entries($ldapconn, $dnsearchres);
            if ($rescount == 1) {
                $userentry = ldap_get_entries($ldapconn, $dnsearchres);
                $new_email = flattenText($userentry[0][strtolower($mailattribute)][0]);
                $new_full_name = flattenText($userentry[0][strtolower($fullnameattribute)][0]);
                $new_groups = [];
                $new_roles = [];
                if (isset($userentry[0][strtolower($groupattribute)])) {
                    unset($userentry[0][strtolower($groupattribute)]["count"]);
                    foreach ($userentry[0][strtolower($groupattribute)] as $group) {
                        $new_groups[] = flattenText($group);
                    }
                }
                if (isset($userentry[0][strtolower($roleattribute)])) {
                    unset($userentry[0][strtolower($roleattribute)]["count"]);
                    foreach ($userentry[0][strtolower($roleattribute)] as $role) {
                        $new_roles[] = flattenText($role);
                    }
                }
                break;
            }
        }

        if ($userentry) {
            $user_data = [
                    'user' => $new_user,
                    'name' => $new_full_name,
                    'mail' => $new_email
            ];

            $user_data = auth_ldap_hook_modify_userdata($this, $userentry, $user_data);
            $user_data["groups"] = $new_groups;
            $user_data["roles"] = $new_roles;
            $user_data["userentry"] = $userentry;
        }
        return $user_data;
    }

    /**
     * Create a LDAP user
     *
     * @param Event $oEvent Either CreateNewUser event or dummy event.
     * @param string $new_user
     * @param string $password
     * @return null|integer New user ID
     */
    private function ldapCreateNewUser($oEvent, $username, $password = null)
    {
        // Get configuration settings:
        $audit = $this->get('audit', null, null, false);
        $method = "ldapCreateNewUser";
        $extended_user_data = $this->retrieveUserDataFromLDAP($oEvent, $username, $password, $audit, $method);

        if (empty($extended_user_data)) {
            $oEvent->set('errorCode', self::ERROR_LDAP_NO_SEARCH_RESULT);
            $oEvent->set('errorMessageTitle', gT('Username not found in LDAP server'));
            $oEvent->set('errorMessageBody', gT('Verify username and try again'));
            ldap_close($ldapconn); // all done? close connection
            if ($audit) {
                $this->log($method."  error: Username not found in LDAP server", \CLogger::LEVEL_ERROR);
            }
            return null;
        }

        $user_groups = $extended_user_data["groups"];
        $user_roles = $extended_user_data["roles"];
        $userentry = $extended_user_data["userentry"];

        $user_data = [
            "user" => $extended_user_data["user"],
            "name" => $extended_user_data["name"],
            "mail" => $extended_user_data["mail"]
        ];

        if (!validateEmailAddress($user_data["mail"])) {
            $oEvent->set('errorCode', self::ERROR_INVALID_EMAIL);
            $oEvent->set('errorMessageTitle', gT("Failed to add user"));
            $oEvent->set('errorMessageBody', gT("The email address is not valid."));
            if ($audit) {
                $this->log($method." error: The email address is not valid", \CLogger::LEVEL_ERROR);
            }
            return null;
        }
        $new_pass = createPassword();
        // If user is being auto created we set parent ID to 1 (admin user)
        if (isset(Yii::app()->session['loginID'])) {
            $parentID = Yii::app()->session['loginID'];
        } else {
            $parentID = 1;
        }
        $status = true;
        $preCollectedUserArray = $oEvent->get('preCollectedUserArray', []);
        if (!empty($preCollectedUserArray)) {
            if (!empty($preCollectedUserArray['status'])) {
                $status = $preCollectedUserArray['status'];
            }
        }

        $authorize = auth_ldap_hook_authorize_user_creation($this, $userentry, $user_data);
        if (!$authorize) {
            $oEvent->set('errorCode', self::ERROR_ALREADY_EXISTING_USER);
            $oEvent->set('errorMessageTitle', '');
            $oEvent->set('errorMessageBody', gT("Not authorized to create the user"));
            if ($audit) {
                $this->log($method." error: Failed to add user, not authorized", \CLogger::LEVEL_ERROR);
            }
            return null;
        }

        $iNewUID = User::insertUser($user_data["user"], $new_pass, $user_data["name"], $parentID, $user_data["mail"], null, $status);
        if (!$iNewUID) {
            $oEvent->set('errorCode', self::ERROR_ALREADY_EXISTING_USER);
            $oEvent->set('errorMessageTitle', '');
            $oEvent->set('errorMessageBody', gT("Failed to add user"));
            if ($audit) {
                $this->log($method." error: Failed to add user", \CLogger::LEVEL_ERROR);
            }
            return null;
        }
        Permission::model()->setGlobalPermission($iNewUID, 'auth_ldap');

        $oEvent->set('newUserID', $iNewUID);
        $oEvent->set('newPassword', $new_pass);
        $oEvent->set('newEmail', $user_data["name"]);
        $oEvent->set('newFullName', $user_data["mail"]);
        $oEvent->set('errorCode', self::ERROR_NONE);
        if ($audit) {
            $this->log("New user created: " . $user_data["user"] . " | " . $user_data["mail"] . " | ". $user_data["name"], \CLogger::LEVEL_TRACE);
        }

        $oUser = $this->api->getUserByName($user_data["user"]);
        if ($oUser) {
            $this->manageGroupData($oUser, $user_groups, false);
            $this->manageRoleData($oUser, $user_roles, false);
        }
        return $iNewUID;
    }

    /**
     * Create a LDAP user
     *
     * @param Event $oEvent Either UpdateUser event or dummy event.
     * @param User $oUser
     * @param string $username
     * @return null|integer Updated user ID
     */
     public function ldapUpdateUser($oEvent, $oUser, $username, $password)
     {
         // Get configuration settings:
         $audit = $this->get('audit', null, null, false);
         $method = "ldapUpdateUser";
         $extended_user_data = $this->retrieveUserDataFromLDAP($oEvent, $username, $password, $audit, $method);

         if (empty($extended_user_data)) {
             $oEvent->set('errorCode', self::ERROR_LDAP_NO_SEARCH_RESULT);
             $oEvent->set('errorMessageTitle', gT('Username not found in LDAP server'));
             $oEvent->set('errorMessageBody', gT('Verify username and try again'));
             ldap_close($ldapconn); // all done? close connection
             if ($audit) {
                 $this->log($method." error: Username not found in LDAP server", \CLogger::LEVEL_ERROR);
             }
             return null;
         }

         $user_groups = $extended_user_data["groups"];
         $user_roles = $extended_user_data["roles"];
         $userentry = $extended_user_data["userentry"];

         $user_data = [
             "user" => $extended_user_data["user"],
             "name" => $extended_user_data["name"],
             "mail" => $extended_user_data["mail"]
         ];

          $authorized = auth_ldap_hook_authorize_user($this, $userentry, $user_data, $oUser);
          if (!$authorized) {
              $this->log("Not authorized ".$user_data["user"], \CLogger::LEVEL_ERROR);
              $this->showError(self::ERROR_UNKNOWN_IDENTITY, gT("User not authorized: ".$user_data["user"]));
              return null;
          }

          $autoUpdateFlag = $this->get('auto_update_users', null, null, true);
          if ($autoUpdateFlag) {
              $changes = array(
                  'full_name' => $user_data["name"],
                  'email' => $user_data["mail"],
              );

              $result = User::model()->updateByPk($oUser->uid, $changes);
              if ($audit) {
                  if ($result) {
                      $this->log("User updated: " . $user_data["user"] . " | " . $user_data["mail"] . " | ". $user_data["name"], \CLogger::LEVEL_TRACE);
                  } else {
                      $this->log("Error updating user " . $user_data["user"], \CLogger::LEVEL_ERROR);
                  }
              }
              $oUser = $this->api->getUserByName($user_data["user"]);
          }

          $this->manageGroupData($oUser, $user_groups, true);
          $this->manageRoleData($oUser, $user_roles, true);
     }

    /**
     * Create LDAP connection and return it
     * In case of error : return an array with errorCode
     *
     * @return array|LDAP\Connection , array if error.
     */
    private function createConnection()
    {
        // Get configuration settings:
        $ldapserver     = $this->get('server');
        $ldapport       = $this->get('ldapport');
        $ldapver        = $this->get('ldapversion');
        $ldaptls        = $this->get('ldaptls');
        $ldapoptreferrals = $this->get('ldapoptreferrals');

        if (empty($ldapport)) {
            $ldapport = 389;
        }

        // Try to connect
        if (strpos($ldapserver, 'ldaps://') === false && strpos($ldapserver, 'ldap://') === false) {
            $ldapserver = 'ldap://' . $ldapserver;
        }
        $ldapconn = ldap_connect($ldapserver . ':' . (int) $ldapport);
        if ($ldapconn === false) {
            // LDAP connect does not connect, but just checks the URI
            // A real connection is only created on the first following ldap_* command
            return array("errorCode" => 2, "errorMessage" => gT('LDAP URI could not be parsed.'));
        }

        // using LDAP version
        if (empty($ldapver)) {
            // If the version hasn't been set, default = 2
            $ldapver = 2;
        }

        $connectionSuccessful = ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, $ldapver);
        if (!$connectionSuccessful) {
            return array("errorCode" => 1, "errorMessage" => gT('Error creating LDAP connection'));
        }
        ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, $ldapoptreferrals);

        // Apply TLS only if ldaps is not used - you can use either SSL or TLS - both does not work
        // TLS also requires LDAPv3
        if (!empty($ldaptls) && $ldaptls == '1' && $ldapver == 3 && preg_match("/^ldaps:\/\//", $ldapserver) === 0) {
            // starting TLS secure layer
            if (!ldap_start_tls($ldapconn)) {
                ldap_unbind($ldapconn); // Could not properly connect, unbind everything.
                return array("errorCode" => 100, 'errorMessage' => ldap_error($ldapconn));
            }
        }

        return $ldapconn;
    }

    private function manageGroupData($oUser, $groups, $updating = false)
    {
        $syncGroupInfo = $this->get('sync_group', null, null, false);
        $autoCreateGroup = $this->get('auto_create_group', null, null, false);

        $groups = auth_ldap_hook_extend_groups($this, $groups, $oUser, $updating);

        $groupObjs = [];
        if ($groups != null) {
            foreach ($groups as $groupName) {
                $group = UserGroup::model()->findByAttributes(["name" => $groupName]);
                if (!$group && $autoCreateGroup) {
                    $this->addGroup($groupName);
                    $group = UserGroup::model()->findByAttributes(["name" => $groupName]);
                }

                if ($group) {
                    $groupObjs[$group->ugid] = $group;
                }
            }
        }

        if ($updating) {
            $userGroups = UserInGroup::model()->findAllByAttributes(["uid" => $oUser->uid]);
            if (!empty($userGroups)) {
                foreach ($userGroups as $userGroup) {
                    if (!array_key_exists($userGroup->ugid, $groupObjs)) {
                        $group = UserGroup::model()->findByAttributes(["ugid" => $userGroup->ugid]);
                        // Remove old groups if sync active and not the owner
                        if ($syncGroupInfo && $group->owner_id != $oUser->uid) {
                            UserInGroup::model()->deleteByPk(['ugid' => $userGroup->ugid, 'uid' => $oUser->uid]);
                        } else {
                            unset($groupObjs[$userGroup->ugid]);
                        }
                    } else {
                        unset($groupObjs[$userGroup->ugid]);
                    }
                }
            }
        }

        // Now add new groups
        if (!empty($groupObjs)) {
            foreach ($groupObjs as $groupObj) {
                UserInGroup::model()->insertRecords(['ugid' => $groupObj->ugid, 'uid' => $oUser->uid]);
            }
        }
    }

    private function addGroup($groupName)
    {
        $groupDescription = "Created by LDAP Plugin";
        $iLoginID = 1;

        $iquery = "INSERT INTO {{user_groups}} (name, description, owner_id) VALUES(:group_name, :group_desc, :loginID)";
        $command = Yii::app()->db->createCommand($iquery)
                        ->bindParam(":group_name", $groupName, PDO::PARAM_STR)
                        ->bindParam(":group_desc", $groupDescription, PDO::PARAM_STR)
                        ->bindParam(":loginID", $iLoginID, PDO::PARAM_INT);
        $result = $command->query();
        if ($result) {
            // Checked
            $id = getLastInsertID(UserGroup::model()->tableName());
            if ($id > 0) {
                $userInGroupsQuery = 'INSERT INTO {{user_in_groups}} (ugid, uid) VALUES (:ugid, :uid)';
                Yii::app()->db->createCommand($userInGroupsQuery)
                    ->bindParam(":ugid", $id, PDO::PARAM_INT)
                    ->bindParam(":uid", $iLoginID, PDO::PARAM_INT)
                    ->query();
            }
            return $id;
        } else {
            return -1;
        }
    }

    private function manageRoleData($oUser, $roles, $updating = false)
    {
        $syncRoleInfo = $this->get('sync_role', null, null, false);
        $autoCreateRole = $this->get('auto_create_role', null, null, false);
        $roleObjs = [];

        $roles = auth_ldap_hook_extend_roles($this, $roles, $oUser, $updating);

        if ($roles != null) {
            foreach ($roles as $roleName) {
                $role = Permissiontemplates::model()->findByAttributes(["name" => $roleName]);
                if (!$role && $autoCreateRole) {
                    $this->addRole($roleName);
                    $role = Permissiontemplates::model()->findByAttributes(["name" => $roleName]);
                }

                if ($role) {
                    $roleObjs[$role->ptid] = $role;
                }
            }
        }

        if ($updating) {
            $userRoles = UserInPermissionrole::model()->findAllByAttributes(["uid" => $oUser->uid]);
            if (!empty($userRoles)) {
                foreach ($userRoles as $userRole) {
                    if (!array_key_exists($userRole->ptid, $roleObjs)) {
                        $role = Permissiontemplates::model()->findByAttributes(["ptid" => $userRole->ptid]);
                        // Remove old roles if sync active and not the owner
                        if ($syncRoleInfo && isset($role) && $role->created_by != $oUser->uid) {
                            UserInPermissionrole::model()->deleteByPk(['ptid' => $userRole->ptid, 'uid' => $oUser->uid]);
                        } else {
                            unset($roleObjs[$userRole->ptid]);
                        }
                    } else {
                        unset($roleObjs[$userRole->ptid]);
                    }
                }
            }
        }

        // Now add new roles
        if (!empty($roleObjs)) {
            foreach ($roleObjs as $roleObj) {
              $userInRole = new UserInPermissionrole();
              $userInRole->ptid = $roleObj->ptid;
              $userInRole->uid = $oUser->uid;
              $userInRole->save();
            }
        }
    }

    private function addRole($roleName)
    {
        $roleDescription = "Created by LDAP Plugin";
        $iLoginID = 1;
        $createdAt = date('Y-m-d H:i:s');
        $renewedLast = date('Y-m-d H:i:s');

        $iquery = "INSERT INTO {{permissiontemplates}} (name, description, renewed_last, created_at, created_by) VALUES(:role_name, :role_desc, :renewed_last, :created_at, :created_by)";
        $command = Yii::app()->db->createCommand($iquery)
                        ->bindParam(":role_name", $roleName, PDO::PARAM_STR)
                        ->bindParam(":role_desc", $roleDescription, PDO::PARAM_STR)
                        ->bindParam(":renewed_last", $renewedLast, PDO::PARAM_STR)
                        ->bindParam(":created_at", $createdAt, PDO::PARAM_STR)
                        ->bindParam(":created_by", $iLoginID, PDO::PARAM_INT);
        $result = $command->query();
        if ($result) {
            // Checked
            $id = getLastInsertID(Permissiontemplates::model()->tableName());
            if ($id > 0) {
                // Assign LDAP permission to the role
                $ldapPermission = new Permission();
                $ldapPermission->entity = 'role';
                $ldapPermission->entity_id = $id;
                $ldapPermission->uid = 0;
                $ldapPermission->permission = "auth_ldap";
                $ldapPermission->read_p = 1;
                $ldapPermission->save();

                $userInRole = new UserInPermissionrole();
                $userInRole->ptid = $id;
                $userInRole->uid = $iLoginID;
                $userInRole->save();
            }

            return $id;
        } else {
            return -1;
        }
    }
}
