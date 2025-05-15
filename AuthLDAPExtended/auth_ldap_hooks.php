<?php
/*
 * AuthLDAPExtended Authentication plugin for LimeSurvey
 * Copyright (C) 2025 Sixto Pablo Martin Garcia <sixto.martin.garcia@gmail.com>
 */

if (!defined('BASEPATH')) {
    exit('No direct script access allowed');
}

// Use this hook to retrieve/modify roles to be assigned to the logged user
function auth_ldap_hook_extend_roles($authLdapExtended, $roles, $oUser, $updating = false)
{
    return $roles;
}

// Use this hook to retrieve/modify groups to be assigned to the logged user
function auth_ldap_hook_extend_groups($authLdapExtended, $groups, $oUser, $updating = false)
{
    return $groups;
}

// Use this hook to verify/modify user data (username, name, mail)
function auth_ldap_hook_modify_userdata($authLdapExtended, $ldap_entry, $user_data)
{
    return $user_data;
}

// Use this hook to authorize a user that already exists
function auth_ldap_hook_authorize_user($authLdapExtended, $ldap_entry, $user_data, $user)
{
    $authorized = true;
    return $authorized;
}

// Use this hook to authorize user creation
function auth_ldap_hook_authorize_user_creation($authLdapExtended, $ldap_entry, $user_data)
{
    $authorized = true;
    return $authorized;
}

// Use this hook to modify something from the user object before log in
function auth_ldap_hook_before_successfully_login($authLdapExtended, $oUser, $updating = false)
{
    return $oUser;
}
