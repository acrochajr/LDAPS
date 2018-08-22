<?php

class LDAPTools
{
    private $username       = 'admin';
    private $password       = '';
    private $account_suffix = '@xyz.net';
    private $hostnameSSL    = 'ldap.xyz.net';


    private $con;

    public function __construct()
    {

        ldap_set_option($this->con, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($this->con, LDAP_OPT_SIZELIMIT, 33);
        ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
        set_time_limit(30);
    }

    public function connect()
    {
        ####################
        # SSL bind attempt #
        ####################
        $port = "636";
        $this->con = ldap_connect("ldaps://".$this->hostnameSSL, $port);


        if (!is_resource($this->con))
        {
            throw new \Exception("Não foi possível conectar ao host $this->hostnameSSL");
        }
        else
        {
            ldap_set_option($this->con, LDAP_OPT_REFERRALS, 0);
        }
    }

    /*
     * Try to bind username to connection, if username and password is null use domain admin
     */
    public function bind($username = null, $password = null)
    {
        if (empty($password))
        {
            $password = Crypto::decrypt(base64_decode($this->password), substr(sha1('xyz', true), 0, 16));
        }

        if (empty($username))
        {
        $username = $this->username;

        }

        $bind = @ldap_bind($this->con, $username . $this->account_suffix, $password);

        if (!$bind)
        {
            throw new \Exception("Não foi possível conectar utilizando o usuário e senha digitados.");
        }

	return $bind;

    }


    public function disconnect()
    {
        ldap_close($this->con);
    }

 
    public function replaceAttribute($options = array ())
    {

    /*
     * Exemplo:
     *          $username = yourpassword

                $ldap->connect();
                $ldap->bind($username, $active_password);

                $ldap->replaceAttribute(array (
                        'dn'           => 'DC=xyz DC=net',
                        'attr_search'  => 'sAMAccountName',
                        'value_search' => $username,
                        'attribute'    => array('unicodePwd' => iconv("UTF-8", "UTF-16LE", '"' . $password. '"'))
                ));
     * */

        $this->connect();
        $this->bind();


        $filter = "(&(objectClass=user)(objectCategory=person)(sAMAccountname={$options['value_search']}))";
        $sr  = ldap_search($this->con,  $options['dn'], $filter );

        $ent = ldap_get_entries($this->con, $sr);


        if (!ldap_mod_replace($this->con, $ent[0]["distinguishedname"][0], $options['attribute']))

        {
            throw new \Exception('Não foi possível trocar a senha.');
        }

        $this->disconnect();

    }
}

