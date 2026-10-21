<?php

/**
 * @group plugin_authpld
 * @group auth_plugins
 * @group plugins
 */
class auth_plugin_authpld_test extends DokuWikiTest
{
    protected $pluginsEnabled = array('authplain', 'authpld');

    public function setUp(): void
    {
        parent::setUp();
        if (is_dir(DOKU_CONF . 'pld')) {
            TestUtils::rdelete(DOKU_CONF . 'pld');
        }
        mkdir(DOKU_CONF . 'pld');
    }

    private function backend($passwd, $users = null, $groups = null)
    {
        file_put_contents(DOKU_CONF . 'pld/passwd', $passwd);
        if ($users !== null) {
            file_put_contents(DOKU_CONF . 'pld/users', $users);
        }
        if ($groups !== null) {
            file_put_contents(DOKU_CONF . 'pld/groups', $groups);
        }
        return new auth_plugin_authpld();
    }

    public function testOptionalPasswdFields()
    {
        $auth = $this->backend("short:hash:cvs\nfour:hash:cvs:unused\nfull:hash:cvs:unused:Full+Name:Enable\n");
        $this->assertSame(array(
            'pass' => 'hash',
            'name' => '',
            'mail' => 'short@pld-linux.org',
            'grps' => array('user'),
        ), $auth->getUserData('short'));
        $this->assertSame('', $auth->getUserData('four')['name']);
        $this->assertSame('Full Name', $auth->getUserData('full', false)['name']);
    }

    public function testOptionalJidAndNameOverride()
    {
        $auth = $this->backend(
            "alice:hash:cvs::Original\nbob:hash:cvs::Bob\ncarol:hash:cvs::Carol\n",
            "alice:external@example.org:Alice Smith\nbob:external@example.org::bob@example.org\n"
            . "carol:external@example.org:\nunknown:external@example.org:Unknown\n"
        );
        $alice = $auth->getUserData('alice');
        $this->assertSame('Alice Smith', $alice['name']);
        $this->assertSame('alice@pld-linux.org', $alice['mail']);
        $this->assertArrayNotHasKey('jid', $alice);
        $this->assertSame('Bob', $auth->getUserData('bob')['name']);
        $this->assertSame('bob@example.org', $auth->getUserData('bob')['jid']);
        $this->assertSame('Carol', $auth->getUserData('carol')['name']);
        $this->assertFalse($auth->getUserData('unknown'));
    }

    public function testMalformedRecordsAndComments()
    {
        $auth = $this->backend(
            "# comment\n\nbroken\nmissing:hash\n:hash:cvs\nalice:hash:cvs # comment\n",
            "broken\nalice\nalice:mail\n:mail:Unknown\n",
            "broken\nalice\nunknown:admin\nalice:staff # comment\n"
        );
        $this->assertSame(1, $auth->getUserCount());
        $this->assertSame('', $auth->getUserData('alice')['name']);
        $this->assertSame(array('user', 'staff'), $auth->getUserData('alice')['grps']);
    }

    public function testDisabledAndBuilderAccounts()
    {
        $auth = $this->backend(
            "enabled:hash:cvs:::Enable\nlegacy:hash:cvs\nbuilder1:hash:cvs:::Enable\n"
            . "disabled:hash:cvs:::Disable\nlocked:hash:cvs:::Locked\nzero:hash:cvs:::0\n",
            "disabled:mail:Disabled\n",
            "disabled:admin\n"
        );
        $this->assertSame(2, $auth->getUserCount());
        foreach (array('builder1', 'disabled', 'locked', 'zero') as $user) {
            $this->assertFalse($auth->getUserData($user));
        }
    }

    public function testReadonlyGroupAtAnyPosition()
    {
        $auth = $this->backend(
            "first:hash:readonly.cvs\nlast:hash:cvs\nnormal:hash:cvs\n",
            null,
            "first:staff\nlast:readonly\nnormal:staff\n"
        );
        foreach (array('first', 'last') as $user) {
            $this->assertContains('readonly', $auth->getUserData($user)['grps']);
            $this->assertNotContains('user', $auth->getUserData($user)['grps']);
        }
        $this->assertContains('user', $auth->getUserData('normal')['grps']);
    }

    public function testUserCountLoadsPldDataFirst()
    {
        $auth = $this->backend("alice:hash:cvs\nbob:hash:cvs\n", null, "alice:staff\n");
        $this->assertSame(2, $auth->getUserCount());
        $this->assertSame(1, $auth->getUserCount(array('grps' => 'staff')));
    }

    public function testUserListLoadsPldDataFirst()
    {
        $auth = $this->backend("bob:hash:cvs\nalice:hash:cvs\n", null, "alice:staff\n");
        $this->assertSame(array('alice', 'bob'), array_keys($auth->retrieveUsers()));
        $this->assertSame(array('bob'), array_keys($auth->retrieveUsers(1, 1)));
        $this->assertSame(array('alice'), array_keys($auth->retrieveUsers(0, 0, array('grps' => 'staff'))));
    }

    public function testGroupListLoadsPldDataFirst()
    {
        $auth = $this->backend("alice:hash:cvs\nbob:hash:cvs\n", null, "alice:staff\n");
        $this->assertTrue($auth->canDo('getGroups'));
        $this->assertEqualsCanonicalizing(array('user', 'staff'), $auth->retrieveGroups());
    }

    public function testPasswordVerification()
    {
        $hash = crypt('correct password', '$6$authpldtest$');
        $auth = $this->backend("alice:$hash:cvs\n");
        $this->assertTrue($auth->checkPass('alice', 'correct password'));
        $this->assertFalse($auth->checkPass('alice', 'wrong password'));
        $this->assertFalse($auth->checkPass('missing', 'correct password'));
    }

    public function testInvalidUserLookup()
    {
        $auth = $this->backend("alice:hash:cvs\n");
        $this->assertFalse($auth->getUserData('missing'));
        $this->assertFalse($auth->getUserData(array('alice')));
        $this->assertFalse($auth->getUserData(null));
    }

    public function testCapabilitiesAndSessionCache()
    {
        $auth = $this->backend("alice:hash:cvs\n");
        $this->assertTrue($auth->success);
        foreach (array('getUsers', 'getUserCount', 'getGroups') as $cap) {
            $this->assertTrue($auth->canDo($cap));
        }
        foreach (array('addUser', 'delUser', 'modLogin', 'modPass', 'modName', 'modMail', 'modGroups') as $cap) {
            $this->assertFalse($auth->canDo($cap));
        }
        $this->assertFalse($auth->useSessionCache('alice'));
    }

    public function testMissingPasswordFile()
    {
        $auth = new auth_plugin_authpld();
        $this->assertFalse($auth->success);
        $this->assertSame(0, $auth->getUserCount());
        $this->assertSame(array(), $auth->retrieveUsers());
        $this->assertFalse($auth->getUserData('testuser'));
    }

    public function localDirectoryCases()
    {
        return array(
            'PLD package layout' => array(true, false),
            'local database takes precedence' => array(true, true),
            'missing local database does not use packaged database' => array(false, true),
        );
    }

    /**
     * @dataProvider localDirectoryCases
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLocalConfigDirectory($localExists, $packagedExists)
    {
        define('DOKU_LOCAL', TMP_DIR . '/local/');
        mkdir(DOKU_LOCAL . 'pld', 0777, true);
        if ($packagedExists) {
            file_put_contents(DOKU_CONF . 'pld/passwd', "packaged:hash:cvs\n");
        }
        if ($localExists) {
            $hash = crypt('correct password', '$6$authpldtest$');
            file_put_contents(DOKU_LOCAL . 'pld/passwd', "alice:$hash:cvs\n");
            file_put_contents(DOKU_LOCAL . 'pld/users', "alice:mail:Alice Smith:alice@example.org\n");
            file_put_contents(DOKU_LOCAL . 'pld/groups', "alice:staff\n");
        }

        $auth = new auth_plugin_authpld();
        $this->assertSame($localExists, $auth->success);
        $this->assertFalse($auth->getUserData('packaged'));
        if ($localExists) {
            $this->assertTrue($auth->checkPass('alice', 'correct password'));
            $this->assertSame('Alice Smith', $auth->getUserData('alice')['name']);
            $this->assertSame('alice@example.org', $auth->getUserData('alice')['jid']);
            $this->assertSame(array('user', 'staff'), $auth->getUserData('alice')['grps']);
            $this->assertSame(1, $auth->getUserCount());
        } else {
            $this->assertSame(0, $auth->getUserCount());
        }
    }
}
