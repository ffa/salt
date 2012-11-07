'''
Management of MySQL grants (user permissions).
==============================================

NOTE: This module requires the MySQLdb python module and the proper
settings in the minion config file.
See salt.modules.mysql for more information.

The mysql_grants module is used to grant and revoke MySQL permissions.

The ``name`` you pass in purely symbolic and does not have anything to do
with the grant itself.

The ``database`` parameter needs to specify a 'priv_level' in the same
specification as defined in the MySQL documentation:

* \*
* \*.\*
* db_name.\*
* db_name.tbl_name
* etc...

.. code-block:: yaml

   frank_exampledb:
      mysql_grants.present:
       - grant: select,insert,update
       - database: exampledb.*
       - user: frank
       - host: localhost

   frank_otherdb:
     mysql_grants.present:
       - grant: all privileges
       - database: otherdb.*
       - user: frank

   restricted_singletable:
     mysql_grants.present:
       - grant: select
       - database: somedb.sometable
       - user: joe
'''


def __virtual__():
    '''
    Only load if the mysql module is available
    '''
    return 'mysql_grants' if 'mysql.grant_exists' in __salt__ else False


def present(name,
            privileges=None,
            grant=None,
            database=None,
            user=None,
            host='localhost',
            grant_option=False,
            escape=True):
    '''
    Ensure that the grant is present with the specified properties

    name
        The name (key) of the grant to add

    privileges
    grant (depreciated)
        The grant priv_type (ie. select,insert,update OR all privileges)

    database
        The database priv_level (ie. db.tbl OR db.*)

    user
        The user to apply the grant to

    host
        The MySQL server

    grant_option
        Adds the WITH GRANT OPTION to the defined grant. default: False

    escape
        Defines if the database value gets escaped or not. default: True
    '''
    if privileges is None and grant is not None:
        privileges = grant

    comment = 'Grant {0} on {1} to {2}@{3} is already present'
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': comment.format(privileges, database, user, host)
           }

    # check if grant exists
    grant_exists = __salt__['mysql.grant_exists'](
        privileges, database, user, host, grant_option, escape
    )
    if grant_exists is True:
        return ret

    # The grant is not present, make it!
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'MySQL grant {0} is set to be created'.format(name)
        return ret

    if grant_exists is None:
        if __salt__['mysql.grant_revoke'](
                "ALL PRIVILEGES",
                database,
                user,
                host,
                grant_option) is False:
            ret['comment'] = ('Failed to remove previous grant before applying new'
                            ' grant: "GRANT {0} ON {1} TO {2}@{3}"'
                            ''.format(privileges, database, user, host))
            ret['result'] = False

    if __salt__['mysql.grant_add'](
        privileges, database, user, host, grant_option, escape
    ):
        ret['comment'] = 'Grant {0} on {1} to {2}@{3} has been added'
        ret['comment'] = ret['comment'].format(privileges, database, user, host)
        ret['changes'][name] = 'Present'
    else:
        ret['comment'] = 'Failed to execute: "GRANT {0} ON {1} TO {2}@{3}"'
        ret['comment'] = ret['comment'].format(privileges, database, user, host)
        ret['result'] = False
    return ret


def absent(name,
           privileges=None,
           grant=None,
           database=None,
           user=None,
           host='localhost',
           grant_option=False,
           escape=True):
    '''
    Ensure that the grant is absent

    name
        The name (key) of the grant to add

    privileges
    grant (depreciated)
        The grant priv_type (ie. select,insert,update OR all privileges)

        Note: The privileges must be exact to remove the grant. Alternatively,
              use "ALL PRIVILEGES" if the privileges are unknown to remove the
              grant.

    database
        The database priv_level (ie. db.tbl OR db.*)

    user
        The user to apply the grant to

    host
        The MySQL server
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    if privileges is None and grant is not None:
        privileges = grant

    #check if db exists and remove it
    if __salt__['mysql.grant_exists'](
            privileges,
            database,
            user, host,
            grant_option,
            escape):

        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = 'MySQL grant {0} is set to be revoked'
            ret['comment'] = ret['comment'].format(name)
            return ret
        if __salt__['mysql.grant_revoke'](
                privileges,
                database,
                user,
                host,
                grant_option):
            ret['comment'] = 'Grant {0} on {1} for {2}@{3} has been revoked'
            ret['comment'].format(privileges, database, user, host)
            ret['changes'][name] = 'Absent'
            return ret

    # fallback
    ret['comment'] = ('Grant {0} on {1} to {2}@{3} is not present, so it'
                      ' cannot be revoked').format(
                              privileges,
                              database,
                              user,
                              host
                              )
    return ret
