# -*- coding: utf-8 -*-
'''
Operation System Security Benchmark module
'''

import re
import logging
import pwd
# Import salt libs
from salt import utils


__virtualname__ = 'os_benchmark'
__outputter__ = {'run': 'nested'}

GREP = utils.which('egrep')
CHAGE = utils.which('chage')
RPMQUERY = utils.which('rpm')
STAT = utils.which('stat')
if utils.which('chkconfig'):
    CHKCONFIG = utils.which('chkconfig')
if utils.which('systemctl'):
    CHKCONFIG = utils.which('systemctl')

PASSED = 'Passed'
FAILED = 'Failed'
UNKNOWN = 'Unknown'
KEYS_MAP = {
    'id': 'id',
    'os': 'os',
    'osrelease': 'os_release'
}
os_benchmark = {}


log = logging.getLogger(__name__)


def __virtual__():
    '''
    Only load module on Linux
    '''
    if 'Linux' in __salt__['grains.get']('kernel'):
        return __virtualname__
    return False


def run():
    '''
    Operation System Security Benchmark.

    CLI Example:

    .. code-block:: bash

        salt '*' os_benchmark.run
    '''
    os_benchmark.update({v: __grains__[k] for k, v in KEYS_MAP.iteritems() if k in __grains__ and __grains__[k]})
    os_benchmark['type'] = 'os'
    os_benchmark['benchmark'] = [
        _audit_2_1(),
        _audit_2_2(),
        _audit_2_3(),
        _audit_2_4(),
        _audit_2_5(),
        _audit_2_6(),
        _audit_2_7(),
        _audit_4_1(),
        _audit_4_2(),
        _audit_5_1(),
        _audit_6_2(),
        _audit_6_3(),
        _audit_6_4(),
        _audit_6_5(),
        _audit_8_1(),
        _audit_9_1()
    ]
    return os_benchmark


def _audit_2_1():
    '''
    Verify unused user accounts.
    '''
    _id = 'os_remove_unused_accounts'
    state = UNKNOWN
    configs = []
    try:
        ret = _grep('/*sh$', '/etc/passwd')
        for line in ret.splitlines():
            line = line.strip(' \t\n\r')
            configs.append(line.split(':')[0])
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify unused user accounts: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _audit_2_2():
    '''
    Verify password fields are not empty
    '''
    _id = 'os_password_required'
    configs = []
    try:
        state = PASSED
        cmd = "/bin/awk -F: '($2 == \"\" ) { print $1 \" does not have a password \"}' /etc/shadow"
        ret = __salt__['cmd.run'](cmd, python_shell=False)
        if ret:
            state = FAILED
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify password fields are not empty: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _audit_2_3():
    '''
    Verify No UID 0 Accounts Exist Other Than root.
    '''
    _id = 'os_uni_root_ensure'
    configs = []
    try:
        state = PASSED
        users = [user.pw_name for user in pwd.getpwall()]
        cmd = "/bin/awk -F: '($3 == 0) { print $1 }' /etc/passwd"
        ret = __salt__['cmd.run'](cmd, python_shell=False)
        root_accounts = [account.strip(' \t\n\r') for account in ret.splitlines() if account.strip(' \t\n\r') in users]
        if len(root_accounts) > 1:
            state = FAILED
        configs = root_accounts
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify No UID 0 Accounts Exist Other Than root: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _audit_2_4():
    '''
    Verify password creation requirements are configured.
    '''
    _id = 'os_strong_password'
    configs = []
    try:
        state = PASSED
        # Verify config in file /etc/pam.d/password-auth
        ret = _grep('pam_pwquality.so', '/etc/pam.d/password-auth')
        if not re.search('pam_pwquality.so', ret, re.IGNORECASE) \
                or not re.search('try_first_pass', ret, re.IGNORECASE) \
                or not re.search('retry=3', ret, re.IGNORECASE):
            state = FAILED
        configs.append('[/etc/pam.d/password-auth] {0}'.format(ret.strip(' \t\n\r')))

        # Verify config in file /etc/pam.d/system-auth
        ret = _grep('pam_pwquality.so', '/etc/pam.d/system-auth')
        if not re.search('pam_pwquality.so', ret, re.IGNORECASE) \
                or not re.search('try_first_pass', ret, re.IGNORECASE) \
                or not re.search('retry=3', ret, re.IGNORECASE):
            state = FAILED
        configs.append('[/etc/pam.d/system-auth] {0}'.format(ret.strip(' \t\n\r')))

        # Verify minimum acceptable size for the new password
        ret = _grep('^minlen', '/etc/security/pwquality.conf')
        if not ret:
            ret = _grep('"^# minlen"', '/etc/security/pwquality.conf')
        match = re.search('(minlen\s*=\s*\d*)', ret)
        if match:
            config = match.group(1).replace(' ', '')
            minlen = int(config.split('=')[-1])
            if minlen < 8:
                state = FAILED
            configs.append('[/etc/security/pwquality.conf] {0}'.format(config))
        else:
            state = FAILED
            configs.append('[/etc/security/pwquality.conf] {0}'.format(ret.strip(' \t\n\r')))

        # Verify credit for having digits in the new password
        ret = _grep('^dcredit', '/etc/security/pwquality.conf')
        if not ret:
            ret = _grep('"^# dcredit"', '/etc/security/pwquality.conf')
        match = re.search('(dcredit\s*=\s*\d*)', ret)
        if match:
            config = match.group(1).replace(' ', '')
            dcredit = int(config.split('=')[-1])
            if dcredit > -1:
                state = FAILED
            configs.append('[/etc/security/pwquality.conf] {0}'.format(config))
        else:
            state = FAILED
            configs.append('[/etc/security/pwquality.conf] {0}'.format(ret.strip(' \t\n\r')))

        # Verify credit for having uppercase characters in the new password
        ret = _grep('^ucredit', '/etc/security/pwquality.conf')
        if not ret:
            ret = _grep('"^# ucredit"', '/etc/security/pwquality.conf')
        match = re.search('(ucredit\s*=\s*\d*)', ret)
        if match:
            config = match.group(1).replace(' ', '')
            ucredit = int(config.split('=')[-1])
            if ucredit > -1:
                state = FAILED
            configs.append('[/etc/security/pwquality.conf] {0}'.format(config))
        else:
            state = FAILED
            configs.append('[/etc/security/pwquality.conf] {0}'.format(ret.strip(' \t\n\r')))

        # Verify credit for having lowercase characters in the new password
        ret = _grep('^lcredit', '/etc/security/pwquality.conf')
        if not ret:
            ret = _grep('"^# lcredit"', '/etc/security/pwquality.conf')
        match = re.search('(lcredit\s*=\s*\d*)', ret)
        if match:
            config = match.group(1).replace(' ', '')
            lcredit = int(config.split('=')[-1])
            if lcredit > -1:
                state = FAILED
            configs.append('[/etc/security/pwquality.conf] {0}'.format(config))
        else:
            state = FAILED
            configs.append('[/etc/security/pwquality.conf] {0}'.format(ret.strip(' \t\n\r')))

        # Verify credit for having other characters in the new password
        ret = _grep('^ocredit', '/etc/security/pwquality.conf')
        if not ret:
            ret = _grep('"^# ocredit"', '/etc/security/pwquality.conf')
        match = re.search('(ocredit\s*=\s*\d*)', ret)
        if match:
            config = match.group(1).replace(' ', '')
            ocredit = int(config.split('=')[-1])
            if ocredit > -1:
                state = FAILED
            configs.append('[/etc/security/pwquality.conf] {0}'.format(config))
        else:
            state = FAILED
            configs.append('[/etc/security/pwquality.conf] {0}'.format(ret.strip(' \t\n\r')))
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify password creation requirements are configured: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _audit_2_5():
    '''
    Verify password hashing algorithm is SHA-512
    '''
    _id = 'os_password_hashing_algorithm'
    configs = []
    try:
        state = PASSED
        # Verify config in file /etc/pam.d/password-auth
        ret = _grep('"^password\s+sufficient\s+pam_unix.so"', '/etc/pam.d/password-auth')
        match = re.search('sha512', ret, re.IGNORECASE)
        if not match:
            state = FAILED
        configs.append('[/etc/pam.d/password-auth] {0}'.format(ret.strip(' \t\n\r')))

        # Verify config in file /etc/pam.d/system-auth
        ret = _grep('"^password\s+sufficient\s+pam_unix.so"', '/etc/pam.d/system-auth')
        match = re.search('sha512', ret, re.IGNORECASE)
        if not match:
            state = FAILED
        configs.append('[/etc/pam.d/system-auth] {0}'.format(ret.strip(' \t\n\r')))
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify password hashing algorithm is SHA-512: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _audit_2_6():
    '''
    Verify password expiration is 90 days or less.
    '''
    _id = 'os_password_expiration'
    configs = []
    try:
        state = PASSED
        # Verify PASS_MAX_DAYS is 90 or less
        ret = _grep('"PASS_MAX_DAYS"', '/etc/login.defs')
        match = re.search('(PASS_MAX_DAYS\s+\d*\s*$)', ret)
        if match:
            config = match.group(1).strip(' \t\n\r')
            max_days = int(config.split()[-1])
            if max_days > 90:
                state = FAILED
            configs.append('[/etc/login.defs] {0}'.format(config))
        else:
            state = FAILED
            configs.append('[/etc/login.defs] {0}'.format(ret))

        # Verify all users with a password have their maximum days
        # between password change set to 90 or less
        ret = _grep('^[^:]+:[^\!*]', '/etc/shadow')
        users = []
        for line in ret.splitlines():
            line = line.strip(' \t\n\r')
            users.append(line.split(':')[0])
        for username in users:
            ret = _chage('--list {0}'.format(username))
            match = re.search('(Maximum number of days between password change\s+:\s+\d*)', ret)
            if match:
                config = match.group(1).strip(' \t\n\r')
                max_days = int(config.split()[-1])
                if max_days > 90:
                    state = FAILED
                    configs.append('[{0}] {1}'.format(username, config))
            else:
                state = FAILED
                configs.append('[{0}] {1}'.format(username, ret))
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify password expiration is 90 days or less: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _audit_2_7():
    '''
    Verify password reuse is limited.
    '''
    _id = 'os_password_reuse'
    configs = []
    try:
        state = PASSED
        # Verify config in file /etc/pam.d/password-auth
        ret = _grep('"^password\s+sufficient\s+pam_unix.so"', '/etc/pam.d/password-auth')
        pwd_auth_state, config = _verify_pwd_reuse(ret)
        if pwd_auth_state == FAILED:
            state = FAILED
        configs.append('[/etc/pam.d/password-auth] {0}'.format(config))

        # Verify config in file /etc/pam.d/system-auth
        ret = _grep('"^password\s+sufficient\s+pam_unix.so"', '/etc/pam.d/system-auth')
        sys_auth_state, config = _verify_pwd_reuse(ret)
        if sys_auth_state == FAILED:
            state = FAILED
        configs.append('[/etc/pam.d/system-auth] {0}'.format(config))
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify password reuse is limited: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _audit_4_1():
    '''
    Verify enable iptables / firewalld.
    '''
    _id = 'os_firewall_required'
    configs = []
    try:
        state = PASSED
        # Verify iptables is installed
        config = _rpmquery('iptables')
        configs.append(config.strip(' \t\n\r'))
        match = re.search('(not installed)', config, re.IGNORECASE)
        if match:
            state = FAILED
        else:
            # Verify auto start iptables
            config = 'Iptables is disabled'
            if 'systemctl' in CHKCONFIG:
                config = _chkconfig('firewalld')
            if 'chkconfig' in CHKCONFIG:
                config = _chkconfig('iptables')

            match1 = re.search('(3:on)', config, re.IGNORECASE)
            match2 = re.search('(enabled)', config, re.IGNORECASE)
            if not match1 and not match2:
                state = FAILED
            configs.append('Iptables is {0}'.format(config.strip(' \t\n\r')))
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify enable iptables / firewalld: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _audit_4_2():
    '''
    Verify iptables rules.
    '''
    _id = 'os_firewall_rule_check'
    configs = []
    try:
        state = PASSED
        cmd = 'iptables-save'
        rules = __salt__['cmd.run'](cmd)
        for line in rules.splitlines():
            if line.startswith('#'):
                continue
            configs.append(line.strip(' \t\n\r'))

    except Exception as exp:
        state = FAILED
        log.error('Error - Verify iptables rules: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}

def _audit_4_3():
    '''
        Verify has iptables log 
    '''
    _id = 'os_firewall_logs_rule_check'
    configs = []
    try:
        state = PASSED
        path = '/var/log/iptables.log'
        cmd = 'tail -f '+ path
        output = __salt__['cmd.run'](cmd)
    	if 'No such file or directory' in output.splitlines()[0]:
    	    configs.append('No iptables log')
            state = FAILED
        else:
            configs.append('Has iptables in %s' % path)
            if output == "":
                configs.append('No content in /var/log/iptables/log')
                state = FAILED
        cmd = '/sbin/iptables -S'
        output  = __salt__['cmd.run'](cmd)
        iptables_configs = output.splitlines() 
        if '-A INPUT -j LOG --log-level debug --log-prefix "Dropped input by firewall: "' in iptables_configs:
            pass
        else:
            state == FAILED
            configs.append('No rules block in/out connection')
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify iptables logs write rules: %s' % exp )

    return {'id': _id , 'state' : state, 'configs': configs}

def _audit_4_4():
    '''
    Verify default rules iptables
    '''
    _id = 'os_firewall_default_rules_check'
    configs = []
    try:
        state = PASSED
        cmd = 'iptables -L'
        output = __salt__['cmd.run'](cmd)
        for line in output.splitlines():
            if line.startswith('Chain'):
                configs.append(line)
                if '(policy DROP)' not in line:
                    state = FAILED
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify iptables logs write rules: %s' % exp )

    return {'id': _id , 'state' : state, 'configs': configs}

def _audit_4_5():
    '''
    Verify iptables loopback interface rules
    '''
    _id = 'os_firewall_loopback_interface_rules'
    configs = []
    try:
        state = PASSED
        cmd = 'iptables -S'
        output = __salt__['cmd.run'](cmd)
        configs = output.splitlines()
        rules  = []
        rules.append('-A INPUT -i lo -j ACCEPT')
        rules.append('-A OUTPUT -o lo -j ACCEPT')
        rules.append('-A INPUT -s 127.0.0.0/8 -j DROP')
        if not set(rules).issubset(output.splitlines()):
            state = FAILED
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify iptables logs write rules: %s' % exp )

    return {'id': _id , 'state' : state, 'configs': configs}

def _audit_4_6():
    
    '''
    Verify iptables outbound and estabblish rules
    '''
    _id = 'os_firewall_outbound_and_establish_rules'
    configs = []
    try:
        state = PASSED
        cmd = 'iptables -S'
        output = __salt__['cmd.run'](cmd)
        configs = output.splitlines()
        rules  = [\
                 '-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT',\
                 '-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT',\
                 '-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT',\
                 '-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT',\
                 '-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT',\
                 '-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT',\
                 ]
        if not set(rules).issubset(output.splitlines()):
            state = FAILED
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify iptables logs write rules: %s' % exp )

    return {'id': _id , 'state' : state, 'configs': configs}
def _audit_4_7():
    
    '''
    Verify iptables open port rules
    '''
    _id = 'os_firewall_open_port_rules_check'
    configs = []
    try:
        state = PASSED
        cmd = 'netstat -plunt'
        output = __salt__['cmd.run'](cmd)
        open_ports = [line.split()[3].split(':')[-1] for line in output.splitlines() if ':' in line.split()[3]] 
        configs.append({'open_ports': open_ports})
        cmd = 'iptables -S'
        output = __salt__['cmd.run'](cmd)
        all_port_rules = [line for line in output.splitlines() if '--dport' in line]
        configs.append({'all_rules': all_port_rules})
        for port in open_ports:
            for rules in all_rules:
                if port not in rules:
                    state = FAILED
                    break
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify iptables logs write rules: %s' % exp )

    return {'id': _id , 'state' : state, 'configs': configs}
def audit_4_8():
    
    '''
    Verify iptables wireless rules
    '''
    _id = 'os_firewall_wireless_rules_check'
    configs = []
    try:
        state = PASSED
        cmd = 'iwconfig'
        output = __salt__['cmd.run'](cmd)
        for line in output.splitlines():
            if 'command not found' in line:
                state = FAILED
                configs.append('No wireless interface')
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify iptables logs write rules: %s' % exp )

    return {'id': _id , 'state' : state, 'configs': configs}

def _audit_5_1():
    '''
    Verify special purpose services.
    '''
    _id = 'os_special_purpose_services'
    configs = []
    try:
        state = PASSED
        temp = [
            _rpmquery('telnet'),
            _rpmquery('telnet-server'),
            _rpmquery('rsh'),
            _rpmquery('rsh-server'),
            _rpmquery('ypbind'),
            _rpmquery('ypserv'),
            _rpmquery('tftp'),
            _rpmquery('tftp-server')
        ]
        for config in temp:
            match = re.search('(not installed)', config, re.IGNORECASE)
            if not match:
                state = FAILED
            configs.append(config.strip(' \t\n\r'))
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify special purpose services: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _audit_6_2():
    '''
    Verify SSH Protocol is set to 2.
    '''
    _id = 'os_ssh_protocol_version'
    configs = []
    try:
        state = PASSED
        config = _grep('"^Protocol"', '/etc/ssh/sshd_config')
        if config:
            match = re.search('(Protocol\s+2)', config, re.IGNORECASE)
            if not match:
                state = FAILED
        else:
            state = FAILED
            config = 'Protocol ???'
        configs.append('[/etc/ssh/sshd_config] {0}'.format(config))
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify SSH Protocol is set to 2: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _audit_6_3():
    '''
    Verify SSH access is limited.
    '''
    _id = 'os_ssh_access_is_limited'
    configs = []
    try:
        state = PASSED
        # Allow users
        config = _grep('"^AllowUsers"', '/etc/ssh/sshd_config')
        if config:
            match = re.search('(AllowUsers\s+.+)', config, re.IGNORECASE)
            if not match:
                state = FAILED
        else:
            state = FAILED
            config = 'AllowUsers ???'
        configs.append('[/etc/ssh/sshd_config] {0}'.format(config))

        # Allow groups
        config = _grep('"^AllowGroups"', '/etc/ssh/sshd_config')
        if config:
            match = re.search('(AllowGroups\s+.+)', config, re.IGNORECASE)
            if not match:
                state = FAILED
        else:
            state = FAILED
            config = 'AllowGroups ???'
        configs.append('[/etc/ssh/sshd_config] {0}'.format(config))
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify SSH access is limited: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _audit_6_4():
    '''
    Verify SSH Idle Timeout Interval is configured.
    '''
    _id = 'os_ssh_idle_timeout_interval'
    configs = []
    try:
        state = PASSED
        # Verify ClientAliveInterval is 300 or less
        config = _grep('"^ClientAliveInterval"', '/etc/ssh/sshd_config')
        if config:
            match = re.search('(ClientAliveInterval\s+\d+)', config, re.IGNORECASE)
            if match:
                config = match.group(1)
                client_alive_interval = int(config.split()[-1])
                if client_alive_interval > 300:
                    state = FAILED
            else:
                state = FAILED
        else:
            config = 'ClientAliveInterval ???'
        configs.append('[/etc/ssh/sshd_config] {0}'.format(config))

        # Verify ClientAliveCountMax is 3 or less
        config = _grep('"^ClientAliveCountMax"', '/etc/ssh/sshd_config')
        if config:
            match = re.search('(ClientAliveCountMax\s+\d+)', config, re.IGNORECASE)
            if match:
                config = match.group(1)
                client_alive_count_max = int(config.split()[-1])
                if client_alive_count_max > 3:
                    state = FAILED
            else:
                state = FAILED
        else:
            config = 'ClientAliveCountMax ???'
        configs.append('[/etc/ssh/sshd_config] {0}'.format(config))
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify SSH Idle Timeout Interval is configured: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _audit_6_5():
    '''
    Verify SSH root login is disabled.
    '''
    _id = 'os_ssh_root_login_is_disabled'
    configs = []
    try:
        state = PASSED
        config = _grep('"^PermitRootLogin"', '/etc/ssh/sshd_config')
        if config:
            match = re.search('(PermitRootLogin\s+no)', config, re.IGNORECASE)
            if not match:
                state = FAILED
        else:
            state = FAILED
            config = 'PermitRootLogin ???'
        configs.append('[/etc/ssh/sshd_config] {0}'.format(config))
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify SSH root login is disabled: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _audit_8_1():
    '''
    Verify time synchronization.
    '''
    _id = 'os_time_synchronization'
    configs = []
    try:
        state = PASSED
        # Verify time synchronization is in use
        config = _rpmquery('ntp')
        configs.append(config.strip(' \t\n\r'))
        match = re.search('(not installed)', config, re.IGNORECASE)
        if match:
            state = FAILED
        else:
            # Verify ntp is configured
            config = _grep('"^server"', '/etc/ntp.conf')
            if config:
                configs.extend(['[/etc/ntp.conf] {0}'.format(item.strip(' \t\n\r')) for item in config.split('\n')])
            else:
                state = FAILED
                configs.append('[/etc/ntp.conf] server ???')
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify time synchronization: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}
def audit_7_1():
    """
    Verify path variables
    """
    _id = 'path_variables_check'
    configs = []
    try:
        state = PASSED
        failed_paths=[]
        cmd = 'echo $PATH | tr ":" "\n"'
        output = __salt__['cmd.run'](cmd, python_shell = True)
        for path in output.splitlines():
            configs.append(path)
            if path == "":
                failed_paths.append(path)
        if len(failed_paths) > 0:
            state = FAILED
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify path variales : %s' % exp)
    return {'id': _id , 'state' : state, 'configs': configs}
def _audit_7_2():
    '''
        Verify path variables folder permission
    '''
    _id = 'path_variables_folder_permission'
    configs = []
    try:
        state = PASSED
        failed_folders = []
        cmd = 'for i in `echo $PATH | tr ":" " "`;do ls -ld "$i"; done;'  
        rules = __salt__['cmd.run'](cmd, python_shell = True)
        for line in rules.splitlines():
    	    configs.append(line)
            folder_permission = line.split()[0]
            matchObj = re.match(r'^.{5}(.{1}).{2}(.{1}).*$', folder_permission) 
            if matchObj.group(1) != '-' or matchObj.group(2) != '-':
                failed_folders.append(line)
        if len(failed_folders) > 0:
            state = FAILED
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify path variables: %s' % exp )

    return {'id': _id , 'state' : state, 'configs': configs}

def _audit_9_1():
    '''
    Verify cron configs.
    '''
    _id = 'os_cron_config'
    configs = []
    try:
        state = PASSED
        # Verify /etc/cron.deny and /etc/at.deny do not exist
        files = {
            '/etc/cron.deny': _stat('/etc/cron.deny'),
            '/etc/at.deny': _stat('/etc/at.deny')
        }
        for file_name, config in files.items():
            match = re.search('(cannot stat)', config, re.IGNORECASE)
            if not match:
                state = FAILED
                config = 'File {0}: Exist'.format(file_name)
            else:
                config = 'File {0}: No such file or directory'.format(file_name)
            configs.append(config)

        # Verify Uid and Gid are both 0/root and Access does not
        # grant permissions to group or other for
        # /etc/cron.allow,
        # /etc/at.allow
        # /etc/crontab
        # /etc/cron.hourly
        # /etc/cron.daily
        # /etc/cron.weekly
        # /etc/cron.monthly
        # /etc/cron.d
        files = {
            '/etc/cron.allow': _stat('/etc/cron.allow'),
            '/etc/at.allow': _stat('/etc/at.allow'),
            '/etc/crontab': _stat('/etc/crontab'),
            '/etc/cron.hourly': _stat('/etc/cron.hourly'),
            '/etc/cron.daily': _stat('/etc/cron.daily'),
            '/etc/cron.weekly': _stat('/etc/cron.weekly'),
            '/etc/cron.monthly': _stat('/etc/cron.monthly'),
            '/etc/cron.d': _stat('/etc/cron.d')
        }
        pattern = '(Access:\s+\(0600\/[-]*rw[-]*\)\s+Uid:\s+\(\s+0\/\s+root\)\s+Gid:\s+\(\s+0\/\s+root\))'
        for file_name, config in files.items():
            match = re.search('(cannot stat)', config, re.IGNORECASE)
            if match:
                state = FAILED
                config = 'File {0}: No such file or directory'.format(file_name)
            else:
                match = re.search(pattern, config, re.IGNORECASE)
                if not match:
                    state = FAILED
                permissions = re.search('(Access:.+\n)', config, re.IGNORECASE).group(1)
                config = 'File {0}\n{1}'.format(file_name, permissions)
            configs.append(config.strip(' \t\n\r'))
    except Exception as exp:
        state = FAILED
        log.error('Error - Verify cron configs: %s' % exp)

    return {'id': _id, 'state': state, 'configs': configs}


def _verify_pwd_reuse(ret):
    state = PASSED
    match = re.search('(remember=\d*)', ret)
    if match:
        config = match.group(1)
        remember = int(config.split('=')[-1])
        if remember < 5:
            state = FAILED
    else:
        state = FAILED
        config = 'remember=???'
    return state, config


def _grep(pattern, filename, shell=False):
    cmd = '{0} {1} {2}'.format(GREP, pattern, filename)
    return __salt__['cmd.run'](cmd, python_shell=shell)


def _chage(pattern, shell=False):
    cmd = '{0} {1}'.format(CHAGE, pattern)
    return __salt__['cmd.run'](cmd, python_shell=shell)


def _rpmquery(package):
    cmd = '{0} {1} {2}'.format(RPMQUERY, '-q', package)
    return __salt__['cmd.run'](cmd, python_shell=False)


def _stat(filename):
    '''
    Standard function for all ``stat`` commands.
    '''
    cmd = '{0} {1}'.format(STAT, filename)
    return __salt__['cmd.run'](cmd, python_shell=False)


def _chkconfig(service):
    if 'systemctl' in CHKCONFIG:
        cmd = '{0} {1} {2}'.format(CHKCONFIG, 'is-enabled', service)
    else:
        cmd = '{0} {1} {2}'.format(CHKCONFIG, '--list', service)
    return __salt__['cmd.run'](cmd, python_shell=False)
