Ansible Playbook - Wazuh agent
==============================

This role will install and configure a Wazuh Agent.

OS Requirements
----------------

This role is compatible with:
 * Red Hat
 * CentOS
 * Fedora
 * Debian
 * Ubuntu
 * Windows
 * macOS


Role Variables
--------------

* `wazuh_managers`: Collection of Wazuh Managers' IP address, port, and protocol used by the agent
* `wazuh_agent_authd`: Collection with the settings to register an agent using authd.
* `wazuh_agent_docker`: Monitor docker


Playbook example
----------------

The following is an example of how this role can be used:

```
     - hosts: all:!wazuh-manager
       roles:
         - ansible-wazuh-agent
       vars:
        wazuh_managers:
          - address: manager-host
            port: 1514
            protocol: tcp
            api_port: 55000
            api_proto: 'http'
            api_user: 'ansible'

        authd_pass: SuperSecure

        wazuh_dir: "/var/ossec"

        wazuh_agent_enrollment:
          enabled: 'yes'
          manager_address: 'manager-host'
          port: 1515
          groups: 'defult'
          authorization_pass_path: "{{ wazuh_dir }}/etc/authd.pass"
          auto_method: 'no'
          delay_after_enrollment: 20
          use_source_ip: 'no'

        wazuh_agent_config:
          syscheck:
            directories:
              - checks: 'whodata="yes"'
                dirs: /home/*/.ssh/authorized_keys
              - checks: 'check_all="yes" report_changes="yes" whodata="yes"'
                dirs: /etc
              - dirs: /bin,/sbin,/boot
                checks: ''
              - dirs: /usr/bin,/usr/sbin
                checks: ''

        ## Log collectors
        wazuh_agent_localfiles:
          debian:
            - format: 'syslog'
              location: '/var/log/auth.log'
            - format: 'syslog'
              location: '/var/log/syslog'
            - format: 'syslog'
              location: '/var/log/dpkg.log'
            - format: 'syslog'
              location: '/var/log/kern.log'
          centos:
            - format: 'syslog'
              location: '/var/log/messages'
            - format: 'syslog'
              location: '/var/log/secure'
            - format: 'syslog'
              location: '/var/log/maillog'
            - format: 'audit'
              location: '/var/log/audit/audit.log'
          linux:
            - format: 'syslog'
              location: "{{ wazuh_dir }}/logs/active-responses.log"
            - format: 'full_command'
              command: 'last -n 20'
              frequency: '360'
            - format: 'command'
              command: df -P
              frequency: '360'
            - format: 'full_command'
              command: netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d
              alias: 'netstat listening ports'
              frequency: '360'
```

License and copyright
---------------------

WAZUH Copyright (C) 2016, Wazuh Inc. (License GPLv3)

### Based on previous work from dj-wasabi

  - https://github.com/dj-wasabi/ansible-ossec-server

### Modified by Wazuh

The playbooks have been modified by Wazuh, including some specific requirements, templates and configuration to improve integration with Wazuh ecosystem.
