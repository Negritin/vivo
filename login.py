from netmiko import Netmiko
from netmiko import NetmikoTimeoutException, ReadTimeout  # netmiko 4.1.2
# from netmiko.ssh_exception import NetmikoTimeoutException  # netmiko 3.4.0
from netvivo import REGEX_PROMPT, REGEX_HOSTNAME
from time import sleep
from pathlib import Path

import netvivo.lib.Format as Format
import logging
import re
import socket

logger = logging.getLogger('login')


class Login:

    @staticmethod
    def jump_server(username=None, password=None, server=None, port=22, read_timeout=300, banner_timeout=100,
                 blocking_timeout=200):

        conn = None

        try:
            jump_server = {
                'device_type': 'terminal_server',
                'ip': server,
                'username': username,
                'password': password,
                'port': port,
                'default_enter': '\r',
                'global_delay_factor': 0.5,
                'read_timeout_override': read_timeout,
                'banner_timeout': banner_timeout,
                'blocking_timeout': blocking_timeout
            }
            conn = Netmiko(**jump_server)
        except OSError:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'jump_server', 'Jump Server kill the session'))
        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'jump_server', e))
        finally:
            return conn

    @staticmethod
    def jump_server_logout(conn) -> None:
        try:
            conn.disconnect()
        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'jump_server_logout', e))

    @staticmethod
    def reconect_jump_server(conn, server, username, password) -> dict:

        Login.force_logout(conn)

        login = Login.eqp_login_from_linux(conn, server, username, password, None, True)

        return login

    @staticmethod
    def eqp_login_from_linux(conn, hostname_ip, username, password, ssh=False, local_users=None) -> dict:

        """
            0  - Não acessou o equipamento, porém com conectividade
            -1 - Sem conectividade
            -2 - Problema DNS/hosts
            -3 - Acessou, sem acesso visualização
            -4 - Acessou, senha enable inválida
            -5 - Não Acessou, senha tacacs/local inválida(s)
            -6 - Não identificou o equipamento
            -7 - Erro
        """

        output = ''
        ssh_conn = None
        telnet_conn = None
        hostname = None
        ios = None
        protocol = None
        access = None

        enable_password = None
        local_password = None

        ret = {"hostname": hostname, "ios": ios, "status": 0, "protocol": protocol, "access": access,
               "local_password": local_password, "output": ''}

        try:

            def _ssh(prompt) -> bool:
                nonlocal access, output, ret, enable_password, local_password
                host_key = None
                key = ''
                output += prompt + 'ssh ' + username + '@' + hostname_ip + '\n'
                try:
                    login = conn.send_command('ssh ' + username + '@' + hostname_ip,
                                              expect_string=r'yes/no|assword:|Type ENTER to run|' + REGEX_PROMPT,
                                              strip_prompt=False, cmd_verify=False)
                except NetmikoTimeoutException:
                    conn.write_channel('\x03')
                    login = conn.read_until_pattern(REGEX_PROMPT)
                    output += login + '\n'
                    return False
                output += login + '\n'

                if re.search(r'(ssh-keygen -f .*)', login, re.IGNORECASE):
                    cmd = re.findall(r'(ssh-keygen -f .*)', login, re.IGNORECASE)[0]
                    output += cmd + '\n'
                    login = conn.send_command(cmd, expect_string=REGEX_PROMPT, strip_prompt=False)
                    output += login + '\n'

                    output += 'ssh ' + username + '@' + hostname_ip + '\n'
                    login = conn.send_command('ssh ' + username + '@' + hostname_ip,
                                              expect_string=r'yes/no|assword:|Type ENTER to run|' + REGEX_PROMPT,
                                              strip_prompt=False, cmd_verify=False)
                    output += login + '\n'

                if re.search(r'no matching (?:key exchange method|host key type) found', login, re.IGNORECASE):
                    sleep(1)
                    key = login.split('Their offer: ')[1].split('\n')[0].replace('\n', '')
                    output += 'ssh -oKexAlgorithms=+' + key + ' ' + username + '@' + hostname_ip + '\n'
                    login = conn.send_command('ssh -oKexAlgorithms=+' + key + ' ' + username + '@' + hostname_ip,
                                              expect_string=r'yes/no|assword:|Type ENTER to run|' + REGEX_PROMPT,
                                              strip_prompt=False, cmd_verify=False)
                    output += login + '\n'
                    if re.search(r'(ssh-keygen -f .*)', login, re.IGNORECASE):
                        cmd = re.findall(r'(ssh-keygen -f .*)', login, re.IGNORECASE)[0]
                        output += cmd + '\n'
                        login = conn.send_command(cmd, expect_string=REGEX_PROMPT, strip_prompt=False)
                        output += login + '\n'

                        output += 'ssh -oKexAlgorithms=+' + key + ' ' + username + '@' + hostname_ip + '\n'
                        login = conn.send_command('ssh -oKexAlgorithms=+' + key + ' ' + username + '@' + hostname_ip,
                                                  expect_string=r'yes/no|assword:|Type ENTER to run|' + REGEX_PROMPT,
                                                  strip_prompt=False, cmd_verify=False)
                        output += login + '\n'

                    if re.search(r'no matching host key type found.', login, re.IGNORECASE):
                        host_key = login.split('Their offer: ')[1].split('\n')[0].replace('\n', '')
                        output += 'ssh -oKexAlgorithms=+' + key + ' -oHostKeyAlgorithms=+' \
                                  + host_key + ' ' + username + '@' + hostname_ip + '\n'
                        login = conn.send_command('ssh -oKexAlgorithms=+' + key + ' -oHostKeyAlgorithms=+'
                                                  + host_key + ' ' + username + '@' + hostname_ip,
                                                  expect_string=r'yes/no|assword:|Type ENTER to run|' + REGEX_PROMPT,
                                                  strip_prompt=False, cmd_verify=False)
                        output += login + '\n'
                        if 'Connection closed' in login:
                            host_key = 'ssh-rsa'
                            output += 'ssh -oKexAlgorithms=+' + key + ' -oHostKeyAlgorithms=+' \
                                    + host_key + ' ' + username + '@' + hostname_ip + '\n'
                            login = conn.send_command('ssh -oKexAlgorithms=+' + key + ' -oHostKeyAlgorithms=+'
                                                    + host_key + ' ' + username + '@' + hostname_ip,
                                                    expect_string=r'yes/no|assword:|Type ENTER to run|' + REGEX_PROMPT,
                                                    strip_prompt=False)
                        output += login + '\n'

                    if re.search(r'Unsupported KEX algorithm', login, re.IGNORECASE):
                        output += 'ssh -oHostKeyAlgorithms=+' + key + ' ' + username + '@' + hostname_ip + '\n'
                        login = conn.send_command('ssh -oHostKeyAlgorithms=+' + key + ' ' + username + '@'
                                                  + hostname_ip,
                                                  expect_string=r'yes/no|assword:|Type ENTER to run|' + REGEX_PROMPT,
                                                  strip_prompt=False, cmd_verify=False)
                        output += login + '\n'

                    if re.search(r'yes/no', login, re.IGNORECASE):
                        login = conn.send_command('yes', expect_string=r'assword:|Type ENTER to run',
                                                  strip_prompt=False)
                        output += login + '\n'

                    if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                        conn.write_channel('\r')
                        sleep(.5)
                        login = conn.read_until_pattern('Configure Router')
                        output += login + '\n'

                        conn.write_channel('2')
                        sleep(.5)
                        login = conn.read_until_pattern(REGEX_PROMPT)
                        output += login + '\n'

                        access = 'local'
                        return True

                    elif re.search(r'assword:', login, re.IGNORECASE):
                        login = conn.send_command(password, expect_string=r'assword:|Datablink token:|ESCOLHA UMA OP|'
                                                                          + REGEX_PROMPT,
                                                  strip_prompt=False,
                                                  cmd_verify=False)
                        # output += login + '\n'
                        if re.search(r'Datablink token:', login, re.IGNORECASE):
                            token = input("Datablink token:")
                            login = conn.send_command(token, expect_string=r'assword:|' + REGEX_PROMPT,
                                                      strip_prompt=False,
                                                      cmd_verify=False)
                            output += login + '\n'
                        if re.search(r'assword:', login, re.IGNORECASE) and local_users:

                            for data in local_users:
                                local_password = [data]
                                enable_password = data.get('enable')

                                conn.write_channel('\x03')
                                conn.read_until_pattern(REGEX_PROMPT)

                                sleep(1)

                                login = conn.send_command('ssh -oKexAlgorithms=+' + key + ' ' + data.get('usr') + '@'
                                                          + hostname_ip,
                                                          expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                        + REGEX_PROMPT,
                                                          strip_prompt=False, cmd_verify=False)
                                output += login + '\n'
                                if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                                    conn.write_channel('\r')
                                    sleep(.5)
                                    login = conn.read_until_pattern('Configure Router')
                                    output += login + '\n'

                                    conn.write_channel('2')
                                    sleep(.5)
                                    login = conn.read_until_pattern(REGEX_PROMPT)
                                    output += login + '\n'

                                    access = 'local'
                                    return True
                                elif re.search(r'assword:', login, re.IGNORECASE):
                                    login = conn.send_command(data.get('pwd'),
                                                              expect_string=r'assword:|ESCOLHA UMA OP|' + REGEX_PROMPT,
                                                              strip_prompt=False,
                                                              cmd_verify=False)
                                    if re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                                        conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False,
                                                          cmd_verify=False)
                                        access = 'local'
                                        return True
                                    elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                                        access = 'local'
                                        return True
                                    else:
                                        continue
                                else:
                                    continue
                            conn.write_channel('\x03')
                            conn.read_until_pattern(REGEX_PROMPT)
                            ret['status'] = -5
                            return False

                        elif re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                            conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False,
                                              cmd_verify=False)
                            access = 'tacacs'
                            return True
                        elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                            access = 'tacacs'
                            return True
                        elif re.search(r'assword:', login, re.IGNORECASE):
                            conn.write_channel('\x03')
                            conn.read_until_pattern(REGEX_PROMPT)
                            ret['status'] = -5
                            return False
                    elif re.search(r'ssh_dispatch_run_fatal', login, re.IGNORECASE):

                        output += 'ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 ' \
                                  + username + '@' + hostname_ip + '\n'
                        login = conn.send_command('ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 '
                                                  + username + '@' + hostname_ip,
                                                  expect_string=r'yes/no|assword:|Type ENTER to run|' + REGEX_PROMPT,
                                                  strip_prompt=False, cmd_verify=False)
                        output += login + '\n'
                        if re.search(r'no matching host key type found.', login, re.IGNORECASE):
                            host_key = login.split('Their offer: ')[1].split('\n')[0].replace('\n', '')
                            output += 'ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+' \
                                      + host_key + ' ' + username + '@' + hostname_ip + '\n'
                            login = conn.send_command('ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 '
                                                      '-oHostKeyAlgorithms=+' + host_key + ' '
                                                      + username + '@' + hostname_ip,
                                                      expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                    + REGEX_PROMPT,
                                                      strip_prompt=False, cmd_verify=False)
                            output += login + '\n'

                        if re.search(r'(ssh-keygen -f .*)', login, re.IGNORECASE):
                            cmd = re.findall(r'(ssh-keygen -f .*)', login, re.IGNORECASE)[0]
                            output += cmd + '\n'
                            login = conn.send_command(cmd, expect_string=REGEX_PROMPT, strip_prompt=False)
                            output += login + '\n'

                            output += 'ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 ' \
                                      + username + '@' + hostname_ip + '\n'
                            login = conn.send_command('ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 '
                                                      + username + '@' + hostname_ip,
                                                      expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                    + REGEX_PROMPT,
                                                      strip_prompt=False, cmd_verify=False)
                            output += login + '\n'
                        if re.search(r'Add correct host key', login, re.IGNORECASE):
                            output += 'ssh-keygen -R ' + hostname_ip + '\n'
                            login = conn.send_command('ssh-keygen -R ' + hostname_ip, expect_string=REGEX_PROMPT,
                                                      strip_prompt=False)
                            output += login + '\n'

                            output += 'ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 ' \
                                      + username + '@' + hostname_ip + '\n'
                            login = conn.send_command('ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 '
                                                      + username + '@' + hostname_ip,
                                                      expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                    + REGEX_PROMPT,
                                                      strip_prompt=False, cmd_verify=False)
                            output += login + '\n'
                        if re.search(r'yes/no', login, re.IGNORECASE):
                            login = conn.send_command('yes', expect_string=r'assword:|Type ENTER to run',
                                                      strip_prompt=False)
                            output += login + '\n'
                        login = conn.send_command(password, expect_string=r'assword:|Datablink token:|ESCOLHA UMA OP|'
                                                                          + REGEX_PROMPT,
                                                  strip_prompt=False,
                                                  cmd_verify=False)
                        # output += login + '\n'
                        if re.search(r'Datablink token:', login, re.IGNORECASE):
                            token = input("Datablink token:")
                            login = conn.send_command(token, expect_string=r'assword:|' + REGEX_PROMPT,
                                                      strip_prompt=False,
                                                      cmd_verify=False)
                            output += login + '\n'
                        if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                            conn.write_channel('\r')
                            sleep(.5)
                            login = conn.read_until_pattern('Configure Router')
                            output += login + '\n'

                            conn.write_channel('2')
                            sleep(.5)
                            login = conn.read_until_pattern(REGEX_PROMPT)
                            output += login + '\n'

                            access = 'local'
                            return True
                        elif re.search(r'assword:', login, re.IGNORECASE) and local_users:

                            for data in local_users:
                                local_password = [data]
                                enable_password = data.get('enable')

                                conn.write_channel('\x03')
                                conn.read_until_pattern(REGEX_PROMPT)

                                sleep(1)

                                output += 'ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 ' + data.get('usr') \
                                          + '@' + hostname_ip + '\n'
                                login = conn.send_command('ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 '
                                                          + data.get('usr') + '@' + hostname_ip,
                                                          expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                        + REGEX_PROMPT,
                                                          strip_prompt=False, cmd_verify=False)
                                output += login + '\n'
                                if re.search(r'no matching host key type found.', login, re.IGNORECASE):
                                    host_key = login.split('Their offer: ')[1].split('\n')[0].replace('\n', '')
                                    output += 'ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+' \
                                              + host_key + ' ' + data.get('usr') + '@' + hostname_ip + '\n'
                                    login = conn.send_command('ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 '
                                                              '-oHostKeyAlgorithms=+' + host_key + ' '
                                                              + data.get('usr') + '@' + hostname_ip,
                                                              expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                            + REGEX_PROMPT,
                                                              strip_prompt=False, cmd_verify=False)
                                    output += login + '\n'
                                if re.search(r'yes/no', login, re.IGNORECASE):
                                    login = conn.send_command('yes', expect_string=r'assword:|Type ENTER to run',
                                                              strip_prompt=False)
                                    output += login + '\n'
                                if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                                    conn.write_channel('\r')
                                    sleep(.5)
                                    login = conn.read_until_pattern('Configure Router')
                                    output += login + '\n'

                                    conn.write_channel('2')
                                    sleep(.5)
                                    login = conn.read_until_pattern(REGEX_PROMPT)
                                    output += login + '\n'

                                    access = 'local'
                                    return True
                                elif re.search(r'assword:', login, re.IGNORECASE):
                                    login = conn.send_command(data.get('pwd'),
                                                              expect_string=r'assword:|ESCOLHA UMA OP|' + REGEX_PROMPT,
                                                              strip_prompt=False,
                                                              cmd_verify=False)
                                    if re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                                        conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False,
                                                          cmd_verify=False)
                                        access = 'local'
                                        return True
                                    elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                                        access = 'local'
                                        return True
                                    else:
                                        continue
                                else:
                                    continue
                            conn.write_channel('\x03')
                            conn.read_until_pattern(REGEX_PROMPT)
                            ret['status'] = -5
                            return False
                        elif re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                            conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False,
                                              cmd_verify=False)
                            access = 'tacacs'
                            return True
                        elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                            access = 'tacacs'
                            return True
                        elif re.search(r'assword:', login, re.IGNORECASE):
                            conn.write_channel('\x03')
                            conn.read_until_pattern(REGEX_PROMPT)
                            ret['status'] = -5
                            return False

                    if re.search(r'no matching cipher found', login, re.IGNORECASE):
                        sleep(1)
                        cipher = login.split('Their offer: ')[1].split('\n')[0].replace('\n', '')

                        if host_key is None:
                            ssh_cmd = 'ssh -oKexAlgorithms=+' + key + \
                                      ' -c ' + cipher.split(',')[0] + ' ' + username + '@' + hostname_ip + '\n'
                        else:
                            ssh_cmd = 'ssh -oKexAlgorithms=+' + key + ' -oHostKeyAlgorithms=+' + host_key + ' -c ' + cipher.split(',')[0] + ' ' \
                                      + username + '@' + hostname_ip + '\n'

                        output += ssh_cmd + '\n'
                        login = conn.send_command(ssh_cmd, expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                         + REGEX_PROMPT,
                                                  strip_prompt=False, cmd_verify=False)
                        output += login + '\n'

                        if 'Connection closed' in login and host_key:
                            host_key = 'ssh-rsa'
                            ssh_cmd = 'ssh -oKexAlgorithms=+' + key + ' -oHostKeyAlgorithms=+' + host_key + ' -c ' + cipher.split(',')[0] + ' ' \
                                      + username + '@' + hostname_ip + '\n'
                            login = conn.send_command(ssh_cmd, expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                         + REGEX_PROMPT,
                                                  strip_prompt=False)
                        output += login + '\n'
                        if re.search(r'(ssh-keygen -f .*)', login, re.IGNORECASE):
                            cmd = re.findall(r'(ssh-keygen -f .*)', login, re.IGNORECASE)[0]
                            output += cmd + '\n'
                            login = conn.send_command(cmd, expect_string=REGEX_PROMPT, strip_prompt=False)
                            output += login + '\n'

                            output += ssh_cmd + '\n'
                            login = conn.send_command(ssh_cmd,
                                                      expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                    + REGEX_PROMPT,
                                                      strip_prompt=False, cmd_verify=False)
                            output += login + '\n'
                        if re.search(r'ssh_dispatch_run_fatal', login, re.IGNORECASE):
                            conn.read_until_pattern(r'\$ ?$')
                            output += 'ssh -oKexAlgorithms=diffie-hellman-group1-sha1 -c ' + cipher.split(',')[0] \
                                      + ' ' + username + '@' + hostname_ip + '\n'
                            login = conn.send_command('ssh -oKexAlgorithms=diffie-hellman-group1-sha1 -c '
                                                      + cipher.split(',')[0] + ' ' + username + '@' + hostname_ip,
                                                      expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                    + REGEX_PROMPT,
                                                      strip_prompt=False, cmd_verify=False)
                            output += login + '\n'
                            if re.search(r'(ssh-keygen -f .*)', login, re.IGNORECASE):
                                cmd = re.findall(r'(ssh-keygen -f .*)', login, re.IGNORECASE)[0]
                                output += cmd + '\n'
                                login = conn.send_command(cmd, expect_string=REGEX_PROMPT, strip_prompt=False)
                                output += login + '\n'

                                output += 'ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -c ' + cipher.split(',')[0] \
                                          + ' ' + username + '@' + hostname_ip + '\n'
                                login = conn.send_command('ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -c '
                                                          + cipher.split(',')[0] + ' ' + username + '@' + hostname_ip,
                                                          expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                        + REGEX_PROMPT,
                                                          strip_prompt=False, cmd_verify=False)
                                output += login + '\n'

                            if re.search(r'Add correct host key', login, re.IGNORECASE):
                                output += 'ssh-keygen -R ' + hostname_ip + '\n'
                                login = conn.send_command('ssh-keygen -R ' + hostname_ip, expect_string=REGEX_PROMPT,
                                                          strip_prompt=False)
                                output += login + '\n'

                                login = conn.send_command('ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -c '
                                                          + cipher.split(',')[0] + ' ' + username + '@' + hostname_ip,
                                                          expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                        + REGEX_PROMPT,
                                                          strip_prompt=False, cmd_verify=False)
                                output += login + '\n'

                            if re.search(r'yes/no', login, re.IGNORECASE):
                                login = conn.send_command('yes', expect_string=r'assword:|Type ENTER to run',
                                                          strip_prompt=False)
                                output += login + '\n'
                            if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                                conn.write_channel('\r')
                                sleep(.5)
                                login = conn.read_until_pattern('Configure Router')
                                output += login + '\n'

                                conn.write_channel('2')
                                sleep(.5)
                                login = conn.read_until_pattern(REGEX_PROMPT)
                                output += login + '\n'

                                access = 'local'
                                return True
                            elif re.search(r'assword:', login, re.IGNORECASE):
                                login = conn.send_command(password,
                                                          expect_string=r'assword:|Datablink token:|ESCOLHA UMA OP|'
                                                                        + REGEX_PROMPT,
                                                          strip_prompt=False,
                                                          cmd_verify=False)
                                # output += login + '\n'
                                if re.search(r'Datablink token:', login, re.IGNORECASE):
                                    token = input("Datablink token:")
                                    login = conn.send_command(token, expect_string=r'assword:|' + REGEX_PROMPT,
                                                              strip_prompt=False,
                                                              cmd_verify=False)
                                    output += login + '\n'
                                if re.search(r'assword:', login, re.IGNORECASE) and local_users:

                                    for data in local_users:
                                        local_password = [data]
                                        enable_password = data.get('enable')

                                        conn.write_channel('\x03')
                                        conn.read_until_pattern(REGEX_PROMPT)

                                        sleep(1)

                                        output += 'ssh -oKexAlgorithms=diffie-hellman-group1-sha1 -c ' \
                                                  + cipher.split(',')[0] + ' ' + data.get('usr') + '@' \
                                                  + hostname_ip + '\n'
                                        login = conn.send_command('ssh -oKexAlgorithms=diffie-hellman-group1-sha1 -c '
                                                                  + cipher.split(',')[0] + ' ' + data.get('usr') + '@'
                                                                  + hostname_ip,
                                                                  expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                                + REGEX_PROMPT,
                                                                  strip_prompt=False, cmd_verify=False)

                                        if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                                            conn.write_channel('\r')
                                            sleep(.5)
                                            login = conn.read_until_pattern('Configure Router')
                                            output += login + '\n'

                                            conn.write_channel('2')
                                            sleep(.5)
                                            login = conn.read_until_pattern(REGEX_PROMPT)
                                            output += login + '\n'

                                            access = 'local'
                                            return True
                                        elif re.search(r'assword:', login, re.IGNORECASE):
                                            login = conn.send_command(data.get('pwd'),
                                                                      expect_string=r'assword:|ESCOLHA UMA OP|'
                                                                                    r'' + REGEX_PROMPT,
                                                                      strip_prompt=False,
                                                                      cmd_verify=False)
                                            if re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                                                conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False,
                                                                  cmd_verify=False)
                                                access = 'local'
                                                return True
                                            elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                                                access = 'local'
                                                return True
                                            else:
                                                continue
                                        else:
                                            continue
                                    conn.write_channel('\x03')
                                    conn.read_until_pattern(REGEX_PROMPT)
                                    ret['status'] = -5
                                    return False
                                elif re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                                    conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False,
                                                      cmd_verify=False)
                                    access = 'tacacs'
                                    return True
                                elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                                    access = 'tacacs'
                                    return True
                                elif re.search(r'assword:', login, re.IGNORECASE):
                                    conn.write_channel('\x03')
                                    conn.read_until_pattern(REGEX_PROMPT)
                                    ret['status'] = -5
                                    return False
                        else:

                            if re.search(r'yes/no', login, re.IGNORECASE):
                                login = conn.send_command('yes', expect_string=r'assword:|Type ENTER to run',
                                                          strip_prompt=False)
                                output += login + '\n'
                            if re.search(r'Type ENTER to run', login, re.IGNORECASE):

                                conn.write_channel('\r')
                                sleep(.5)
                                login = conn.read_until_pattern('Configure Router')
                                output += login + '\n'

                                conn.write_channel('2')
                                sleep(.5)
                                login = conn.read_until_pattern(REGEX_PROMPT)
                                output += login + '\n'

                                access = 'local'
                                return True
                            elif re.search(r'assword:', login, re.IGNORECASE):
                                login = conn.send_command(password,
                                                          expect_string=r'assword:|Datablink token:|ESCOLHA UMA OP|'
                                                                        + REGEX_PROMPT,
                                                          strip_prompt=False,
                                                          cmd_verify=False)
                                # output += login + '\n'
                                if re.search(r'Datablink token:', login, re.IGNORECASE):
                                    token = input("Datablink token:")
                                    login = conn.send_command(token, expect_string=r'assword:|' + REGEX_PROMPT,
                                                              strip_prompt=False,
                                                              cmd_verify=False)
                                    output += login + '\n'
                                if re.search(r'assword:', login, re.IGNORECASE) and local_users:

                                    for data in local_users:
                                        local_password = [data]
                                        enable_password = data.get('enable')

                                        conn.write_channel('\x03')
                                        conn.read_until_pattern(REGEX_PROMPT)

                                        sleep(1)
                                        if host_key is None:
                                            ssh_cmd = 'ssh -oKexAlgorithms=+' + key + \
                                                    ' -c ' + cipher.split(',')[0] + ' ' + data.get('usr') + '@' + hostname_ip + '\n'
                                        else:
                                            ssh_cmd = 'ssh -oKexAlgorithms=+' + key + ' -oHostKeyAlgorithms=+' + host_key + ' -c ' + cipher.split(',')[0] + ' ' \
                                                    + data.get('usr') + '@' + hostname_ip + '\n'

                                        output += ssh_cmd + '\n'
                                        login = conn.send_command(ssh_cmd, expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                                + REGEX_PROMPT,
                                                                  strip_prompt=False, cmd_verify=False)
                                        if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                                            conn.write_channel('\r')
                                            sleep(.5)
                                            login = conn.read_until_pattern('Configure Router')
                                            output += login + '\n'

                                            conn.write_channel('2')
                                            sleep(.5)
                                            login = conn.read_until_pattern(REGEX_PROMPT)
                                            output += login + '\n'

                                            access = 'local'
                                            return True
                                        elif re.search(r'assword:', login, re.IGNORECASE):
                                            login = conn.send_command(data.get('pwd'),
                                                                      expect_string=r'assword:|ESCOLHA UMA OP|'
                                                                                    r'' + REGEX_PROMPT,
                                                                      strip_prompt=False,
                                                                      cmd_verify=False)
                                            if re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                                                conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False,
                                                                  cmd_verify=False)
                                                access = 'local'
                                                return True
                                            elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                                                access = 'local'
                                                return True
                                            else:
                                                continue
                                        else:
                                            continue
                                    conn.write_channel('\x03')
                                    conn.read_until_pattern(REGEX_PROMPT)
                                    ret['status'] = -5
                                    return False
                                elif re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                                    conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False,
                                                      cmd_verify=False)
                                    access = 'tacacs'
                                    return True
                                elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                                    access = 'tacacs'
                                    return True
                                elif re.search(r'assword:', login, re.IGNORECASE):
                                    conn.write_channel('\x03')
                                    conn.read_until_pattern(REGEX_PROMPT)
                                    ret['status'] = -5
                                    return False

                    if re.search(r'Invalid key length', login, re.IGNORECASE):
                        return False
                elif re.search(r'no matching cipher found', login, re.IGNORECASE):

                    cipher = login.split('Their offer: ')[1].split('\n')[0].replace('\n', '')
                    login = conn.send_command('ssh -c ' + cipher.split(',')[0] + ' ' + username + '@' + hostname_ip,
                                              expect_string=r'yes/no|assword:|Type ENTER to run|' + REGEX_PROMPT,
                                              strip_prompt=False, cmd_verify=False)
                    output += login + '\n'
                    if re.search(r'(ssh-keygen -f .*)', login, re.IGNORECASE):
                        cmd = re.findall(r'(ssh-keygen -f .*)', login, re.IGNORECASE)[0]
                        output += cmd + '\n'
                        login = conn.send_command(cmd, expect_string=REGEX_PROMPT, strip_prompt=False)
                        output += login + '\n'

                        output += 'ssh -c ' + cipher.split(',')[0] + ' ' + username + '@' + hostname_ip + '\n'
                        login = conn.send_command('ssh -c ' + cipher.split(',')[0] + ' ' + username + '@' + hostname_ip,
                                                  expect_string=r'yes/no|assword:|Type ENTER to run|' + REGEX_PROMPT,
                                                  strip_prompt=False, cmd_verify=False)
                        output += login + '\n'

                    if re.search(r'Add correct host key', login, re.IGNORECASE):
                        output += 'ssh-keygen -R ' + hostname_ip + '\n'
                        login = conn.send_command('ssh-keygen -R ' + hostname_ip, expect_string=REGEX_PROMPT,
                                                  strip_prompt=False)
                        output += login + '\n'

                        output += 'ssh -c ' + cipher.split(',')[0] + ' ' + username + '@' + hostname_ip + '\n'
                        login = conn.send_command('ssh -c ' + cipher.split(',')[0] + ' ' + username + '@' + hostname_ip,
                                                  expect_string=r'yes/no|assword:|Type ENTER to run|' + REGEX_PROMPT,
                                                  strip_prompt=False, cmd_verify=False)
                        output += login + '\n'
                    if re.search(r'yes/no', login, re.IGNORECASE):
                        login = conn.send_command('yes', expect_string=r'assword:|Type ENTER to run',
                                                  strip_prompt=False)
                        output += login + '\n'
                    if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                        conn.write_channel('\r')
                        sleep(.5)
                        login = conn.read_until_pattern('Configure Router')
                        output += login + '\n'

                        conn.write_channel('2')
                        sleep(.5)
                        login = conn.read_until_pattern(REGEX_PROMPT)
                        output += login + '\n'

                        access = 'local'
                        return True
                    elif re.search(r'assword:', login, re.IGNORECASE):
                        login = conn.send_command(password, expect_string=r'assword:|Datablink token:|ESCOLHA UMA OP|'
                                                                          + REGEX_PROMPT,
                                                  strip_prompt=False,
                                                  cmd_verify=False)
                        # output += login + '\n'
                        if re.search(r'Datablink token:', login, re.IGNORECASE):
                            token = input("Datablink token:")
                            login = conn.send_command(token, expect_string=r'assword:|' + REGEX_PROMPT,
                                                      strip_prompt=False,
                                                      cmd_verify=False)
                            output += login + '\n'
                        if re.search(r'assword:', login, re.IGNORECASE) and local_users:

                            for data in local_users:
                                local_password = [data]
                                enable_password = data.get('enable')

                                conn.write_channel('\x03')
                                conn.read_until_pattern(REGEX_PROMPT)

                                sleep(1)

                                output += 'ssh -c ' + cipher.split(',')[0] + ' ' + data.get('usr') + '@' \
                                          + hostname_ip + '\n'
                                login = conn.send_command('ssh -c ' + cipher.split(',')[0] + ' ' + data.get('usr') + '@'
                                                          + hostname_ip,
                                                          expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                        + REGEX_PROMPT,
                                                          strip_prompt=False, cmd_verify=False)

                                if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                                    conn.write_channel('\r')
                                    sleep(.5)
                                    login = conn.read_until_pattern('Configure Router')
                                    output += login + '\n'

                                    conn.write_channel('2')
                                    sleep(.5)
                                    login = conn.read_until_pattern(REGEX_PROMPT)
                                    output += login + '\n'

                                    access = 'local'
                                    return True
                                elif re.search(r'assword:', login, re.IGNORECASE):
                                    login = conn.send_command(data.get('pwd'),
                                                              expect_string=r'assword:|ESCOLHA UMA OP|' + REGEX_PROMPT,
                                                              strip_prompt=False,
                                                              cmd_verify=False)
                                    if re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                                        conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False,
                                                          cmd_verify=False)
                                        access = 'local'
                                        return True
                                    elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                                        access = 'local'
                                        return True
                                    else:
                                        continue
                                else:
                                    continue
                            conn.write_channel('\x03')
                            conn.read_until_pattern(REGEX_PROMPT)
                            ret['status'] = -5
                            return False
                        elif re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                            conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False, cmd_verify=False)
                            access = 'tacacs'
                            return True
                        elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                            access = 'tacacs'
                            return True
                        elif re.search(r'assword:', login, re.IGNORECASE):
                            conn.write_channel('\x03')
                            conn.read_until_pattern(REGEX_PROMPT)
                            ret['status'] = -5
                            return False

                    if re.search(r'Invalid key length', login, re.IGNORECASE):
                        return False
                elif re.search(r'ssh_dispatch_run_fatal', login, re.IGNORECASE):
                    output += 'ssh -oKexAlgorithms=diffie-hellman-group1-sha1 ' + username + '@' + hostname_ip + '\n'
                    login = conn.send_command('ssh -oKexAlgorithms=diffie-hellman-group1-sha1 ' + username + '@'
                                              + hostname_ip, expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                           + REGEX_PROMPT,
                                              strip_prompt=False, cmd_verify=False)
                    output += login + '\n'
                    if re.search(r'(ssh-keygen -f .*)', login, re.IGNORECASE):
                        cmd = re.findall(r'(ssh-keygen -f .*)', login, re.IGNORECASE)[0]
                        output += cmd + '\n'
                        login = conn.send_command(cmd, expect_string=REGEX_PROMPT, strip_prompt=False)
                        output += login + '\n'

                        output += 'ssh -oKexAlgorithms=diffie-hellman-group1-sha1 ' \
                                  + username + '@' + hostname_ip + '\n'
                        login = conn.send_command('ssh -oKexAlgorithms=diffie-hellman-group1-sha1 ' + username + '@'
                                                  + hostname_ip, expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                               + REGEX_PROMPT,
                                                  strip_prompt=False, cmd_verify=False)
                        output += login + '\n'
                    if re.search(r'Add correct host key', login, re.IGNORECASE):
                        output += 'ssh-keygen -R ' + hostname_ip + '\n'
                        login = conn.send_command('ssh-keygen -R ' + hostname_ip, expect_string=REGEX_PROMPT,
                                                  strip_prompt=False)
                        output += login + '\n'

                        output += 'ssh -oKexAlgorithms=diffie-hellman-group1-sha1 ' \
                                  + username + '@' + hostname_ip + '\n'
                        login = conn.send_command('ssh -oKexAlgorithms=diffie-hellman-group1-sha1 ' + username + '@'
                                                  + hostname_ip, expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                               + REGEX_PROMPT,
                                                  strip_prompt=False, cmd_verify=False)
                        output += login + '\n'
                    if re.search(r'yes/no', login, re.IGNORECASE):
                        login = conn.send_command('yes', expect_string=r'assword:|Type ENTER to run',
                                                  strip_prompt=False)
                        output += login + '\n'
                    if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                        conn.write_channel('\r')
                        sleep(.5)
                        login = conn.read_until_pattern('Configure Router')
                        output += login + '\n'

                        conn.write_channel('2')
                        sleep(.5)
                        login = conn.read_until_pattern(REGEX_PROMPT)
                        output += login + '\n'

                        access = 'local'
                        return True
                    elif re.search(r'assword:', login, re.IGNORECASE):
                        login = conn.send_command(password, expect_string=r'assword:|Datablink token:|ESCOLHA UMA OP|'
                                                                          + REGEX_PROMPT,
                                                  strip_prompt=False,
                                                  cmd_verify=False)
                        # output += login + '\n'
                        if re.search(r'Datablink token:', login, re.IGNORECASE):
                            token = input("Datablink token:")
                            login = conn.send_command(token, expect_string=r'assword:|' + REGEX_PROMPT,
                                                      strip_prompt=False,
                                                      cmd_verify=False)
                            output += login + '\n'
                        if re.search(r'assword:', login, re.IGNORECASE) and local_users:

                            for data in local_users:
                                local_password = [data]
                                enable_password = data.get('enable')

                                conn.write_channel('\x03')
                                conn.read_until_pattern(REGEX_PROMPT)

                                sleep(1)

                                output += 'ssh -oKexAlgorithms=diffie-hellman-group1-sha1 ' \
                                          + data.get('usr') + '@' + hostname_ip + '\n'
                                login = conn.send_command('ssh -oKexAlgorithms=diffie-hellman-group1-sha1 '
                                                          + data.get('usr') + '@' + hostname_ip,
                                                          expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                        + REGEX_PROMPT,
                                                          strip_prompt=False, cmd_verify=False)
                                if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                                    conn.write_channel('\r')
                                    sleep(.5)
                                    login = conn.read_until_pattern('Configure Router')
                                    output += login + '\n'

                                    conn.write_channel('2')
                                    sleep(.5)
                                    login = conn.read_until_pattern(REGEX_PROMPT)
                                    output += login + '\n'

                                    access = 'local'
                                    return True
                                elif re.search(r'assword:', login, re.IGNORECASE):
                                    login = conn.send_command(data.get('pwd'),
                                                              expect_string=r'assword:|ESCOLHA UMA OP|' + REGEX_PROMPT,
                                                              strip_prompt=False,
                                                              cmd_verify=False)
                                    if re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                                        conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False,
                                                          cmd_verify=False)
                                        access = 'local'
                                        return True
                                    elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                                        access = 'local'
                                        return True
                                    else:
                                        continue
                                else:
                                    continue
                            conn.write_channel('\x03')
                            conn.read_until_pattern(REGEX_PROMPT)
                            ret['status'] = -5
                            return False
                        elif re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                            conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False, cmd_verify=False)
                            access = 'tacacs'
                            return True
                        elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                            access = 'tacacs'
                            return True
                        elif re.search(r'assword:', login, re.IGNORECASE):
                            conn.write_channel('\x03')
                            conn.read_until_pattern(REGEX_PROMPT)
                            ret['status'] = -5
                            return False

                    if re.search(r'Invalid key length', login, re.IGNORECASE):
                        return False

                elif re.search(r'Type ENTER to run', login, re.IGNORECASE):
                    conn.write_channel('\r')
                    sleep(.5)
                    login = conn.read_until_pattern('Configure Router')
                    output += login + '\n'

                    conn.write_channel('2')
                    sleep(.5)
                    login = conn.read_until_pattern(REGEX_PROMPT)
                    output += login + '\n'

                    access = 'local'
                    return True

                elif not (re.search(r'refused', login, re.IGNORECASE) or
                          re.search(r'closed', login, re.IGNORECASE) or
                          re.search(r'Unable', login, re.IGNORECASE) or
                          re.search(r'Cannot', login, re.IGNORECASE) or
                          re.search(r'failed', login, re.IGNORECASE)):
                    if re.search(r'yes/no', login, re.IGNORECASE):
                        login = conn.send_command('yes', expect_string=r'assword:|Type ENTER to run',
                                                  strip_prompt=False)

                    output += login + '\n'
                    if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                        conn.write_channel('\r')
                        sleep(.5)
                        login = conn.read_until_pattern('Configure Router')
                        output += login + '\n'

                        conn.write_channel('2')
                        sleep(.5)
                        login = conn.read_until_pattern(REGEX_PROMPT)
                        output += login + '\n'

                        access = 'local'
                        return True
                    elif re.search(r'assword:', login, re.IGNORECASE):

                        login = conn.send_command(password, expect_string=r'assword:|Datablink token:|'
                                                                          + REGEX_PROMPT + '|ESCOLHA UMA OP',
                                                  strip_prompt=False,
                                                  cmd_verify=False)

                        if re.search(r'Datablink token:', login, re.IGNORECASE):
                            token = input("Datablink token:")
                            login = conn.send_command(token, expect_string=r'assword:|' + REGEX_PROMPT,
                                                      strip_prompt=False,
                                                      cmd_verify=False)
                            output += login + '\n'
                        if re.search(r'assword:', login, re.IGNORECASE) and local_users:

                            for data in local_users:
                                local_password = [data]
                                enable_password = data.get('enable')

                                conn.write_channel('\x03')
                                conn.read_until_pattern(REGEX_PROMPT)

                                sleep(1)

                                output += 'ssh ' + data.get('usr') + '@' + hostname_ip + '\n'
                                login = conn.send_command('ssh ' + data.get('usr') + '@' + hostname_ip,
                                                          expect_string=r'yes/no|assword:|Type ENTER to run|'
                                                                        + REGEX_PROMPT,
                                                          strip_prompt=False, cmd_verify=False)
                                if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                                    conn.write_channel('\r')
                                    sleep(.5)
                                    login = conn.read_until_pattern('Configure Router')
                                    output += login + '\n'

                                    conn.write_channel('2')
                                    sleep(.5)
                                    login = conn.read_until_pattern(REGEX_PROMPT)
                                    output += login + '\n'

                                    access = 'local'
                                    return True
                                elif re.search(r'assword:', login, re.IGNORECASE):
                                    login = conn.send_command(data.get('pwd'),
                                                              expect_string=r'assword:|ESCOLHA UMA OP|' + REGEX_PROMPT,
                                                              strip_prompt=False,
                                                              cmd_verify=False)
                                    if re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                                        conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False,
                                                          cmd_verify=False)
                                        access = 'local'
                                        return True
                                    elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                                        access = 'local'
                                        return True
                                    else:
                                        continue
                                else:
                                    continue
                            conn.write_channel('\x03')
                            conn.read_until_pattern(REGEX_PROMPT)
                            ret['status'] = -5
                            return False
                        elif re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                            conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False, cmd_verify=False)
                            access = 'tacacs'
                            return True
                        elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                            access = 'tacacs'
                            return True
                        elif re.search(r'assword:', login, re.IGNORECASE):
                            conn.write_channel('\x03')
                            conn.read_until_pattern(REGEX_PROMPT)
                            ret['status'] = -5
                            return False

                else:
                    return False

            def _telnet(prompt) -> bool:
                nonlocal access, hostname, output, ret, enable_password, local_password
                output += prompt + 'telnet ' + hostname_ip + '\n'
                try:
                    login = conn.send_command('telnet ' + hostname_ip,
                                              expect_string=r'sername:|(?<![Ll]ast )(?<!successful )[Ll]ogin:|'
                                                            r'ser name:|Answer:|accept|' + REGEX_PROMPT + '|'
                                                            r'Type ENTER to run',
                                              strip_prompt=False)
                    output += login + '\n'
                except NetmikoTimeoutException:
                    logout = Login.force_logout(conn)
                    output += '\n' + logout
                    return False

                tmp_hostname = re.findall(r'([\w.\-/]+) login', login, re.IGNORECASE)
                hostname = tmp_hostname[0].lower() if tmp_hostname else None

                if re.search(r'Type ENTER to run', login, re.IGNORECASE):
                    conn.write_channel('\r')
                    cmd_out = ''
                    stop_loop = 9
                    while cmd_out == '' or stop_loop == 0:
                        cmd_out = conn.read_channel()
                        if stop_loop == 5:
                            conn.write_channel('\r')
                        sleep(.5)
                        stop_loop -= 1

                    cmd_out = ''
                    stop_loop = 9
                    conn.write_channel('2')
                    while cmd_out == '' or stop_loop == 0:
                        cmd_out = conn.read_channel()
                        if stop_loop == 5:
                            conn.write_channel('2')
                        sleep(.5)
                        stop_loop -= 1

                    access = 'local'
                    return True
                elif not (re.search(r'refused', login, re.IGNORECASE) or
                          re.search(r'closed', login, re.IGNORECASE) or
                          re.search(r'Unable', login, re.IGNORECASE) or
                          re.search(r'Cannot', login, re.IGNORECASE) or
                          re.search(r'assword:', login, re.IGNORECASE)):

                    if re.search(r'Answer: y', login, re.IGNORECASE):
                        login = conn.send_command('y', expect_string=r'ser name:', strip_prompt=False, cmd_verify=False)
                        output += login + '\n'

                    if re.search(r'Press \'a\' to', login, re.IGNORECASE):
                        login = conn.send_command('a', expect_string=r'login:', strip_prompt=False, cmd_verify=False)
                        output += login + '\n'

                    if re.search(r'Username:', login, re.IGNORECASE) or \
                            re.search(r'ser name:', login, re.IGNORECASE) or \
                            re.search(r'Login:', login, re.IGNORECASE):

                        # TREHO ABAIXO COM BUG NO CORIANT
                        login = conn.send_command(username, expect_string=r'assword:',
                                                  strip_prompt=False, cmd_verify=False)
                        # FUNCIONANDO PELO TRECHO ABAIXO
                        # conn.write_channel(username + '\r')
                        # sleep(.5)

                        # login = conn.read_until_pattern('assword:')

                        # if re.search(r'Login:', login, re.IGNORECASE):
                        #     # TREHO ABAIXO COM BUG NO CORIANT
                        #     # login = conn.send_command(username, expect_string=r'assword:',
                        #     #                           strip_prompt=False, cmd_verify=False)
                        #     # FUNCIONANDO PELO TRECHO ABAIXO
                        #     conn.write_channel(username + '\r')
                        #     sleep(.5)
                        #     login = conn.read_until_pattern('assword:')
                        if 'assword:' in login:
                            output += login + '\n'
                            login = conn.send_command(password,
                                                      expect_string=r'sername:|(?<![Ll]ast )(?<!successful )[Ll]ogin:|'
                                                                    r'ser name:|assword:|' + REGEX_PROMPT + r'|accept|'
                                                                    + r'ESCOLHA UMA OP',
                                                      strip_prompt=False,
                                                      cmd_verify=False)
                            # conn.write_channel(password + '\r')
                            # sleep(.5)
                            # login = conn.read_until_pattern(r'sername:|(?<![Ll]ast )(?<!successful )[Ll]ogin:|ser name:'
                            #                                 R'|assword:|' + REGEX_PROMPT + r'|accept|ESCOLHA UMA OP')

                            output += login + '\n'
                    if 'backtraceHandler' in login:
                        access = 'falha_hw'
                        return False
                    elif re.search(r'closed.*host', login, re.IGNORECASE) and local_users:

                        for data in local_users:
                            local_password = [data]
                            enable_password = data.get('enable')

                            sleep(.5)
                            output += prompt + 'telnet ' + hostname_ip + '\n'
                            login = conn.send_command('telnet ' + hostname_ip,
                                                      expect_string=r'sername:|(?<![Ll]ast )(?<!successful )[Ll]ogin:|'
                                                                    r'ser name:|Answer:|accept|' + REGEX_PROMPT + '|'
                                                                    r'Type ENTER to run',
                                                      strip_prompt=False, cmd_verify=False)



                            if re.search(r'Press \'a\' to', login, re.IGNORECASE):
                                login = conn.send_command('a', expect_string=r'login:', strip_prompt=False, cmd_verify=False)
                                output += login + '\n'
                            elif re.search(r'Type ENTER to run', login, re.IGNORECASE):
                                conn.write_channel('\r')
                                cmd_out = ''
                                stop_loop = 9
                                while cmd_out == '' or stop_loop == 0:
                                    cmd_out = conn.read_channel()
                                    if stop_loop == 5:
                                        conn.write_channel('\r')
                                    sleep(.5)
                                    stop_loop -= 1

                                cmd_out = ''
                                stop_loop = 9
                                conn.write_channel('2')
                                while cmd_out == '' or stop_loop == 0:
                                    cmd_out = conn.read_channel()
                                    if stop_loop == 5:
                                        conn.write_channel('2')
                                    sleep(.5)
                                    stop_loop -= 1

                                access = 'local'
                                return True
                            elif re.search(r'Answer: y', login, re.IGNORECASE):
                                login = conn.send_command('y', expect_string=r'ser name:', strip_prompt=False,
                                                          cmd_verify=False)
                                output += login + '\n'

                            if re.search(r'Username:', login, re.IGNORECASE) or \
                                    re.search(r'ser name:', login, re.IGNORECASE) or \
                                    re.search(r'Login:', login, re.IGNORECASE):
                                # TREHO ABAIXO COM BUG NO CORIANT
                                login = conn.send_command(data.get('usr'),
                                                          expect_string=r'assword:',
                                                          strip_prompt=False, cmd_verify=False)
                                # FUNCIONANDO PELO TRECHO ABAIXO
                                # conn.write_channel(data.get('usr') + '\r')
                                # sleep(.5)
                                # login = conn.read_until_pattern('assword:')

                                output += login + '\n'
                                login = conn.send_command(data.get('pwd'),
                                                          expect_string=r'(?<![Ll]ast )(?<!successful )[Ll]ogin:|accept|'
                                                                        r'ser name:|sername:|assword:|' + REGEX_PROMPT
                                                                        + r'|ESCOLHA UMA OP',
                                                          strip_prompt=False,
                                                          cmd_verify=False)
                                # conn.write_channel(data.get('pwd') + '\r')
                                # sleep(.5)
                                # login = conn.read_until_pattern(r'(?<![Ll]ast )(?<!successful )[Ll]ogin:|accept|ser name:'
                                #                                 r'|sername:|assword:|' + REGEX_PROMPT + '|ESCOLHA UMA OP')

                                output += login + '\n'

                            if re.search(r'Press \'a\' to', login, re.IGNORECASE):
                                login = conn.send_command('a', expect_string=r'login:', strip_prompt=False, cmd_verify=False)
                                output += login + '\n'
                            elif 'backtraceHandler' in login:
                                access = 'falha_hw'
                                return False
                            elif re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                                conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False, cmd_verify=False)
                                access = 'local'
                                return True
                            elif re.search(r'closed.*host', login, re.IGNORECASE):
                                continue
                            elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                                access = 'local'
                                return True
                        ret['status'] = -5
                        return False

                    elif (re.search(r'Username:', login, re.IGNORECASE) or
                          re.search(r'ser name:', login, re.IGNORECASE) or
                          re.search(r'Press', login, re.IGNORECASE) or
                          re.search(r'(?<![Ll]ast )(?<!successful )[Ll]ogin:', login, re.IGNORECASE)) and local_users:

                        for data in local_users:
                            local_password = [data]
                            enable_password = data.get('enable')

                            if re.search(r'Press \'a\' to', login, re.IGNORECASE):
                                login = conn.send_command('a', expect_string=r'login:', strip_prompt=False, cmd_verify=False)
                                output += login + '\n'
                            elif re.search(r'Type ENTER to run', login, re.IGNORECASE):
                                conn.write_channel('\r')
                                cmd_out = ''
                                stop_loop = 9
                                while cmd_out == '' or stop_loop == 0:
                                    cmd_out = conn.read_channel()
                                    if stop_loop == 5:
                                        conn.write_channel('\r')
                                    sleep(.5)
                                    stop_loop -= 1

                                cmd_out = ''
                                stop_loop = 9
                                conn.write_channel('2')
                                while cmd_out == '' or stop_loop == 0:
                                    cmd_out = conn.read_channel()
                                    if stop_loop == 5:
                                        conn.write_channel('2')
                                    sleep(.5)
                                    stop_loop -= 1

                                access = 'local'
                                return True
                            elif re.search(r'Answer: y', login, re.IGNORECASE):
                                login = conn.send_command('y', expect_string=r'ser name:', strip_prompt=False,
                                                          cmd_verify=False)
                                output += login + '\n'

                            if re.search(r'Username:', login, re.IGNORECASE) or \
                                    re.search(r'ser name:', login, re.IGNORECASE) or \
                                    re.search(r'Login:', login, re.IGNORECASE):
                                # TREHO ABAIXO COM BUG NO CORIANT
                                login = conn.send_command(data.get('usr'),
                                                          expect_string=r'assword:',
                                                          strip_prompt=False, cmd_verify=False)
                                # FUNCIONANDO PELO TRECHO ABAIXO
                                # conn.write_channel(data.get('usr') + '\r')
                                # sleep(.5)
                                # login = conn.read_until_pattern('assword:')

                                output += login + '\n'
                                login = conn.send_command(data.get('pwd'),
                                                          expect_string=r'(?<![Ll]ast )(?<!successful )[Ll]ogin:|accept|'
                                                                        r'ser name:|sername:|assword:|' + REGEX_PROMPT
                                                                        + r'|ESCOLHA UMA OP',
                                                          strip_prompt=False,
                                                          cmd_verify=False)
                                # conn.write_channel(data.get('pwd') + '\r')
                                # sleep(.5)
                                # login = conn.read_until_pattern(r'(?<![Ll]ast )(?<!successful )[Ll]ogin:|accept|ser name:'
                                #                                 r'|sername:|assword:|' + REGEX_PROMPT + '|ESCOLHA UMA OP')

                                output += login + '\n'

                            if re.search(r'Press \'a\' to', login, re.IGNORECASE):
                                login = conn.send_command('a', expect_string=r'login:', strip_prompt=False, cmd_verify=False)
                                output += login + '\n'
                            elif 'backtraceHandler' in login:
                                access = 'falha_hw'
                                return False
                            elif re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                                conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False, cmd_verify=False)
                                access = 'local'
                                return True
                            elif re.search(r'closed.*host', login, re.IGNORECASE):
                                login = conn.send_command('telnet ' + hostname_ip,
                                                          expect_string=r'sername:|ser name:|Answer:|accept|'
                                                                        r'(?<![Ll]ast )(?<!successful )[Ll]ogin:|'
                                                                        r'' + REGEX_PROMPT + '|Type ENTER to run',
                                                          strip_prompt=False)
                                continue
                            elif re.search(REGEX_PROMPT, login, re.IGNORECASE) and prompt not in login:
                                access = 'local'
                                return True
                            else:
                                continue
                        access = 'password_failed'
                        if re.search(r'sername:|ser name:|(?<![Ll]ast )(?<!successful )[Ll]ogin:|assword:', login,
                                     re.IGNORECASE):
                            logout = Login.force_logout(conn)
                            output += '\n' + logout
                        ret['status'] = -5
                        return False
                    elif re.search(r'Username:', login, re.IGNORECASE) or \
                            re.search(r'ser name:', login, re.IGNORECASE) or \
                            re.search(r'(?<![Ll]ast )(?<!successful )[Ll]ogin:', login, re.IGNORECASE):
                        access = 'password_failed'
                        logout = Login.force_logout(conn, '\x03\x1A')
                        output += '\n' + logout
                        ret['status'] = -5
                        return False
                    elif re.search(r'ESCOLHA UMA OP', login, re.IGNORECASE):
                        conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False, cmd_verify=False)
                        access = 'tacacs'
                        return True
                    elif re.search(REGEX_PROMPT, login, re.IGNORECASE):
                        access = 'tacacs'
                        return True
                    elif re.search(r'assword', login, re.IGNORECASE):
                        logout = Login.force_logout(conn)
                        output += '\n' + logout
                        ret['status'] = -5
                        return False
                else:
                    # conn.read_until_pattern(REGEX_PROMPT)  # netmiko 4.1.2
                    return False

            jump_prompt = conn.find_prompt()

            if socket.gethostname() not in jump_prompt:
                output += 'ping -c 2 -n -W 1 -q ' + hostname_ip + '\n'
                eqp_status = conn.send_command('ping -c 2 -n -W 1 -q ' + hostname_ip,
                                               cmd_verify=False)

                if re.search(r'received, 5?0% packet loss', eqp_status, re.IGNORECASE):
                    ping = True
                elif re.search(r'Nome ou serviço desconhecido', eqp_status, re.IGNORECASE) or \
                        re.search(r'Name or service not known', eqp_status, re.IGNORECASE) or \
                        re.search(r'Falha (?:\w|\W)+ na (?:\w|\W)+ de nome', eqp_status, re.IGNORECASE):
                    output += eqp_status + '\n'
                    ret['status'] = -2  # hostname não encontrado
                    return ret
                else:
                    output += eqp_status + '\n'
                    ret['status'] = -1  # Ping NOK
                    return ret

                if ssh and ping:
                    ssh_conn = _ssh(jump_prompt)

                    if not ssh_conn:
                        telnet_conn = _telnet(jump_prompt)
                elif ping:
                    telnet_conn = _telnet(jump_prompt)

                    if not telnet_conn:
                        ssh_conn = _ssh(jump_prompt)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname_ip, 23))
                sock.close()
                del sock

                if result == 0:
                    telnet_conn = _telnet(jump_prompt)

                    if not telnet_conn:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((hostname_ip, 22))
                        sock.close()
                        del sock
                        if result == 0:
                            ssh_conn = _ssh(jump_prompt)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((hostname_ip, 22))
                    sock.close()
                    del sock

                    if result == 0:
                        ssh_conn = _ssh(jump_prompt)

                        if not ssh_conn:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(1)
                            result = sock.connect_ex((hostname_ip, 23))
                            sock.close()
                            del sock
                            if result == 0:
                                telnet_conn = _telnet(jump_prompt)
                    else:
                        ret['status'] = -1  # Sem Conectividade

            if ssh_conn is True or telnet_conn is True:

                eqp_prompt = conn.find_prompt()
                if eqp_prompt == jump_prompt:
                    raise Exception

                login_check = Login.check_ios(conn, eqp_prompt, enable_password)
                output += login_check.get('output')
                if login_check.get('status') == -1:
                    login_check = Login.check_ios(conn, eqp_prompt, enable_password)
                    output += login_check.get('output')

                hostname = re.findall(REGEX_HOSTNAME, eqp_prompt, re.IGNORECASE)

                ret['hostname'] = hostname[0].lower() if hostname else None
                ret['ios'] = login_check.get('ios')
                ret['status'] = login_check.get('status')
                ret['protocol'] = 'ssh' if ssh_conn is True else 'telnet' if telnet_conn is True else ''
            elif hostname is not None:
                ret['hostname'] = hostname

        except NetmikoTimeoutException:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'eqp_login_from_linux', 'Timeout'))
            ret['status'] = -7
        except OSError:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'eqp_login_from_linux',
                                             'Jump Server kill the session'))
            ret['status'] = -7
        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'eqp_login_from_linux', e))
            ret['status'] = -7
        finally:
            ret['access'] = access
            ret['local_password'] = local_password
            ret['output'] = Format.f_remove_color_codes(output)
            return ret

    @staticmethod
    def eqp_logout(conn, ios_type=None) -> dict:

        ret = None
        output = ''
        log = ''
        prompt = conn.find_prompt()

        try:
            if 'assword:' in prompt:
                logout = Login.force_logout(conn)
                output += '\n' + logout
            elif ios_type is None and 'jmp-srv' not in prompt:
                try:
                    output += '\n' + prompt + 'exit\n'
                    log = conn.send_command('exit', expect_string=REGEX_PROMPT + r'|y/n',
                                            cmd_verify=False)
                    output += '\n' + log
                    if 'y/n' in log:
                        output += '\n' + prompt + 'y\n'
                        log = conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False, cmd_verify=False)
                        output += '\n' + log
                    if '$' not in log:
                        output += '\n' + prompt + 'quit\n'
                        log = conn.send_command('quit', expect_string=REGEX_PROMPT + r'|y/n', strip_prompt=False,
                                                cmd_verify=False)
                        output += '\n' + log
                        if 'y/n' in log:
                            output += '\n' + prompt + 'y\n'
                            log = conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False,
                                                    cmd_verify=False)
                            output += '\n' + log
                        if '$' not in log:
                            output += '\n' + prompt + 'logout\n'
                            log = conn.send_command('logout', expect_string=REGEX_PROMPT, strip_prompt=False,
                                                    cmd_verify=False)
                            output += '\n' + log
                except ReadTimeout:
                    Login.force_logout(conn)

            elif ios_type == 'DatacomMiniMux':
                if '#' in prompt:
                    log = conn.send_command('exit', expect_string=REGEX_PROMPT, strip_prompt=False, cmd_verify=False)
                    output += '\n' + log

                conn.write_channel('exit\r')
                sleep(.5)
                login = conn.read_until_pattern(r'Option')
                output += login + '\n'

                conn.write_channel('e')
                sleep(.5)
                login = conn.read_until_pattern(REGEX_PROMPT)
                output += login + '\n'
            elif (ios_type in 'CiscoXE|Linux' or 'Datacom' in ios_type) and 'jmp-srv' not in prompt \
                    and 'redeip-oper1' not in prompt:
                output += '\n' + prompt + 'exit\n'
                log = conn.send_command('exit', expect_string=REGEX_PROMPT, strip_prompt=False, cmd_verify=False)
                output += '\n' + log
            elif ios_type == 'Nokia' or ios_type == 'TP4100' or ios_type == 'TP5000':
                output += '\n' + prompt + 'logout\n'
                log = conn.send_command('logout', expect_string=REGEX_PROMPT, strip_prompt=False, cmd_verify=False)
                output += '\n' + log

            elif 'jmp-srv' not in prompt and 'redeip-oper1' not in prompt:
                output += '\n' + prompt + 'quit\n'
                log = conn.send_command('quit', expect_string=r'y/n|' + REGEX_PROMPT, strip_prompt=False,
                                        cmd_verify=False)
                output += '\n' + log

            if 'y/n' in log:
                output += '\n' + prompt + 'y\n'
                log = conn.send_command('y', expect_string=REGEX_PROMPT, strip_prompt=False, cmd_verify=False)
                output += '\n' + log

            # Desabilitado pois não está sendo utilizado o método "redispatch" do Netmiko durante o login
            # log = Login.check_ios(conn, conn.find_prompt())
            # output += '\n' + log.get('output')

            ret = {"status": 1}
        except OSError:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'eqp_logout', 'Jump Server kill the session'))
            ret = {"status": -7}
        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'eqp_logout', e))
            ret = {"status": -7}
        finally:
            ret['output'] = Format.f_remove_color_codes(output)
            return ret

    @staticmethod
    def check_ios(conn, host, enable_password=None) -> dict:

        login_status = None
        # device_type = 'autodetect'
        output = ''
        prompt = conn.find_prompt()

        try:
            if '/CPU' in host:
                output += prompt + 'terminal length 0\n'
                conn.send_command('terminal length 0', expect_string=REGEX_PROMPT, cmd_verify=False)
                # device_type = 'cisco_xr'
                login_status = {"ios": "CiscoXR", "status": 1}
            elif '<' in host:
                output += prompt + 'screen-length 0 temporary\n'
                cmd_out = conn.send_command('screen-length 0 temporary', expect_string=REGEX_PROMPT, cmd_verify=False)
                output += cmd_out + '\n'
                if 'Unrecognized' in cmd_out:
                    output += prompt + 'display version | include Software\n'
                    cmd_out = conn.send_command('display version | include Software', expect_string=REGEX_PROMPT,
                                                cmd_verify=False)
                    output += cmd_out + '\n'
                    if re.search(r'HPE? Comware', cmd_out, re.IGNORECASE):
                        output += prompt + 'screen-length disable\n'
                        conn.send_command('screen-length disable', expect_string=REGEX_PROMPT, cmd_verify=False)
                        # device_type = 'hp_comware'
                        login_status = {"ios": "HP", "status": 1}
                    elif re.search(r'H3C Comware', cmd_out, re.IGNORECASE):
                        output += prompt + 'screen-length disable\n'
                        conn.send_command('screen-length disable', expect_string=REGEX_PROMPT, cmd_verify=False)
                        login_status = {"ios": "H3C", "status": 1}
                    elif 'Permission denied' in cmd_out:
                        login_status = {"ios": "HP", "status": -3}
                    elif re.search(r'Too many', cmd_out, re.IGNORECASE):
                        output += prompt + 'display version\n'
                        cmd_out = conn.send_command('display version', expect_string=REGEX_PROMPT, cmd_verify=False)
                        if re.search(r'H3C Comware|3Com Corporation', cmd_out, re.IGNORECASE):
                            login_status = {"ios": "H3C", "status": 1}
                        else:
                            login_status = {"ios": "Não foi possível identificar", "status": -6}
                    else:
                        login_status = {"ios": "Não foi possível identificar", "status": -6}
                else:
                    output += prompt + 'display version | include VRP\n'
                    cmd_out = conn.send_command('display version | include VRP', expect_string=REGEX_PROMPT,
                                                cmd_verify=False)
                    output += cmd_out + '\n'
                    if 'VRP (R) software, Version 8' in cmd_out:
                        # device_type = 'huawei_vrpv8'
                        login_status = {"ios": "HuaweiVrpV8", "status": 1}
                    else:
                        # device_type = 'huawei'
                        login_status = {"ios": "Huawei", "status": 1}
            elif '$' in host and 'jmp-srv' not in host and 'redeip-oper1' not in host and 'discovery' not in host:
                output += prompt + 'show inventory\n'
                cmd_out = conn.send_command('show inventory', expect_string=REGEX_PROMPT, cmd_verify=False)
                output += cmd_out + '\n'
                if 'DM2500' in cmd_out:
                    output += prompt + 'set terminal pager disabled\n'
                    cmd_out = conn.send_command('set terminal pager disabled', expect_string=REGEX_PROMPT,
                                                cmd_verify=False)
                    output += cmd_out + '\n'
                    login_status = {"ios": "DatacomDM2500", "status": 1}
                elif 'Command not authorized by TACACS+' in cmd_out or 'Unable to connect to TACACS server' in cmd_out:
                    login_status = {"ios": "DatacomDM2500", "status": -3}
                else:
                    output += prompt + 'uname\n'
                    cmd_out = conn.send_command('uname', expect_string=REGEX_PROMPT, cmd_verify=False)
                    output += cmd_out + '\n'
                    if 'Linux' in cmd_out:
                        login_status = {"ios": "Linux", "status": 1}
                    else:
                        login_status = {"ios": "Não foi possível identificar", "status": -6}
            elif ':/' in host:
                output += prompt + 'get platform/inventory/product-name\n'
                cmd_out = conn.send_command('get platform/inventory/product-name',
                                            expect_string=REGEX_PROMPT, cmd_verify=False)
                output += cmd_out + '\n'
                if 'IDU' in cmd_out:
                    login_status = {"ios": "Ceragon", "status": 1}
                else:
                    login_status = {"ios": "Não foi possível identificar", "status": -6}
            elif re.search(r'^\*?[AB]:[\w._:-]+#', host):
                # device_type = 'alcatel_sros'
                output += prompt + 'environment no more\n'
                cmd_out = conn.send_command('environment no more', expect_string=REGEX_PROMPT, cmd_verify=False)
                output += cmd_out + '\n'
                login_status = {"ios": "Nokia", "status": 1}
            elif '#' in host:
                output += prompt + 'terminal length 0\n'
                cmd_out = conn.send_command('terminal length 0', expect_string=REGEX_PROMPT, cmd_verify=False)
                output += cmd_out + '\n'
                if 'Invalid' in cmd_out or 'syntax error:' in cmd_out:
                    output += prompt + 'show system\n'
                    cmd_out = conn.send_command('show system', expect_string=r'--More--|' + REGEX_PROMPT,
                                                cmd_verify=False)
                    output += cmd_out + '\n'
                    if '--More--' in cmd_out:
                        cmd_out += conn.send_command('\x20\x20', expect_string=r'--More--|' + REGEX_PROMPT,
                                                     cmd_verify=False)
                        output += cmd_out + '\n'
                    if 'Factory' in cmd_out:
                        login_status = {"ios": "Datacom", "status": 1}
                    elif 'Chassis/Slot' in cmd_out:
                        login_status = {"ios": "DatacomDmOS", "status": 1}
                    elif 'Incomplete' in cmd_out:
                        output += prompt + 'show system information\n'
                        cmd_out = conn.send_command('show system information', expect_string=REGEX_PROMPT,
                                                    cmd_verify=False)
                        output += cmd_out + '\n'
                        if 'SIAE' in cmd_out:
                            login_status = {"ios": "Siae", "status": 1}
                        else:
                            login_status = {"ios": "Não foi possível identificar", "status": -6}
                    else:
                        login_status = {"ios": "Não foi possível identificar", "status": -6}

                elif 'Unrecognised' in cmd_out:

                    cmd_out = conn.send_command('terminal length 200', expect_string=REGEX_PROMPT, strip_prompt=False,
                                                cmd_verify=False)
                    output += cmd_out + '\n'
                    # device_type = 'coriant'

                else:
                    output += prompt + 'show version\n'
                    cmd_out = conn.send_command('show version', expect_string=REGEX_PROMPT, cmd_verify=False)
                    output += cmd_out + '\n'
                    if 'NXOS' in cmd_out:
                        # device_type = 'cisco_nxos'
                        login_status = {"ios": "CiscoNX", "status": 1}
                    elif 'Ruckus' in cmd_out:
                        # device_type = 'brocade_fastiron'
                        login_status = {"ios": "BrocadeRuckus", "status": 1}
                    elif 'Brocade' in cmd_out:
                        # device_type = 'brocade_vdx'
                        login_status = {"ios": "BrocadeVDX", "status": 1}
                    elif 'Cisco' in cmd_out:
                        output += prompt + 'terminal length 0\n'
                        conn.send_command('terminal length 0', expect_string=REGEX_PROMPT, cmd_verify=False)
                        # device_type = 'cisco_xe'
                        login_status = {"ios": "CiscoXE", "status": 1}
                    elif 'ZTE' in cmd_out:
                        # device_type = 'zte_zxros'
                        login_status = {"ios": "ZTE", "status": 1}
                    elif 'Command fail' in cmd_out:
                        output += prompt + 'get system status\n'
                        cmd_out = conn.send_command('get system status', expect_string=REGEX_PROMPT, cmd_verify=False)
                        output += cmd_out + '\n'
                        if 'FortiGate' in cmd_out or 'FortiWiFi' in cmd_out:
                            # device_type = 'fortinet'
                            login_status = {"ios": "Fortinet", "status": 1}
                        else:
                            login_status = {"ios": "Não foi possível identificar", "status": -6}
                    elif 'Command authorization failed' in cmd_out:
                        output += prompt + 'enable view\n'
                        ena = conn.send_command('enable view', expect_string=r'assword:|' + REGEX_PROMPT,
                                                strip_prompt=False, cmd_verify=False)
                        output += '\n' + ena
                        if re.search(r'assword:', ena, re.IGNORECASE):
                            chk_ena = conn.send_command(enable_password, expect_string=r'assword:|' + REGEX_PROMPT,
                                                        strip_prompt=False,
                                                        cmd_verify=False)
                            output += '\n' + chk_ena
                            if re.search(r'assword:', chk_ena, re.IGNORECASE):
                                login_status = {"ios": "CiscoXE", "status": -4}
                            else:
                                output += prompt + 'terminal length 0\n'
                                conn.send_command('terminal length 0', expect_string=REGEX_PROMPT, cmd_verify=False)
                                # device_type = 'cisco_xe'
                                login_status = {"ios": "CiscoXE", "status": 1}
                    else:
                        login_status = {"ios": "Não foi possível identificar", "status": -6}
            elif '@' in host and '>' in host:
                output += prompt + 'set cli screen-length 0\n'
                conn.send_command('set cli screen-length 0', expect_string=REGEX_PROMPT, cmd_verify=False)
                output += prompt + 'set cli screen-width 255\n'
                conn.send_command('set cli screen-width 255', expect_string=REGEX_PROMPT, cmd_verify=False)
                # device_type = 'juniper'
                login_status = {"ios": "Juniper", "status": 1}
            elif '>' in host:
                output += prompt + 'display version\n'

                # TRECHO COM BUG NO CORIANT
                # cmd_out = conn.send_command('display version', expect_string=r'frameid/slotid|' + REGEX_PROMPT,
                #                             strip_prompt=True, cmd_verify=False)
                # FUNCIONANDO PELO TRECHO ABAIXO

                conn.write_channel('display version\r\r')
                sleep(.5)
                cmd_out = conn.read_until_pattern(REGEX_PROMPT)
                output += cmd_out + '\n'
                if 'frameid/slotid' in cmd_out:
                    if re.search(r'MA560[038]', cmd_out, re.IGNORECASE):
                        cmd_out = conn.send_command('undo smart', expect_string=REGEX_PROMPT, cmd_verify=False)
                        output += cmd_out + '\n'
                        cmd_out = conn.send_command('enable', expect_string=REGEX_PROMPT, cmd_verify=False)
                        output += cmd_out + '\n'
                        # device_type = 'huawei_smartax'
                        login_status = {"ios": "HuaweiSmartAX", "status": 1}
                    else:
                        login_status = {"ios": "Não foi possível identificar", "status": -6}
                elif 'Unknown' in cmd_out or 'Invalid' in cmd_out:
                    output += prompt + 'show version\n'
                    cmd_out = conn.send_command('show version', expect_string=r'--More--|' + REGEX_PROMPT,
                                                cmd_verify=False)
                    output += cmd_out + '\n'
                    if '--More--' in cmd_out:
                        conn.write_channel('\x20')
                        check_out = conn.read_until_pattern(r'--More--|' + REGEX_PROMPT)
                        cmd_out += check_out
                        while '--More--' in check_out:
                            conn.write_channel('\x20')
                            check_out = conn.read_until_pattern(r'--More--|' + REGEX_PROMPT)
                            cmd_out += check_out
                    if 'Cisco' in cmd_out or 'Command authorization failed' in cmd_out:
                        output += prompt + 'enable\n'
                        ena = conn.send_command('enable', expect_string=r'assword:|' + REGEX_PROMPT,
                                                strip_prompt=False, cmd_verify=False)
                        output += '\n' + ena
                        if re.search(r'assword:', ena, re.IGNORECASE):
                            chk_ena = conn.send_command(enable_password, expect_string=r'assword:|' + REGEX_PROMPT,
                                                        strip_prompt=False,
                                                        cmd_verify=False)
                            output += '\n' + chk_ena
                            if re.search(r'assword:', chk_ena, re.IGNORECASE):
                                login_status = {"ios": "CiscoXE", "status": -4}
                            elif 'Error in authentication' in chk_ena:
                                output += prompt + 'enable view\n'
                                ena = conn.send_command('enable view', expect_string=r'assword:|' + REGEX_PROMPT,
                                                        strip_prompt=False, cmd_verify=False)
                                output += '\n' + ena
                                if re.search(r'Authentication failed', chk_ena, re.IGNORECASE):
                                    login_status = {"ios": "CiscoXE", "status": -4}
                                else:
                                    output += prompt + 'show version\n'
                                    cmd_out = conn.send_command('show version', expect_string=REGEX_PROMPT,
                                                                cmd_verify=False)
                                    output += cmd_out + '\n'
                                    if 'Cisco' in cmd_out:
                                        output += prompt + 'terminal length 0\n'
                                        conn.send_command('terminal length 0', expect_string=REGEX_PROMPT,
                                                          cmd_verify=False)
                                        login_status = {"ios": "CiscoXE", "status": 1}
                                    else:
                                        login_status = {"ios": "CiscoXE", "status": -4}
                            else:
                                output += prompt + 'terminal length 0\n'
                                conn.send_command('terminal length 0', expect_string=REGEX_PROMPT, cmd_verify=False)
                                # device_type = 'cisco_xe'
                                login_status = {"ios": "CiscoXE", "status": 1}
                        elif re.search(r'#', ena, re.IGNORECASE):
                            output += prompt + 'terminal length 0\n'
                            conn.send_command('terminal length 0', expect_string=REGEX_PROMPT, cmd_verify=False)
                            # device_type = 'cisco_xe'
                            login_status = {"ios": "CiscoXE", "status": 1}
                    elif 'Ruckus' in cmd_out:
                        # device_type = 'brocade_fastiron'
                        output += prompt + 'enable\n'
                        conn.send_command('enable', expect_string=REGEX_PROMPT, strip_prompt=False, cmd_verify=False)
                        output += prompt + 'skip-page-display\n'
                        conn.send_command('skip-page-display', expect_string=REGEX_PROMPT, strip_prompt=False,
                                          cmd_verify=False)
                        login_status = {"ios": "BrocadeICX", "status": 1}
                    elif 'Invalid' in cmd_out:
                        output += prompt + 'show system\n'
                        cmd_out = conn.send_command('show system', expect_string=REGEX_PROMPT, cmd_verify=False)
                        output += cmd_out + '\n'
                        if re.search(r'(?:Model:|1) *(DM.*)', cmd_out, re.IGNORECASE):
                            login_status = {"ios": "Datacom", "status": 1}
                        elif 'Invalid' in cmd_out:
                            output += prompt + 'show inventory\n'
                            cmd_out = conn.send_command('show inventory', expect_string=REGEX_PROMPT, cmd_verify=False)
                            output += cmd_out + '\n'
                            if re.search(r'System Model +- (\w+ \d+)', cmd_out, re.IGNORECASE):
                                login_status = {"ios": "TP5000", "status": 1}
                            elif re.search(r'Product Model +: (\w+ \d+)', cmd_out, re.IGNORECASE):
                                login_status = {"ios": "TP4100", "status": 1}
                            elif 'Invalid' in cmd_out:
                                output += prompt + 'enable\n'
                                ena = conn.send_command('enable', expect_string=r'assword:|' + REGEX_PROMPT,
                                                        strip_prompt=False, cmd_verify=False)
                                output += '\n' + ena
                                if re.search(r'assword:', ena, re.IGNORECASE):
                                    chk_ena = conn.send_command(enable_password,
                                                                expect_string=r'assword:|' + REGEX_PROMPT,
                                                                strip_prompt=False,
                                                                cmd_verify=False)
                                    output += '\n' + chk_ena
                                    if re.search(r'Access denied', chk_ena, re.IGNORECASE):
                                        login_status = {"ios": "Não foi possível identificar", "status": -6}
                                    else:
                                        output += prompt + 'show version\n'
                                        cmd_out = conn.send_command('show version', expect_string=REGEX_PROMPT,
                                                                    cmd_verify=False)
                                        output += cmd_out + '\n'
                                        if 'Command authorization failed' in cmd_out:
                                            output += prompt + 'enable view\n'
                                            ena = conn.send_command('enable view',
                                                                    expect_string=r'assword:|' + REGEX_PROMPT,
                                                                    strip_prompt=False, cmd_verify=False)
                                            output += '\n' + ena
                                            if re.search(r'assword:', ena, re.IGNORECASE):
                                                chk_ena = conn.send_command(enable_password,
                                                                            expect_string=r'assword:|' + REGEX_PROMPT,
                                                                            strip_prompt=False,
                                                                            cmd_verify=False)
                                                output += '\n' + chk_ena
                                                if re.search(r'Authentication failed', chk_ena, re.IGNORECASE):
                                                    login_status = {"ios": "Não foi possível identificar", "status": -6}
                                                else:
                                                    output += prompt + 'show version\n'
                                                    cmd_out = conn.send_command('show version',
                                                                                expect_string=REGEX_PROMPT,
                                                                                cmd_verify=False)
                                                    output += cmd_out + '\n'
                                                    if 'Cisco' in cmd_out:
                                                        output += prompt + 'terminal length 0\n'
                                                        conn.send_command('terminal length 0',
                                                                          expect_string=REGEX_PROMPT, cmd_verify=False)
                                                        login_status = {"ios": "CiscoXE", "status": 1}
                                                    else:
                                                        login_status = {"ios": "Não foi possível identificar",
                                                                        "status": -6}
                                        else:
                                            login_status = {"ios": "Não foi possível identificar", "status": -6}
                                else:
                                    login_status = {"ios": "Não foi possível identificar", "status": -6}
                        else:
                            output += prompt + 'enable\n'
                            ena = conn.send_command('enable view', expect_string=r'assword:|' + REGEX_PROMPT,
                                                    strip_prompt=False, cmd_verify=False)
                            output += '\n' + ena
                            if re.search(r'assword:', ena, re.IGNORECASE):
                                chk_ena = conn.send_command(enable_password, expect_string=r'assword:|' + REGEX_PROMPT,
                                                            strip_prompt=False,
                                                            cmd_verify=False)
                                output += '\n' + chk_ena
                                if re.search(r'assword:', chk_ena, re.IGNORECASE):
                                    login_status = {"ios": "Datacom", "status": -4}
                                else:
                                    output += prompt + 'show tech-support\n'
                                    cmd_out = conn.send_command('show tech-support', expect_string=REGEX_PROMPT,
                                                                cmd_verify=False)
                                    output += cmd_out + '\n'
                                    if re.search(r'product_name=DM706CR', cmd_out, re.IGNORECASE):
                                        login_status = {"ios": "DatacomMiniMux", "status": 1}
                                    else:
                                        login_status = {"ios": "DatacomMiniMux", "status": 1}
                            else:
                                login_status = {"ios": "Não foi possível identificar", "status": -6}
                    elif 'ZTE' in cmd_out:
                        output += prompt + 'enable\n'
                        ena = conn.send_command('enable', expect_string=r'assword:|' + REGEX_PROMPT,
                                                strip_prompt=False, cmd_verify=False)
                        output += '\n' + ena
                        if re.search(r'assword:', ena, re.IGNORECASE):
                            chk_ena = conn.send_command(enable_password, expect_string=r'assword:|' + REGEX_PROMPT,
                                                        strip_prompt=False,
                                                        cmd_verify=False)
                            output += '\n' + chk_ena
                            if re.search(r'assword:', chk_ena, re.IGNORECASE):
                                # device_type = 'zte_zxros'
                                login_status = {"ios": "ZTE", "status": -4}
                            else:
                                # device_type = 'zte_zxros'
                                login_status = {"ios": "ZTE", "status": 1}
                    elif 'System version' in cmd_out:

                        if enable_password or 'rdcn' in host:
                            output += prompt + 'enable\n'
                            cmd_out = conn.send_command('enable', expect_string=r'assword:|' + REGEX_PROMPT,
                                                        strip_prompt=False, cmd_verify=False)
                            if 'assword:' in cmd_out and 'rdcn' in host:
                                cmd_out = conn.send_command('654321a', expect_string=r'assword:|' + REGEX_PROMPT,
                                                            strip_prompt=False, cmd_verify=False)
                            elif 'assword:' in cmd_out and enable_password:
                                cmd_out = conn.send_command(enable_password, expect_string=r'assword:|' + REGEX_PROMPT,
                                                            strip_prompt=False, cmd_verify=False)
                            if 'assword:' in cmd_out:
                                login_status = {"ios": "DatacomMiniMux", "status": -4}
                            else:
                                output += prompt + 'show manufacturer\n'
                                cmd_out = conn.send_command('show manufacturer', expect_string=REGEX_PROMPT,
                                                            strip_prompt=False, cmd_verify=False)
                                output += cmd_out + '\n'
                                if 'DATACOM' in cmd_out:
                                    login_status = {"ios": "DatacomMiniMux", "status": 1}
                                else:
                                    login_status = {"ios": "Não foi possível identificar", "status": -6}
                        else:
                            login_status = {"ios": "DatacomMiniMux", "status": -4}
                    else:
                        login_status = {"ios": "Não foi possível identificar", "status": -6}
                elif 'Unrecognised' in cmd_out:
                    output += prompt + 'enable\n'
                    conn.send_command('enable', expect_string=REGEX_PROMPT, strip_prompt=False, cmd_verify=False)

                    cmd_out = conn.send_command('terminal length 200', expect_string=REGEX_PROMPT, strip_prompt=False,
                                                cmd_verify=False)
                    output += cmd_out + '\n'
                    # device_type = 'coriant'
                    login_status = {"ios": "Coriant", "status": 1}
                elif 'SHELL PARSER FAILURE' in cmd_out:
                    # device_type = 'ciena_saos'
                    login_status = {"ios": "Ciena", "status": 1}
                else:
                    login_status = {"ios": "Não foi possível identificar", "status": -6}
            elif 'jmp-srv' in host or 'discovery' in host or 'redeip-oper1' in host:
                login_status = {"ios": "Linux", "status": 1}
            else:
                login_status = {"ios": "Não foi possível identificar", "status": -6}

            # redispatch(conn, device_type=device_type)

        except IndexError:
            login_status = {"ios": "Não foi possível identificar", "status": -7}

        except OSError:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'check_ios',
                                             'Jump Server kill the session'))
            login_status = {"ios": "Não foi possível identificar", "status": -7}

        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'check_ios', e))
            login_status = {"ios": "Não foi possível identificar", "status": -7}
        finally:
            login_status['output'] = Format.f_remove_color_codes(output)
            return login_status

    @staticmethod
    def force_logout(conn, cmd='\x03') -> str:
        output = ''
        conn.write_channel(cmd)
        try:
            cmd_out = conn.read_until_pattern(REGEX_PROMPT + r'|telnet>|ogin:|assword:|Bad secrets')
            output += cmd_out + '\n'
            if 'jmp-srv' in cmd_out or 'redeip-oper1' in cmd_out:
                pass
            elif re.search(r'ogin:', cmd_out, re.IGNORECASE):
                conn.write_channel('\x1A')
                cmd_out = conn.read_until_pattern(REGEX_PROMPT)
                output += cmd_out + '\n'
            elif re.search(r'Bad secrets', cmd_out, re.IGNORECASE):
                conn.write_channel('exit\n')
                cmd_out = conn.read_until_pattern(REGEX_PROMPT)
                output += cmd_out + '\n'
            elif re.search(r'telnet>', cmd_out, re.IGNORECASE):
                conn.write_channel('quit\n')
                cmd_out = conn.read_until_pattern(REGEX_PROMPT)
                output += cmd_out + '\n'
        except ReadTimeout:
            try:
                conn.write_channel('\x1b')
                cmd_out = conn.read_until_pattern(r'telnet>|exit telnet|' + REGEX_PROMPT)
                output += cmd_out + '\n'
                if re.search(r'telnet>', cmd_out, re.IGNORECASE):
                    conn.write_channel('quit\n')
                    cmd_out = conn.read_until_pattern(REGEX_PROMPT)
                elif re.search(r'exit telnet', cmd_out, re.IGNORECASE):
                    conn.write_channel('e\n')
                    cmd_out = conn.read_until_pattern(REGEX_PROMPT)
                output += cmd_out + '\n'
            except ReadTimeout:
                conn.write_channel('\x1d')
                cmd_out = conn.read_until_pattern(r'telnet>|exit telnet|' + REGEX_PROMPT)
                output += cmd_out + '\n'
                if re.search(r'telnet>', cmd_out, re.IGNORECASE):
                    conn.write_channel('quit\n')
                    cmd_out = conn.read_until_pattern(REGEX_PROMPT)
                elif re.search(r'exit telnet', cmd_out, re.IGNORECASE):
                    conn.write_channel('e\n')
                    cmd_out = conn.read_until_pattern(REGEX_PROMPT)
                output += cmd_out + '\n'

        return output
