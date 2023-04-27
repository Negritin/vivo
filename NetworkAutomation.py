from netvivo.Login import Login
from netvivo.eqp_models.Ceragon import Ceragon
from netvivo.eqp_models.Ciena import Ciena
from netvivo.eqp_models.BrocadeICX import BrocadeICX
from netvivo.eqp_models.BrocadeVDX import BrocadeVDX
from netvivo.eqp_models.CiscoXE import CiscoXE
from netvivo.eqp_models.CiscoNX import CiscoNX
from netvivo.eqp_models.CiscoXR import CiscoXR
from netvivo.eqp_models.Coriant import Coriant
from netvivo.eqp_models.Datacom import Datacom
from netvivo.eqp_models.DatacomDmOS import DatacomDmOS
from netvivo.eqp_models.DatacomDM2500 import DatacomDM2500
from netvivo.eqp_models.DatacomMiniMux import DatacomMiniMux
from netvivo.eqp_models.Fortinet import Fortinet
from netvivo.eqp_models.Huawei import Huawei
from netvivo.eqp_models.HP import HP
from netvivo.eqp_models.H3C import H3C
from netvivo.eqp_models.HuaweiSmartAX import HuaweiSmartAX
from netvivo.eqp_models.HuaweiVrpV8 import HuaweiVrpV8
from netvivo.eqp_models.Juniper import Juniper
from netvivo.eqp_models.Linux import Linux
from netvivo.eqp_models.TP5000 import TP5000
from netvivo.eqp_models.TP4100 import TP4100
from netvivo.eqp_models.Nokia import Nokia
from netvivo.eqp_models.Siae import Siae
from netvivo.eqp_models.ZTE import ZTE
from pathlib import Path

import logging
import logging.config
import os
import re

logger = logging.getLogger('main')


class NetworkAutomation:
    def __init__(self, username=None, password=None, server=None, port=22, read_timeout=None, banner_timeout=None,
                 blocking_timeout=None, debug=False):

        try:
            os.mkdir('./logs')
        except FileExistsError:
            pass

        log_dict = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'default': {
                    'format': '%(asctime)s %(levelname)s:%(message)s',
                },
            },
            'handlers': {
                'login': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/Login.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'main': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/Main.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'brocade_icx': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/BrocadeICX.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'brocade_vdx': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/BrocadeVDX.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'ceragon': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/Ceragon.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'ciena': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/Ciena.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'cisco_xe': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/CiscoXE.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'cisco_nx': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/CiscoNX.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'cisco_xr': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/CiscoXR.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'coriant': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/Coriant.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'datacom': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/Datacom.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'datacom_dmos': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/DatacomDmOS.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'datacom_mini_mux': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/DatacomMiniMux.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'datacom_dm_2500': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/DatacomDM2500.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'fortinet': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/Fortinet.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'h3c': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/H3C.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'hp': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/HP.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'huawei': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/Huawei.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'huawei_smart': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/HuaweiSmartAX.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'huawei_vrp': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/HuaweiVrpV8.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'juniper': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/Juniper.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'linux': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/Linux.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'nokia': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/Nokia.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'tp4100': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/TP4100.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'tp5000': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/TP5000.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'zte': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/ZTE.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
                'siae': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/Siae.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5,
                },
            },
            'loggers': {
                'login': {
                    'level': 'DEBUG',
                    'handlers': ['login'],
                    'propagate': False,
                },
                'main': {
                    'level': 'DEBUG',
                    'handlers': ['main'],
                    'propagate': False,
                },
                'brocade_icx': {
                    'level': 'DEBUG',
                    'handlers': ['brocade_icx'],
                    'propagate': False,
                },
                'brocade_vdx': {
                    'level': 'DEBUG',
                    'handlers': ['brocade_vdx'],
                    'propagate': False,
                },
                'ceragon': {
                    'level': 'DEBUG',
                    'handlers': ['ceragon'],
                    'propagate': False,
                },
                'ciena': {
                    'level': 'DEBUG',
                    'handlers': ['ciena'],
                    'propagate': False,
                },
                'cisco_xe': {
                    'level': 'DEBUG',
                    'handlers': ['cisco_xe'],
                    'propagate': False,
                },
                'cisco_nx': {
                    'level': 'DEBUG',
                    'handlers': ['cisco_nx'],
                    'propagate': False,
                },
                'cisco_xr': {
                    'level': 'DEBUG',
                    'handlers': ['cisco_xr'],
                    'propagate': False,
                },
                'coriant': {
                    'level': 'DEBUG',
                    'handlers': ['coriant'],
                    'propagate': False,
                },
                'datacom': {
                    'level': 'DEBUG',
                    'handlers': ['datacom'],
                    'propagate': False,
                },
                'datacom_dmos': {
                    'level': 'DEBUG',
                    'handlers': ['datacom_dmos'],
                    'propagate': False,
                },
                'datacom_mini_mux': {
                    'level': 'DEBUG',
                    'handlers': ['datacom_mini_mux'],
                    'propagate': False,
                },
                'datacom_dm_2500': {
                    'level': 'DEBUG',
                    'handlers': ['datacom_dm_2500'],
                    'propagate': False,
                },
                'fortinet': {
                    'level': 'DEBUG',
                    'handlers': ['fortinet'],
                    'propagate': False,
                },
                'h3c': {
                    'level': 'DEBUG',
                    'handlers': ['h3c'],
                    'propagate': False,
                },
                'hp': {
                    'level': 'DEBUG',
                    'handlers': ['hp'],
                    'propagate': False,
                },
                'huawei': {
                    'level': 'DEBUG',
                    'handlers': ['huawei'],
                    'propagate': False,
                },
                'huawei_smart': {
                    'level': 'DEBUG',
                    'handlers': ['huawei_smart'],
                    'propagate': False,
                },
                'huawei_vrp': {
                    'level': 'DEBUG',
                    'handlers': ['huawei_vrp'],
                    'propagate': False,
                },
                'linux': {
                    'level': 'DEBUG',
                    'handlers': ['linux'],
                    'propagate': False,
                },
                'juniper': {
                    'level': 'DEBUG',
                    'handlers': ['juniper'],
                    'propagate': False,
                },
                'nokia': {
                    'level': 'DEBUG',
                    'handlers': ['nokia'],
                    'propagate': False,
                },
                'tp4100': {
                    'level': 'DEBUG',
                    'handlers': ['tp4100'],
                    'propagate': False,
                },
                'tp5000': {
                    'level': 'DEBUG',
                    'handlers': ['tp5000'],
                    'propagate': False,
                },
                'zte': {
                    'level': 'DEBUG',
                    'handlers': ['zte'],
                    'propagate': False,
                },
                'siae': {
                    'level': 'DEBUG',
                    'handlers': ['siae'],
                    'propagate': False,
                },
            },
        }

        if debug:
            handlers_debug = {
                'console': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': './logs/Console.log',
                    'formatter': 'default',
                    'maxBytes': 1024000,
                    'backupCount': 5
                }
            }
            loggers_debug = {
                '': {
                    'level': 'DEBUG',
                    'handlers': ['console']
                }
            }
            log_dict.get('handlers').update(handlers_debug)
            log_dict.get('loggers').update(loggers_debug)

        logging.config.dictConfig(log_dict)

        self.conn = Login.jump_server(username, password, server, port, read_timeout, banner_timeout, blocking_timeout)

    def disconnect(self):
        try:
            # Logout from jump server
            Login.jump_server_logout(self.conn)
            return True
        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'disconnect', e))
            return False

    def configure(self, host, usr, pwd, config, ssh=None, log_commands=None, local_users=None):

        logs_ini = None
        config_ini = None
        logs_fim = None
        config_fim = None
        config_status = {"output": None, "config_status": None, "conn_status": None}
        output = ''

        try:
            # Login on Jump Server
            server_prompt = self.conn.find_prompt()
            Login.check_ios(self.conn, server_prompt)

            login = Login.eqp_login_from_linux(self.conn, host, usr, pwd, ssh, local_users)
            output += '\n' + login.get('output')
            if login.get('status') == 1:

                if log_commands is not None:
                    logs_ini = eval(login.get('ios')).get_logs(self.conn, )
                    config_ini = eval(login.get('ios')).get_config(self.conn)
                config_status = eval(login.get('ios')).configure(self.conn, config)
                if config_status.get('conn_status') == 1:
                    if log_commands is not None:
                        logs_fim = eval(login.get('ios')).get_logs(self.conn, )
                        config_fim = eval(login.get('ios')).get_config(self.conn)

                    # Logout from equipment
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -3 or login.get('status') == -4:
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -6 or login.get('status') == -7:
                prompt = self.conn.find_prompt()
                if prompt != server_prompt:
                    log = Login.eqp_logout(self.conn)
                    output += '\n' + log.get('output')
        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'configure', e))
        finally:
            return {'logs_ini': logs_ini, 'config_ini': config_ini, 'config': config_status.get('output'),
                    'logs_fim': logs_fim, 'config_fim': config_fim, 'config_status': config_status.get('config_status'),
                    'conn_status': config_status.get('conn_status')}

    def save_config(self, host, usr, pwd, ssh=None, local_users=None):

        config_saved = None
        output = ''

        try:
            # Login on Jump Server
            server_prompt = self.conn.find_prompt()
            Login.check_ios(self.conn, server_prompt)

            login = Login.eqp_login_from_linux(self.conn, host, usr, pwd, ssh, local_users)
            output += '\n' + login.get('output')
            if login.get('status') == 1:

                config_saved = eval(login.get('ios')).save_config(self.conn)
                output += config_saved.get('output')

                # Logout from equipment
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -3 or login.get('status') == -4:
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -6 or login.get('status') == -7:
                prompt = self.conn.find_prompt()
                if prompt != server_prompt:
                    log = Login.eqp_logout(self.conn)
                    output += '\n' + log.get('output')
        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'save_config', e))
        finally:
            return {'protocol': login.get('protocol'), 'config_saved': config_saved.get('status')}

    def get_eqp_brief_info(self, host, usr, pwd, ssh=None, local_users=None):

        hostname = None
        ios = None
        vendor = None
        model = None
        protocol = None
        access = None
        gateway = None
        firmware = None
        interface = None
        status = None
        local_password = None
        output = ''
        info = {'hostname': hostname, 'ios': ios, 'vendor': vendor, 'model': model, 'protocol': protocol,
                'access': access, 'gateway': gateway, 'firmware': firmware, 'interface': interface,
                'status': status, 'local_password': local_password, 'output': output}

        try:
            # Login on Jump Server
            server_prompt = self.conn.find_prompt()
            Login.check_ios(self.conn, server_prompt)

            login = Login.eqp_login_from_linux(self.conn, host, usr, pwd, ssh, local_users)
            status = login.get('status')
            output += '\n' + login.get('output')
            if login.get('status') == 1:
                local_password = login.get('local_password')

                eqp_info = eval(login.get('ios')).get_eqp_model(self.conn)
                output += '\n' + eqp_info.get('output')

                login_int_info = eval(login.get('ios')).get_ip_int(self.conn, host)
                interface = login_int_info.get('interface')
                output += '\n' + login_int_info.get('output')

                gateway_info = eval(login.get('ios')).get_eqp_gateway(self.conn)
                gateway = gateway_info.get("gateway")
                output += '\n' + gateway_info.get('output')

                firmware_info = eval(login.get('ios')).get_eqp_firmware(self.conn)
                firmware = firmware_info.get("firmware")
                output += '\n' + firmware_info.get('output')

                if login.get('ios') == 'Ceragon':
                    hostname = eval(login.get('ios')).get_hostname(self.conn).get("hostname")
                else:
                    hostname = login.get('hostname')

                ios = login.get('ios')
                vendor = eqp_info.get('vendor')
                model = eqp_info.get('model')
                protocol = login.get('protocol')
                access = login.get('access')

                # Logout from equipment
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == 0 and login.get('hostname') is not None:
                hostname = login.get('hostname')
                ios = login.get('ios')
                protocol = login.get('protocol')
                access = login.get('access')
            elif login.get('status') == -3 or login.get('status') == -4:
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -6 or login.get('status') == -7:
                prompt = self.conn.find_prompt()
                if prompt != server_prompt:
                    log = Login.eqp_logout(self.conn)
                    output += '\n' + log.get('output')
            info = {'hostname': hostname, 'ios': ios, 'vendor': vendor, 'model': model, 'protocol': protocol,
                    'access': access, 'gateway': gateway, 'firmware': firmware, 'interface': interface,
                    'status': status, 'local_password': local_password, 'output': output}
        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'get_eqp_brief_info', e))
        finally:
            return info

    def get_ptp_clock_id(self, host, usr, pwd, ssh=None, local_users=None):

        local_clock_id = None
        local_clock_id_profile = None
        parent_clock_id = None
        gm_clock_id_1 = None
        gm_clock_id_1_profile = None
        gm_clock_id_2 = None
        gm_clock_id_2_profile = None
        output = ''
        info = {'local_clock_id': local_clock_id, 'local_clock_id_profile': local_clock_id_profile,
                'parent_clock_id': parent_clock_id, 'gm_clock_id_1': gm_clock_id_1,
                'gm_clock_id_1_profile': gm_clock_id_1_profile, 'gm_clock_id_2': gm_clock_id_2,
                'gm_clock_id_2_profile': gm_clock_id_2_profile
                }

        try:
            # Login on Jump Server
            server_prompt = self.conn.find_prompt()
            Login.check_ios(self.conn, server_prompt)

            login = Login.eqp_login_from_linux(self.conn, host, usr, pwd, ssh, local_users)
            output += '\n' + login.get('output')
            if login.get('status') == 1:
                eqp_info = eval(login.get('ios')).get_ptp_clock_id(self.conn)

                local_clock_id = eqp_info.get('local_clock_id')
                local_clock_id_profile = eqp_info.get('local_clock_id_profile')
                parent_clock_id = eqp_info.get('parent_clock_id')
                gm_clock_id_1 = eqp_info.get('gm_clock_id_1')
                gm_clock_id_1_profile = eqp_info.get('gm_clock_id_1_profile')
                gm_clock_id_2 = eqp_info.get('gm_clock_id_2')
                gm_clock_id_2_profile = eqp_info.get('gm_clock_id_2_profile')

                # Logout from equipment
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -3 or login.get('status') == -4:
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -6 or login.get('status') == -7:
                prompt = self.conn.find_prompt()
                if prompt != server_prompt:
                    log = Login.eqp_logout(self.conn)
                    output += '\n' + log.get('output')
            info = {'local_clock_id': local_clock_id, 'local_clock_id_profile': local_clock_id_profile,
                    'parent_clock_id': parent_clock_id, 'gm_clock_id_1': gm_clock_id_1,
                    'gm_clock_id_1_profile': gm_clock_id_1_profile, 'gm_clock_id_2': gm_clock_id_2,
                    'gm_clock_id_2_profile': gm_clock_id_2_profile
                    }
        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'get_ptp_clock_id', e))
        finally:
            return info

    def check_allow_ssh(self, host, usr, pwd, ssh=None, local_users=None, ip='200.204.1.4'):

        policy_type = None
        policy_name = None
        next_entry = None
        control_plane = None
        output = ''
        info = {'policy_type': policy_type, 'policy_name': policy_name, 'next_entry': next_entry,
                'control_plane': control_plane}

        try:
            # Login on Jump Server
            server_prompt = self.conn.find_prompt()
            Login.check_ios(self.conn, server_prompt)

            login = Login.eqp_login_from_linux(self.conn, host, usr, pwd, ssh, local_users)
            output += '\n' + login.get('output')
            if login.get('status') == 1:
                eqp_info = eval(login.get('ios')).check_allow_ssh(self.conn, ip)

                policy_type = eqp_info.get('type')
                policy_name = eqp_info.get('name')
                next_entry = eqp_info.get('next_entry')
                control_plane = eqp_info.get('control_plane')

                # Logout from equipment
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -3 or login.get('status') == -4:
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -6 or login.get('status') == -7:
                prompt = self.conn.find_prompt()
                if prompt != server_prompt:
                    log = Login.eqp_logout(self.conn)
                    output += '\n' + log.get('output')
            info = {'policy_type': policy_type, 'policy_name': policy_name, 'next_entry': next_entry,
                    'control_plane': control_plane}
        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'check_ssh_allow_type', e))
        finally:
            return info

    def get_logs_jm(self, host, usr, pwd, ssh=None, local_users=None):

        config = None
        logs = None
        output = ''
        info = {'config': config, 'logs': logs, 'output': output}

        try:
            # Login on Jump Server
            server_prompt = self.conn.find_prompt()
            Login.check_ios(self.conn, server_prompt)

            login = Login.eqp_login_from_linux(self.conn, host, usr, pwd, ssh, local_users)
            output += '\n' + login.get('output')
            if login.get('status') == 1:

                config = eval(login.get('ios')).get_config(self.conn)
                logs = eval(login.get('ios')).get_logs_jm(self.conn)

                # Logout from equipment
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -3 or login.get('status') == -4:
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -6 or login.get('status') == -7:
                prompt = self.conn.find_prompt()
                if prompt != server_prompt:
                    log = Login.eqp_logout(self.conn)
                    output += '\n' + log.get('output')
            info = {'config': config, 'logs': logs, 'output': output}
        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'get_logs_jm', e))
        finally:
            return info

    def get_flash_size(self, host, usr, pwd, ssh=None, local_users=None):

        output = ''
        flash = []
        info = {'output': output, 'flash': flash}

        try:
            # Login on Jump Server
            server_prompt = self.conn.find_prompt()
            Login.check_ios(self.conn, server_prompt)

            login = Login.eqp_login_from_linux(self.conn, host, usr, pwd, ssh, local_users)
            output += '\n' + login.get('output')
            if login.get('status') == 1:

                ret = eval(login.get('ios')).get_flash_size(self.conn)
                flash = ret.get('flash')
                # Logout from equipment
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -3 or login.get('status') == -4:
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -6 or login.get('status') == -7:
                prompt = self.conn.find_prompt()
                if prompt != server_prompt:
                    log = Login.eqp_logout(self.conn)
                    output += '\n' + log.get('output')

            info = {'output': output, 'flash': flash}
        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'get_flash_size', e))
        finally:
            return info

    def exemple(self, host, usr, pwd, ssh=None, local_users=None):

        output = ''
        info = {'output': output}

        try:
            # Login on Jump Server
            server_prompt = self.conn.find_prompt()
            Login.check_ios(self.conn, server_prompt)

            login = Login.eqp_login_from_linux(self.conn, host, usr, pwd, ssh, local_users)
            output += '\n' + login.get('output')
            if login.get('status') == 1:

                # Logout from equipment
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -3 or login.get('status') == -4:
                log = Login.eqp_logout(self.conn, login.get('ios'))
                output += '\n' + log.get('output')
            elif login.get('status') == -6 or login.get('status') == -7:
                prompt = self.conn.find_prompt()
                if prompt != server_prompt:
                    log = Login.eqp_logout(self.conn)
                    output += '\n' + log.get('output')
            info = {'output': output}
        except Exception as e:
            logger.error('{}: {}: {}'.format(Path(__file__).stem, 'exemple', e))
        finally:
            return info
