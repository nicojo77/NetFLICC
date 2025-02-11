"""
version:        1.1
thy_modules.py contains mainly 
Its main goal is to associte logo to application identified by NFStream or Zeek.

For each app, a check will be performed in the next order:
1. nologo_list
2. special_slugs
If an application doesn't match either one of the above, the application will be fetch in:
https://simpleicons.org/

In case of no match, the html will show nothing and the logo will need to be manualy created.
"""
import inspect
import logging
import time
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.traceback import install

install(show_locals=False)
console = Console()
logger = logging.getLogger(__name__)


# The next dictionary contains application names that won't match simpleicons database.
# The slugs (application names) are slightly different.
# https://simpleicons.org/
# List of "slugs" can be found here: https://github.com/simple-icons/simple-icons/blob/master/slugs.md
# Note that some applications may share the logo of another application,
# e.g. DataSaver which is an Android application.
special_slugs = {
                'ampproject': 'amp',
                'qq': 'tencentqq',
                'twitter': 'x',
                'alibaba': 'alibabadotcom',
                'goto': 'gotomeeting',
                'datasaver': 'android',
                'forticlient': 'fortinet',
}

# List of logo not found in simpleicons db.
# Some applications may share the same logo: e.g. microsoft and windowsupdate.
nologo_list = [
               'azure',
               'ciscovpn',
               'crashlytics',
               'defaultvpn',
               'icloudprivaterelay',
               'microsoft',
               'playstore',
               'yahoo',
               'disneyplus',
               'edonkey',
               'outlook',
               'skype_teams',
               'xbox',
               'ms_onedrive',
               'windowsupdate', # microsoft.png copy.
               'accuweather',
               'teams',
               'wickr',
               'botim',
               'imo',
               'amazonaws',
]

# The next dictionary.keys() match the applications that are relevant for g4m only.
# The dictionary.values() is the CamelToe name format and matches NFStream results.
# Dictionary should be adapted to match g4m requirements.
# The list is loaded in netflicc.py via newapps.py and is also used in reportGen.py.
apps_of_interest = {
                'botim': 'Botim',
                'imessage': 'iMessage',
                'imo': 'IMO',
                'line': 'Line',
                'signal': 'Signal',
                'snapchat': 'Snapchat',
                'telegram': 'Telegram',
                'viber': 'Viber',
                'whatsapp': 'WhatsApp',
                'wickr': 'Wickr',
}

# The next list is used to exclude protocols and vpns from the standard applications.
exclude_list = [
                'ajp',
                'afp',
                'bgp',
                'cassandra',
                'ciscoskinny',
                'ciscovpn',
                'coap',
                'cybersec',
                'dnp3',
                'dns',
                'dtls',
                'doh_dot',
                'ethernetip',
                'ftp_control',
                'ftp_data',
                'gre',
                'gtp',
                'gtp_c',
                'h323',
                'http',
                'http_proxy',
                'icloudprivaterelay',
                'iec60870',
                'icmp',
                'icmpv6',
                'igmp',
                'imaps',
                'imap',
                'ipsec',
                'kerberos',
                'ldap',
                'memcached',
                'mdns',
                'modbus',
                'mpegdash',
                'mssql-tds',
                'nat-pmp',
                'netbios',
                'nfs',
                'ntp',
                'ocsp',
                'openvpn',
                'oracle',
                'pop3',
                'pops',
                'quic',
                'raknet',
                'rdp',
                'rpc',
                'rsh',
                'rsync',
                'rtcp',
                'rtp',
                'rtmp',
                'rtsp',
                's7comm',
                'smbv23',
                'smtp',
                'smtps',
                'snmp',
                'soap',
                'socks',
                'syslog',
                'sip',
                'ssdp',
                'ssh',
                'stun',
                'targusdataspeed',
                'telnet',
                'tftp',
                'tls',
                'tor',
                'ubntac2',
                'unknown',
                'vnc',
                'wireguard',
                'whois-das',
                'wsd',
                'xdmcp',
                'z3950',
]

# The next functions could be used to debug.
#
# from thy_modules import db
# db()
# or
# debug = [True|False]
# db("this is a test", colour="yellow", title='another', mydebug)
#
# from thy_modules import timer
# @timer
# def main():

def db(msg='👍', colour='orange_red1', title='', debug=True):
    '''Simple debug statement: change debug val to False to disable db
    1.  debug = False; db("something", debug=debug)
    or
    2.  db("something", debug=False)'''
    if debug:
        # Get the current stack frame.
        frame = inspect.currentframe()
        # Get the caller's stack frame.
        caller_frame = frame.f_back
        # Get the filename and line number from the caller's frame.
        filename = caller_frame.f_globals["__file__"]
        filename = filename.split('/')[-1]
        lineno = caller_frame.f_lineno
        # Create the debug message.
        debug_message = f"DEBUGGING {filename} ({lineno})\n{msg}"
        rprint(Panel.fit(debug_message,
                         border_style=colour,
                         title=title,
                         title_align='left'))


def timer(func):
    '''Wrapper function, return a function running time.'''
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed_time = time.perf_counter() - start_time
        minutes = int(elapsed_time / 60)
        sec = int(elapsed_time % 60)
        mils = str(elapsed_time).split('.')[-1][:4]
        console.print(
            f"Function [i][green]{func.__name__!r}[/] took: [cyan]{minutes:02d}:{sec:02d}.{mils}\n",
            style="italic dim")
        logger.info(f"Function {func.__name__!r} took: {minutes:02d}:{sec:02d}.{mils}")
        return result
    return wrapper

