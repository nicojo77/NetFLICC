"""
version:        1.1
Collect information on applications, VPNs, and G4M speicific apps.
"""
import base64
import logging
import os
import re
import shutil
import time
import requests
import pandas as pd
from rich.console import Console
from rich.panel import Panel
from rich.traceback import install
import constants
import thy_modules
from netflicc import Zeeked

install(show_locals=False)
console = Console()
logger = logging.getLogger(__name__)


def sort_unique_names(app_set: set) -> list:
    '''Sort list of names and compound names to get unique names.'''
    application_set = app_set
    previous = None
    single_apps = []
    # The list must be sorted.
    applications = sorted(list(application_set))
    for application in applications:
        if not previous or not application.startswith(previous):
            single_apps.append(application)
            previous = application
    return single_apps


class ApplicationNames():
    '''Collect every application's name with camel-toe format.'''

    def __init__(self, app_name_) -> None:
        '''Dictionary with all lower case applications as keys and camel-toe as values.'''
        self.app_name =app_name_

    def extend_app_name(self, extension):
        '''Update dictionary with new data.'''
        self.app_name.update(extension)
        return self.app_name


class Nfstreamed():
    '''Process data with NFStream.'''

    def __init__(self, nfstreamed_pcap_):
        '''Istantiate dataframe with nfstream.'''
        self.nfstream_df = pd.read_parquet(nfstreamed_pcap_)
        self.app_name = {}


    def get_apps(self) -> None:
        '''Get applications list.'''
        self.applications = self.nfstream_df['application_name'].unique()
        application_set = set()
        exclude_list = thy_modules.exclude_list

        # Differentiate applications from protocols.
        for application in self.applications:
            if len(application.split('.')) > 1: # e.g. DNS.Appple
                application = application.split('.')[-1]
                if application.lower() not in self.app_name:
                    self.app_name[application.lower()] = application
                if application.lower() not in exclude_list:
                    application_set.add(application.lower())
            else:
                if application.lower() not in self.app_name:
                    self.app_name[application.lower()] = application
                if application.lower() not in exclude_list:
                    application_set.add(application.lower())

        self.single_apps = sort_unique_names(application_set)


    def convert_dates(self):
        '''Convert unix timestamp to datetime and to csv'''

        def targetted_column(df: pd.DataFrame, col: str) -> pd.DataFrame:
            '''Convert specific df column to datetime'''
            df[f'{col}'] = pd.to_numeric(df[f'{col}'])
            df[f'{col}'] = pd.to_datetime(df[f'{col}'], unit='ms')
            df[f'{col}'] = df[f'{col}'].dt.tz_localize('UTC').dt.tz_convert('Europe/Zurich')
            return df[f'{col}']

        df = self.nfstream_df
        df['bidirectional_first_seen_ms'] = targetted_column(df, 'bidirectional_first_seen_ms')
        df['bidirectional_last_seen_ms'] = targetted_column(df, 'bidirectional_last_seen_ms')
        df['src2dst_first_seen_ms'] = targetted_column(df, 'src2dst_first_seen_ms')
        df['src2dst_last_seen_ms'] = targetted_column(df, 'src2dst_last_seen_ms')
        df['dst2src_first_seen_ms'] = targetted_column(df, 'dst2src_first_seen_ms')
        df['dst2src_last_seen_ms'] = targetted_column(df, 'dst2src_last_seen_ms')

        df.to_csv('nfstreamed_pcap.csv', index=False)


    def get_vpn_applications(self) -> None:
        '''Parse NFStreamed data for vpn applications.'''
        df = self.nfstream_df[['application_name', 'application_category_name' ]]
        filt = (df['application_category_name'] == 'VPN')
        vpn = df[filt]['application_name'].unique()
        vpn_app_set = set()
        for i in vpn:
            try:
                i = i.split('.')[1]
                vpn_app_set.add(i.lower())
            except IndexError:
                vpn_app_set.add(i.lower())

        self.vpn = sort_unique_names(vpn_app_set)


    def traffic_per_application(self) -> None:
        '''Get amount of traffic per application.'''
        # Get the total of bidirectional bytes (in and out).
        sum_traffic = self.nfstream_df['bidirectional_bytes'].sum()
        # Create table grouped by application and use aggregator like in visidata.
        traffic_df = self.nfstream_df.groupby('application_name')['bidirectional_bytes'].agg(
            counts='count',
            bytes_sum='sum'
        ).reset_index()

        # Rename columns.
        traffic_df.rename(columns={
            'application_name': 'application',
            'counts': 'count',
            'bytes_sum': 'bidirectional_bytes'
        }, inplace=True)

        # Create ratio based on per application bytes and overall bytes.
        # Sort the table based on ratios, from higher to lower.
        traffic_df['ratio_%'] = traffic_df['bidirectional_bytes']\
                                    .apply(lambda x: f"{x * 100 / sum_traffic:.2f}")
        sorted_df = traffic_df.sort_values(by=['ratio_%'], ascending=False)
        sorted_df.to_csv('traffic_per_application.csv', index=False)
        sorted_df.to_excel('traffic_per_application.xlsx', index=False)


class SubZeeked(Zeeked):
    '''Process data with Zeek.'''

    def detect_telegram(self, ipset: set) -> bool:
        '''Get Telegram application in conn.log'''
        df = self.log_df
        df = df[df['id.resp_h'].isin(list(ipset))]
        is_telegram_ip = df['id.resp_h'].unique()
        self.telegram = bool(is_telegram_ip)
        return self.telegram


    def detect_messenger(self) -> bool:
        '''Get Messenger application in x509.log'''
        df = self.log_df
        if not df.empty:
            app = 'Messenger'
            df = df[df['san.dns'].str.contains(app, case=False, na=False)]
            is_messenger = df['san.dns'].unique()
            self.messenger = bool(is_messenger)
        return self.messenger


    def get_apps_subz(self, telegram=False, messenger=False) -> None:
        '''
        Get applications list in dns.log.

        Telegram --> conn.log
        Messenger --> x509.log
        '''
        df = self.log_df
        application_set = set()

        # Parse the dns.log for applications of interest.
        for app in apps_of_interest.keys():
            pattern = rf'(\.{app}\.)'
            filt = df['query'].str.extract(pattern, flags=re.IGNORECASE, expand=False).notnull()
            isapp = df.loc[filt, ['query']]
            # Application found.
            if not isapp.empty:
                application_set.add(app)

        # Add either Telegram or Messenger to the applications list.
        if telegram:
            application_set.add('telegram')
        if messenger:
            application_set.add('messenger')

        # Create a list of unique applications.
        # e.g. WhatsApp.net and WhatsAppChat.net would give whatsapp only.
        self.single_apps = sort_unique_names(application_set)


    def detect_tor(self) -> None:
        '''Compare list of kwown Tor exit nodes against ip in conn.log.'''
        df = self.log_df
        ipsrc = df['id.orig_h']
        ipdst = df['id.resp_h']
        frame = [ipsrc, ipdst]
        df = pd.concat(frame, axis=0).unique()

        dfips_set = set(line.strip() for line in df)

        # Collect TOR nodes on Internet, save TOR IPs into file, load IPs to a set.
        file = 'dan.txt'
        file_copy = constants.DAN_TXT
        url = 'https://www.dan.me.uk/torlist/?full'
        headers = {
            'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)\
            Chrome/58.0.3029.110 Safari/537.3'
        }

        # The minimum waiting time must be 30min, otherwise url blocked.
        creation_time = os.path.getctime(file_copy)
        current_time = time.time()
        diff_time = (current_time - creation_time)

        if diff_time > 21600: # 6 hours.
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    content = response.text
                    with open(file, 'w') as outfile:
                        outfile.write(content)
                    shutil.copy2(file, file_copy)
                else:
                    console.log(Panel.fit(f"Requests status code: {response}", border_style='red'))
                    console.log(Panel.fit(f'Cannot download dan.txt: {url}', border_style='red'))
                    console.log(Panel.fit('Using local copy of dan.txt.', border_style='orange_red1'))
                    logger.error(f"Requests status code: {response}")
                    logger.error(f'Cannot download dan.txt: {url}')
                    logger.info('Using local copy of dan.txt.')
                    shutil.copy2(file_copy, os.getcwd())
            except Exception as exc:
                console.log(Panel.fit(f"{exc}", border_style='orange_red1', title='Exception', title_align='left'))
                logger.exception(f"{exc}")
        else:
            console.log(Panel.fit('dan.txt downloaded in the past 6 hours.\nUsing a local copy.',
                                  border_style='orange_red1'))
            logger.warning('dan.txt downloaded in the past 6 hours. Using a local copy.')
            shutil.copy2(file_copy, os.getcwd())

        try:
            with open(file) as rf:
                torips_set = set(line.strip() for line in rf)
        except FileNotFoundError as exc:
            console.log(f'File {file} not found: {exc}', style='red')
            logger.warning(f'File {file} not found: {exc}')
            return None

        console.log(f'[grey70]TOR nodes comparison list:[/] {len(torips_set)}', style='italic')
        logger.info(f'TOR nodes comparison list: {len(torips_set)}')

        # Verify if TOR nodes in conn.log.
        istor = set.intersection(torips_set, dfips_set)
        self.is_tor = bool(istor)


    def detect_grapheneos(self) -> None:
        '''Get traces of Graphenos in http.log.'''
        if not self.log_df.empty:
            df = self.log_df['host']
            pattern = r'(\.grapheneos\.)'
            filt = df.str.extract(pattern, flags=re.IGNORECASE, expand=False).notnull()
            isgrapheneos = df.loc[filt]
            self.is_grapheneos = not isgrapheneos.empty
        else:
            self.is_grapheneos = False


    # Zeek has more success in finding vpns.
    def detect_vpns(self) -> None:
        '''
        Check if Zeek captured Wireguard or openVPN.

        Wireguard: wireguard.log is created.
        OpenVPN: checked in conn.log['service'].
        '''
        wireguard = 'raw_data/wireguard.log'
        self.is_wireguard = os.path.isfile(wireguard)

        df = self.log_df['service']
        pattern = r'(openvpn)'
        filt = df.str.extract(pattern, flags=re.IGNORECASE, expand=False).notnull()
        isopenvpn = df.loc[filt]
        self.is_openvpn = not isopenvpn.empty


def applications_dataframe(zeek_data_, nfstream_data_) -> pd.DataFrame:
    '''Create dataframe with Zeek and NFStream data.'''

    # Collect every application found in both Zeek and NFStream.
    all_apps = sorted(set(zeek_data_.single_apps).union(set(nfstream_data_.single_apps)))

    # Load non-conventional application slugs.
    special_slugs = thy_modules.special_slugs

    # Create list of image link matching application.
    img_app = []
    for i in all_apps:
        if i in thy_modules.nologo_list:
            logo = png_to_base64(f"/home/anon/Documents/git/pythonScripts/netflicc/app_icons/{i}.png")
            img_app.append(f'''<img height="30" width="30" src='data:image/png;base64,{logo}' alt=''/>''')
        elif i in special_slugs.keys():
            img_app.append(f'''<img height="30" width="30" src="https://cdn.simpleicons.org/{special_slugs[i]}?viewbox=auto"\
                            alt='' onerror="this.style.display='none';"/>''')
        else:
           img_app.append(f'''<img height="30" width="30" src="https://cdn.simpleicons.org/{i}?viewbox=auto"\
                            alt='' onerror="this.style.display='none';"/>''')

    original_names = dictionary_appnames
    final_apps = []
    for i in all_apps:
        try:
            if i in original_names:
                final_apps.append(original_names.get(i))
            else:
                final_apps.append(i)
        except Exception as exc:
            console.log(Panel.fit(f"{exc}", border_style='red'))

    # Create df with extra comparison column which contains comparable application names.
    # 'comparison' will serve as basis to G4M and NFStream columns, but eventually removed.
    df = pd.DataFrame({'Apps': img_app, 'Applications': final_apps, 'comparison': all_apps})

    # Apply tick marks to matching applications with Zeek or NFStream.
    df['G4M'] = df['comparison'].apply(lambda x: '✔' if x in zeek_data_.single_apps else '')
    df['NFStream'] = df['comparison'].apply(lambda x: '✔' if x in nfstream_data_.single_apps else '')
    df.drop(['comparison'], axis=1, inplace=True)
    return df


def privacy_applications_dataframe(nfs_vpn_,
                                   zeek_tor_: bool,
                                   zeek_grapheneos_: bool,
                                   zeek_wireguard_: bool,
                                   zeek_openvpn_: bool) -> pd.DataFrame:
    '''Create dataframe with Zeek and NFStream vpn data.'''
    zeek_vpn_data = []
    if zeek_grapheneos_:
        zeek_vpn_data.append('grapheneos')
    if zeek_wireguard_:
        zeek_vpn_data.append('wireguard')
    if zeek_openvpn_:
        zeek_vpn_data.append('openvpn')
    if zeek_tor_:
        zeek_vpn_data.append('tor')

    # Ensure data is lowercase.
    nfsvpn = [i.lower() for i in nfs_vpn_]
    zeek_vpn_data = [i.lower() for i in zeek_vpn_data]

    all_vpns = sorted(set(nfsvpn).union(set(zeek_vpn_data)))
    img_app = []
    for i in all_vpns:
        if i in thy_modules.nologo_list:
            logo = png_to_base64(f"/home/anon/Documents/git/pythonScripts/netflicc/app_icons/{i}.png")
            img_app.append(f'''<img height="30" width="30" src='data:image/png;base64,{logo}'\
                        alt='' onerror="this.onerror=null; this.src='data:image/png;base64,{vpnlogo}';"/>''')
        elif i == 'tor':
            img_app.append('''<img height="30" width="30" src="https://cdn.simpleicons.org/torproject?viewbox=auto"\
                        alt='' onerror="this.style.display='none';"/>''')
        else:
            img_app.append(f'''<img height="30" width="30" src="https://cdn.simpleicons.org/{i}?viewbox=auto"\
                        alt='' onerror="this.onerror=null; this.src='data:image/png;base64,{vpnlogo}';"/>''')

    final_apps = []
    for i in all_vpns:
        try:
            if i in dictionary_appnames:
                final_apps.append(dictionary_appnames[i])
            else:
                final_apps.append(i)
        except Exception as exc:
            console.log(Panel.fit(f"{exc}", border_style='red'))
            logger.exception(f"{exc}")

    # Create df with extra comparison column which contains comparable application names.
    vpndf = pd.DataFrame({'Apps': img_app, 'VPNs': final_apps, 'comparison': all_vpns})

    # Apply tick marks to matching applications with Zeek or NFStream.
    vpndf['Zeek'] = vpndf['comparison'].apply(lambda x: '✔' if x in zeek_vpn_data else '')
    vpndf['NFStream'] = vpndf['comparison'].apply(lambda x: '✔' if x in nfsvpn else '')
    vpndf.drop(['comparison'], axis=1, inplace=True)
    return vpndf


def png_to_base64(png_file_: str) -> str:
    '''Convert png to base64.'''
    with open(png_file_, 'rb') as image_file:
        png_base64 = base64.b64encode(image_file.read()).decode('utf-8')
    return png_base64

# Create default vpn logo in case vpn not found in simpleicons database.
vpnlogo = png_to_base64('/home/anon/Documents/git/pythonScripts/netflicc/app_icons/defaultvpn.png')

# nfstream_file is created in importXP.py.
nfstream_file = 'raw_data/nfstreamed_pcap.parquet'

apps_of_interest = thy_modules.apps_of_interest
apps_of_interest_list = set(apps_of_interest.values())

def main(conn_data_) -> tuple[pd.DataFrame, pd.DataFrame, set[str]]:
    '''
    Script launcher.

    Returns:
    applications_df: pd.DataFrame
    vpn_df: pd.DataFrame
    apps_of_interest_list: set[str]
    '''
    with console.status("[bold italic green]Processing newapps.py ...[/]") as _:
        # Process NFStream data for applications.
        nfs_data = Nfstreamed(nfstream_file)
        nfs_data.get_apps()
        nfs_data.convert_dates()
        nfs_data.traffic_per_application()

        # Process Zeek data for Telegram application.
        console.log("checking Telegram...", style="italic yellow")
        conn_data = conn_data_
        conn_data.detect_telegram('ips.txt')

        # Process Zeek data for overall applications.
        console.log("checking applications...", style="italic yellow")
        dns_data = SubZeeked('raw_data/dns.log')
        dns_data.get_apps_subz(conn_data.telegram)

        # Check for vpn or other privacy protection means.
        console.log("checking vpns...", style="italic yellow")
        nfs_data.get_vpn_applications()
        http_data = SubZeeked('raw_data/http.log')
        http_data.detect_grapheneos()
        conn_data.detect_tor()
        conn_data.detect_vpns()

        # Create dictionary with {'appname': 'app_name'} naming convention.
        global dictionary_appnames
        dictionary_appnames = ApplicationNames(nfs_data.app_name)
        dictionary_appnames = dictionary_appnames.extend_app_name(apps_of_interest)

        # Build "Applications" and "Privacy Protection Means" dataframes.
        applications_df = applications_dataframe(dns_data, nfs_data)
        vpn_df = privacy_applications_dataframe(nfs_data.vpn,
                                                conn_data.is_tor,
                                                http_data.is_grapheneos,
                                                conn_data.is_wireguard,
                                                conn_data.is_openvpn)

        logger.info(f"module {__name__} done")
        return applications_df, vpn_df, apps_of_interest_list


if __name__ == "__main__":
    pass
