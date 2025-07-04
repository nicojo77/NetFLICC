"""
version:        1.2
Collect information about case, user, pcap_metadata and user-agents.
"""
import linecache
import logging
import os
import re
import subprocess
import sys
import glob as gb
import pandas as pd
import numpy as np
from datetime import datetime
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.traceback import install

install(show_locals=False)
console = Console()
logger = logging.getLogger(__name__)

tid_is_ch = False # tid is a Swiss phone number.
tid_is_imei = False # tid is IMEI number.

class UserAgent:
    '''
    Get source, counts, firstseen and lastseen for each user-agent.
    '''
    def __init__(self, source, sip_date):
        self.source = source
        self.counts = 1
        self.first_seen = sip_date
        self.last_seen = sip_date

    def increment_count(self):
        '''Counter for instance UserAgent.'''
        self.counts += 1


def logfile_to_dataframe(log) -> pd.DataFrame:
    '''Format zeek log files to Pandas dataframe'''
    # Get line 7 which has headers.
    http_log = gb.glob(f'*/{log}')[0]
    log_headers = linecache.getline(http_log, 7).split('\x09')
    # Security check, line must start with #fields.
    if not log_headers.pop(0) == '#fields':
        rprint(Panel.fit("⛔ Headers not found, verify log file.", border_style='red'))
        sys.exit(9)

    # Load dataframe with headers.
    df = pd.read_csv(http_log, skiprows=8, sep='\x09', names=log_headers, low_memory=False)
    # Remove last line (#close).
    df.drop(index=df.index[-1], axis=0, inplace=True)

    # Adjust time format and allow datetime parsing.
    df['ts'] = pd.to_numeric(df['ts'])
    df['ts'] = pd.to_datetime(df['ts'], unit='s')
    # Convert to 'Europe/Zurich' time zone
    df['ts'] = df['ts'].dt.tz_localize('UTC').dt.tz_convert('Europe/Zurich')
    return df


def pcap_metadata() -> list:
    '''Get pcap metadata: pcap, dates and period.'''
    pcap_path = gb.glob('*/*.pcap')[0]
    name_pcap = os.path.basename(pcap_path)

    meta_df = logfile_to_dataframe('conn.log')
    meta_df.reset_index(inplace=True)
    meta_df['ts'] = pd.to_datetime(meta_df['ts'])

    first_pcap = meta_df['ts'].min()
    last_pcap = meta_df['ts'].max()
    span = last_pcap - first_pcap
    span = str(span)
    period = span.split('.', maxsplit=1)[0]

    pcap_data = [name_pcap, first_pcap, last_pcap, period]
    return pcap_data


def get_http_data() -> pd.DataFrame:
    '''
    Adaptation of logfile_to_dataframe().
    Take care of square brackets [] to prevent false results.
    '''
    http_log = gb.glob('*/http.log')[0]

    # Get log file and prepare headers.
    headers = linecache.getline(http_log, 7).split('\x09')
    if not headers.pop(0) == '#fields':
        console.log(Panel.fit("Headers not found, verify log file.",
                              border_style='red'))
        sys.exit(9)

    # load dataframe with headers.
    http_df = pd.read_csv(http_log, skiprows=8, sep='\x09', names=headers, low_memory=False)
    # Remove last line (#close and NaN).
    http_df.drop(index=http_df.index[-1], axis=0, inplace=True)

    # Adjust time format and allow datetime parsing.
    http_df['ts'] = pd.to_numeric(http_df['ts'])
    http_df['ts'] = pd.to_datetime(http_df['ts'], unit='s')
    # Convert to 'Europe/Zurich' time zone
    http_df['ts'] = http_df['ts'].dt.tz_localize('UTC').dt.tz_convert('Europe/Zurich')
    return http_df


# Calculate imei check-digit regarding Luhn's formula.
def luhn(imei: str) -> str:
    '''
    Returns IMEI check-digit as string.
    checkdigit: str
    '''
    num_list = []
    for i in range(14):
        if i % 2 == 0:
            num_list.append(int(imei[i]))
        else:
            num_list.append(int(imei[i]) * 2)

    # Add every single numerical value.
    sum_singles = 0
    for num in num_list:
        num = str(num)
        for single in num:
            single = int(single)
            sum_singles += single

    # Round to upper decimal.
    sum_rounded_up = ((sum_singles // 10) + 1) * 10

    # Calculate check-digit.
    checkdigit = sum_rounded_up -sum_singles
    # Slicing prevents str(10) being returned.
    checkdigit = str(checkdigit)[-1]

    return checkdigit


def determine_tid_type_type(tid) -> None:
    '''Determine the target identifier format, msisdn or imei.'''
    # IDX is set to Target Identifier TID to differentiate the origin.
    global idx
    global is_imei
    global tid_is_ch
    global tid_is_imei

    if tid[0] != '+' and len(tid) == 15:
        tid_is_imei = True
        is_imei = True
    else:
        if tid[1:2] == '41':
            tid_is_ch = True

def create_useragent_dataframe(df_: pd.DataFrame) -> pd.DataFrame:
    '''
    Create user-agents dataframe.
    Create a dictionary of user-agents.
    Get unique values of user_agent,
    Get first and last time seen as well as counts.
    User_agent value must be str, nan values are float.
    '''
    http_df = df_

    # Replace [] by () to prevent dropping values.
    http_df['user_agent'] = http_df['user_agent'].str.replace('[', '(')
    http_df['user_agent'] = http_df['user_agent'].str.replace(']', ')')

    # Copy initial http_df to separate dfs.
    http_full_df = http_df.copy()
    http_filtered_df = http_df.copy()

    # Filtering.
    pattern = r'(apple(?!\.trust)|chrome|iphone|android|.?os)'
    filt = http_filtered_df['user_agent'].str.extract(
            pattern, flags=re.IGNORECASE, expand=False).notnull()
    http_filtered_df['user_agent'] = http_filtered_df[filt]['user_agent']

    # pd.options.mode.use_inf_as_na=True
    http_filtered_df['user_agent'] = http_filtered_df['user_agent'].replace('', np.nan)
    http_filtered_df.dropna(subset=['user_agent'], axis=0, how='any', inplace=True)

    def sub_useragent_dataframe(sub_df):
        '''Process individual data.'''
        df = sub_df # Prevent some bad assignement.
        useragents_dic = {}
        for useragent in df['user_agent'].values:
            filt = (df['user_agent'] == useragent)
            fseen = df[filt]['ts'].min()
            lseen = df[filt]['ts'].max()

            # Known user-agent, increment count and adapt dates.
            if useragent in useragents_dic:
                useragents_dic[useragent].increment_count()
                if fseen < useragents_dic[useragent].first_seen:
                    useragents_dic[useragent].first_seen = fseen
                if lseen > useragents_dic[useragent].last_seen:
                    useragents_dic[useragent].last_seen = lseen
            # Unknow user-agent.
            else:
                ua = UserAgent('HTTP', fseen)
                useragents_dic[useragent] = ua

        # Create new dataframe for final output.
        # useragents_dic needs formatting as each of its key represents a 'user_agent' with
        # a unique value which is an instance of class UserAgent.
        # Original headers renamed for better readability in report.
        data = []
        for useragent, useragent_val in useragents_dic.items():
            data.append({
                'User-agent': useragent,
                'Source': useragent_val.source,
                'Counts': useragent_val.counts,
                'First seen': useragent_val.first_seen,
                'Last seen': useragent_val.last_seen
            })

        df = pd.DataFrame(data)
        df['First seen'] = df['First seen'].apply(lambda x: x.strftime('%d.%m.%Y'))
        df['Last seen'] = df['Last seen'].apply(lambda x: x.strftime('%d.%m.%Y'))
        df.sort_values(['Counts'], ascending=False, inplace=True)
        return df

    # Get full list of user-agents.
    try:
        ua_full_df = sub_useragent_dataframe(http_full_df)
        ua_full_df.to_csv('user_agents_full.csv', index=False)
    except Exception as exc:
        console.log(Panel.fit(f"Error while creating full user-agent df: {exc}",
                              border_style='orange_red1'))
        logger.exception(f"Error while creating full user-agent df: {exc}")
        ua_full_df = pd.DataFrame()

    # Get filtered list of user-agents.
    try:
        ua_filtered_df = sub_useragent_dataframe(http_filtered_df)
        ua_filtered_df.to_csv('user_agents_filt.csv', index=False)
    except Exception as exc:
        console.log(Panel.fit(f"Error while creating filtered user-agent df: {exc}",
                              border_style='orange_red1'))
        logger.exception(f"Error while creating filtered user-agent df: {exc}")
        ua_filtered_df = pd.DataFrame()

    if ua_filtered_df.empty and ua_full_df.empty:
        console.log(Panel.fit("No user-agent found", border_style='orange_red1'))
        logger.warning("No user-agent found")
        return pd.DataFrame()
    if ua_filtered_df.empty:
        console.log(Panel.fit("Using full list of user-agents", border_style='cyan'))
        logger.info("Using full list of user-agents")
        return ua_full_df
    console.log(Panel.fit("Using filtered list of user-agents", border_style='cyan'))
    logger.info("Using filtered list of user-agents")
    return ua_filtered_df


def get_sip_useragent(tid_: str) -> pd.DataFrame:
    '''Parse pcap with ngrep for SIP user-agents.'''
    pcap_file = gb.glob('*/*.pcap')[0]
    subscriber_number = tid_[1:]

    if tid_is_ch:
        # First process: ngrep for phone number.
        p1 = subprocess.Popen(['ngrep', '-I', pcap_file, '-W', 'single', '-ti',
                            fr'(?<=P-Asserted-Identity: (<sip|<tel):\+){subscriber_number}'],
                            stdout=subprocess.PIPE)

        # Second process: grep -Piv, searches SIP answers and invert match.
        p2 = subprocess.Popen(['grep', '-Piv', r'(SIP/2.0\s+[1-6]\d{2}\s+)(\w+)(\s)?(\w+)(\.\.)'],
                            stdin=p1.stdout, stdout=subprocess.PIPE)

        # Third process: grep -Pi, searches SIP requests where tid is the originator, i.e. From.
        p3 = subprocess.Popen(['grep', '-Pi', rf'(?<=From: (<sip|<tel):\+){subscriber_number}'],
                            stdin=p2.stdout, stdout=subprocess.PIPE)

        # Fourth process: filetering out Multimedia Telephony Application Server MTAS.
        mtas = '(mtas|tas|as|zte|sbc|volte|wfc|proxy|acme|application|server|oracle|packet|broadworks|mavenir|ocsbc|ims-tas)'
        p4 = subprocess.Popen(['grep', '-Piv', fr'(\.\.user-agent:)(.*?)(\s){mtas}(\s)?(.*?)(?=\.\.)'],
                        stdin=p3.stdout, stdout=subprocess.PIPE)

        output, _ = p4.communicate()

    # TID is foreign number.
    else:
        # First process: ngrep for phone number.
        p1 = subprocess.Popen(['ngrep', '-I', pcap_file, '-W', 'single', '-ti',
                            fr'(?<=subscribe (sip|tel):\+){subscriber_number}'],
                            stdout=subprocess.PIPE)

        # Third process: grep -Pi, searches SIP requests where tid is the originator, i.e. From.
        p2 = subprocess.Popen(['grep', '-Pi', rf'(?<=From: (<sip|<tel):\+){subscriber_number}'],
                            stdin=p1.stdout, stdout=subprocess.PIPE)

        # Fourth process: filetering out Multimedia Telephony Application Server MTAS.
        mtas = '(mtas|tas|as|zte|sbc|volte|wfc|proxy|acme|application|server|oracle|packet|broadworks|mavenir|ocsbc|ims-tas)'
        p3 = subprocess.Popen(['grep', '-Piv', fr'(\.\.user-agent:)(.*?)(\s){mtas}(\s)?(.*?)(?=\.\.)'],
                        stdin=p2.stdout, stdout=subprocess.PIPE)

        output, _ = p3.communicate()

    # TID is imei number.
    if tid_is_imei:
        imei_num = tid_[:14]
        tac = imei_num[:8]
        sn = imei_num[8:14]
        imei_formatted = f"{tac}-{sn}"

        # First process: ngrep for SIP SUBSCRIBE Method..
        p1 = subprocess.Popen(['ngrep', '-I', pcap_file, '-W', 'single', '-ti', fr'[^\s{2}]subscribe'],
                            stdout=subprocess.PIPE)

        # Third process: grep -Pi, searches SIP Contact IMEI.
        p2 = subprocess.Popen(['grep', '-Pi', rf'(?<=sip\.instance="<urn:gsma:imei:){imei_formatted}'],
                            stdin=p1.stdout, stdout=subprocess.PIPE)

        # Fourth process: filetering out Multimedia Telephony Application Server MTAS.
        mtas = '(mtas|tas|as|zte|sbc|volte|wfc|proxy|acme|application|server|oracle|packet|broadworks|mavenir|ocsbc|ims-tas)'
        p3 = subprocess.Popen(['grep', '-Piv', fr'(\.\.user-agent:)(.*?)(\s){mtas}(\s)?(.*?)(?=\.\.)'],
                        stdin=p2.stdout, stdout=subprocess.PIPE)

        output, _ = p3.communicate()

    # Decode subprocess output (binary) to text.
    decoded_output = output.decode('utf-8')
    undef_blocks = re.split('\n', decoded_output)

    # Take into account only blocks starting with UDP, TCP and undefined ?.
    # You can check it with a for loop and start_pattern = r'^.{1}(?=\s{1})'
    sip_blocks = []
    for block in undef_blocks:
        if block.startswith(('T', 'U', '?')):
            sip_blocks.append(block)

    # If no data found, returns an empty dataframe.
    if not sip_blocks:
        df = pd.DataFrame()
        return df

    # Create a user-agent dictionary.
    ua_dic = {}
    for block in sip_blocks:
        ua_pattern = r'(?<=User-Agent:\s)(.*?)(?=\.\.)'
        re.compile(ua_pattern, flags=re.IGNORECASE)
        ua = re.findall(ua_pattern, block)

        if ua:
            date_pattern = r'\d{4}/\d{2}/\d{2}'
            re.compile(date_pattern, flags=0)
            sip_date = re.findall(date_pattern, block)
            sip_date = datetime.strptime(sip_date[-1], '%Y/%m/%d').date()
            useragent = ua[-1]

            # Known user-agent, increment count and adapt dates.
            if useragent in ua_dic:
                ua_dic[useragent].increment_count()
                if sip_date < ua_dic[useragent].first_seen:
                    ua_dic[useragent].first_seen = sip_date
                if sip_date > ua_dic[useragent].last_seen:
                    ua_dic[useragent].last_seen = sip_date

            # Unknown user-agent.
            else:
                newua = UserAgent('SIP', sip_date)
                ua_dic[useragent] = newua

    # Create the data structure.
    data = []
    for useragent, useragent_val in ua_dic.items():
        data.append({
            'User-agent': useragent,
            'Source': useragent_val.source,
            'Counts': useragent_val.counts,
            'First seen': useragent_val.first_seen,
            'Last seen': useragent_val.last_seen
        })

    # Create the dataframe if data exists and format time.
    if data:
        df = pd.DataFrame(data)
        df['First seen'] = df['First seen'].apply(lambda x: x.strftime('%d.%m.%Y'))
        df['Last seen'] = df['Last seen'].apply(lambda x: x.strftime('%d.%m.%Y'))
        df.sort_values(['Counts'], ascending=False, inplace=True)
    else:
        df = pd.DataFrame()

    return df

def main(tid, http_log=False) -> tuple[list, str|pd.DataFrame]:
    '''Script launcher.'''
    with console.status("[bold italic green]Processing meta_uAgent.py ...[/]") as _:
        # Create an empty dataframe for user-agents.
        httpuadf = pd.DataFrame()

        console.log("collecting metadata...", style="italic yellow")
        pcap_data = pcap_metadata()
        console.log("checking user-agents...", style="italic yellow")
        try:
            if http_log:
                http_df = get_http_data() # Return user-agents dataframe.
                httpuadf = create_useragent_dataframe(http_df)
        except Exception as exc:
            console.print_exception(show_locals=True)
            logger.exception(f'An error occured: {exc}')

        determine_tid_type_type(tid)
        sipuadf = get_sip_useragent(tid)

        if httpuadf.empty and sipuadf.empty:
            uadf = pd.DataFrame()
        else:
            frame = [httpuadf, sipuadf]
            uadf = pd.concat(frame, axis=0).reset_index(drop=True)
            uadf = uadf.sort_values(by=['Source', 'Counts'], ascending=[True, False])
            uadf.to_csv('user_agents.csv', index=False)

    logger.info(f"module {__name__} done")
    return pcap_data, uadf

if __name__ == "__main__":
    pass
