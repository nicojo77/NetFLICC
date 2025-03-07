"""
version:        1.1
Collect information about case, user, pcap_metadata and user-agents.
"""
import glob as gb
import linecache
import logging
import os
import re
import sys
import pandas as pd
import numpy as np
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.traceback import install

install(show_locals=False)
console = Console()
logger = logging.getLogger(__name__)


# Define user-agent attributes.
class UserAgent:
    '''
    Class user-agent.
    Get counts, firstseen and lastseen for each user-agent.
    '''
    def __init__(self, counts, firstseen, lastseen):
        self.counts = counts
        self.first_seen = firstseen
        self.last_seen = lastseen

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


def get_user_agent() -> pd.DataFrame:
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
        df['user_agent'].astype(str)
        for useragent in df['user_agent'].values:
            filt = (df['user_agent'] == useragent)
            fdate = df[filt]['ts'].min() # first seen.
            fdate = fdate.strftime('%d.%m.%Y')
            ldate = df[filt]['ts'].max() # last seen.
            ldate = ldate.strftime('%d.%m.%Y')
            counts = df[filt]['user_agent'].value_counts()[0] # counts.

            # Assign values to the user-agent.
            processed_ua = UserAgent(counts, fdate, ldate)

            # Build the dictionary.
            if processed_ua in useragents_dic:
                pass
            else:
                useragents_dic[useragent] = processed_ua

        # Create new dataframe for final output.
        # useragents_dic needs formatting as each of its key represents a 'user_agent' with
        # a unique value which is an instance of class UserAgent.
        # Original headers renamed for better readability in report.
        data = []
        for useragent, useragent_val in useragents_dic.items():
            data.append({
                'User-agent': useragent,
                'Counts': useragent_val.counts,
                'First seen': useragent_val.first_seen,
                'Last seen': useragent_val.last_seen
            })

        df = pd.DataFrame(data)
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


def main(http_log=False) -> tuple[list, str|pd.DataFrame]:
    '''Script launcher.'''
    with console.status("[bold italic green]Processing meta_uAgent.py ...[/]") as _:
        console.log("collecting metadata...", style="italic yellow")
        pcap_data = pcap_metadata()
        console.log("checking user-agents...", style="italic yellow")
        uadf = ''
        try:
            if http_log:
                http_df = get_user_agent() # Return user-agents dataframe.
                uadf = create_useragent_dataframe(http_df)
            else:
                uadf = pd.DataFrame()
        except Exception as exc:
            console.print_exception(show_locals=True)
            logger.exception(f'An error occured: {exc}')

    logger.info(f"module {__name__} done")
    return pcap_data, uadf

if __name__ == "__main__":
    pass
