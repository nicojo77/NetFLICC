"""
version:        1.1
Get web history from http.log.
"""
import glob as gb
import linecache
import logging
import sys
import pandas as pd
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.traceback import install

install(show_locals=False)
console = Console()
logger = logging.getLogger(__name__)

def logfile_to_dataframe(log) -> pd.DataFrame:
    '''Convert ZEEK log file to dataframe.'''
    # Get line 7 which has headers.
    zeek_log = gb.glob(f'*/{log}')[0]
    # zeek_log = gb.glob(f'*/*/{log}')[0]
    log_headers = linecache.getline(zeek_log, 7).split('\x09')
    # Security check, line must start with #fields.
    if not log_headers.pop(0) == '#fields':
        rprint(Panel.fit("⛔ Headers not found, verify log file.", border_style='red'))
        sys.exit(9)

    # Load dataframe with headers.
    df = pd.read_csv(zeek_log, skiprows=8, sep='\x09', names=log_headers, low_memory=False)
    # Remove last line (#close).
    df.drop(index=df.index[-1], axis=0, inplace=True)

    # Adjust time format and allow datetime parsing.
    df['ts'] = pd.to_numeric(df['ts'])
    df['ts'] = pd.to_datetime(df['ts'], unit='s')
    # Convert to 'Europe/Zurich' time zone
    df['ts'] = df['ts'].dt.tz_localize('UTC').dt.tz_convert('Europe/Zurich')
    return df


class Request:
    '''Instantiate counters per protocols.'''
    def __init__(self):
        self.counts = 0
        self.http_counts = 0
        self.ssl_counts = 0
        self.dns_counts = 0

    def add_http(self):
        '''http counter.'''
        self.counts += 1
        self.http_counts += 1

    def add_ssl(self):
        '''ssl counter.'''
        self.counts += 1
        self.ssl_counts += 1

    def add_dns(self):
        '''dns counter.'''
        self.counts += 1
        self.dns_counts += 1


def browsing_activity() -> pd.DataFrame:
    '''Get http event from http.log and ssl.log.'''
    http_df = logfile_to_dataframe('http.log')
    ssl_df = logfile_to_dataframe('ssl.log')
    dns_df = logfile_to_dataframe('dns.log')

    request_dic = {}
    def get_web_requests(dataframe: pd.DataFrame, field: str):
        '''
        Get requests according to 'field' which differs uppon zeek logfile.
        http.log -> host field
        ssl.log -> server_name field
        dns.log -> query field
        '''
        for request in dataframe[field]:
            if request != '-': # garbage
                if field == 'host':
                    if request not in request_dic:
                        processed_request = Request()
                        request_dic[request] = processed_request
                        request_dic[request].add_http()
                    else:
                        request_dic[request].add_http()
                elif field == 'server_name':
                    if request not in request_dic:
                        processed_request = Request()
                        request_dic[request] = processed_request
                        request_dic[request].add_ssl()
                    else:
                        request_dic[request].add_ssl()

                elif field == 'query':
                    if request not in request_dic:
                        processed_request = Request()
                        request_dic[request] = processed_request
                        request_dic[request].add_dns()
                    else:
                        request_dic[request].add_dns()

                else:
                    print("webhis.py - error: unknown field")

    get_web_requests(http_df, 'host')
    get_web_requests(ssl_df, 'server_name')
    get_web_requests(dns_df, 'query')

    data = []
    for request, request_val in request_dic.items():
        data.append({
            'Requests': request,
            'HTTP': request_val.http_counts,
            'SSL': request_val.ssl_counts,
            'DNS': request_val.dns_counts,
            'Counts': request_val.counts
        })

    request_df = pd.DataFrame(data)
    request_df.sort_values(['Counts'], ascending=False, inplace=True)
    # Create a local copy, useful for investigators.
    request_df.to_csv('web_history.csv', index=False)
    request_df.to_excel('web_history.xlsx', index=False)

    return request_df


def main() -> pd.DataFrame:
    '''
    Script launcher.

    Returns: pd.DataFrame
    '''
    with console.status("[bold italic green]Processing webhis.py ...[/]") as _:
        console.log("[i]web history...[/]", style="yellow")
        dataframe = browsing_activity()

    logger.info(f"module {__name__} done")
    return dataframe


if __name__ == "__main__":
    pass
