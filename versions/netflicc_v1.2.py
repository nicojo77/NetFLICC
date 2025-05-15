#!/usr/bin/env python3
"""
script:         netflicc.py
author:         IFC3/joni
date:           12.04.2024
modification:   13.05.2025
version:        1.2

NetFLICC.py main goal is to simplify the process of analysing data from FLICC
and to provide report for the investigator.

Requirements:
▻ ref requirements.txt
▻ zeek with Wireguard package (stun optional)

exit codes:
0   normal exit
1   directory not empty, user quit
2   user_name wrong format, too many attempts
3   KeyboardInterrupt
4   integrity_checks, conn.log doesn't exist
9   errors in sub_modules
"""
import glob as gb
import linecache
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from argparse import ArgumentParser, RawTextHelpFormatter
from textwrap import dedent
import pandas as pd
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.traceback import install
import questionary
from questionary import Style
import logger_config
import activity
import celloc
import ftree
import geoip_v2
import gsma
import importXP
import meta_uAgent
import newapps
import reportGen
import shift
import thy_constants
import webhis
from thy_modules import timer

install(show_locals=False)
console = Console()
interrupt_event = threading.Event()
logger = logging.getLogger(__name__)
INTERRUPT_RECEIVED = False
CTRLC_RICHCONFIRM = False

# Bypass the need to enter manually data and path to pcap at prompt.
TESTING = False 
# Here you can copy path(s) to testing exports, simply un-comment testing one.
# EXPORTS_PATH = f'{thy_constants.TEST_PATH}/small/'
# EXPORTS_PATH = f'{thy_constants.TEST_PATH}/medium/'
# EXPORTS_PATH = f'{thy_constants.TEST_PATH}/another_file/'
# EXPORTS_PATH = f'/media/anon/tora_256GB/dueffe/md/iosua_tel/'
EXPORTS_PATH = f'/media/anon/tora_256GB/dueffe/ctm/'

# Change True to False to prevent opening default browser.
BROWSER = True

def start_timer() -> float:
    '''
    Starts NetFLICC timer.

    Returns:
    start_time: float
    '''
    start_time = time.perf_counter()
    return start_time


def stop_timer(start_time_: float) -> None:
    '''Stops NetFLICC timer.'''
    elapsed_time = time.perf_counter() - start_time_
    minutes = int(elapsed_time / 60)
    sec = int(elapsed_time % 60)
    mils = str(elapsed_time).split('.')[-1][:4]
    console.log(
        f"NetFLICC processing completed in: [cyan]{minutes:02d}:{sec:02d}.{mils}\n",
        style="bold italic green")
    logger.info(f"NetFLICC processing completed in: {minutes:02d}:{sec:02d}.{mils}")


class Zeeked():
    '''Process data with Zeek.'''

    def __init__(self, zeek_logfile):
        '''Format zeek logfile for being loaded into Pandas.'''

        if os.path.isfile(zeek_logfile):
            log_headers = linecache.getline(zeek_logfile, 7).split('\x09')
            if not log_headers.pop(0) == '#fields':
                console.log(Panel.fit(f"Error processing {zeek_logfile}", border_style='red'))
                logger.error(f"Error processing {zeek_logfile}")
                self.log_df = pd.DataFrame()
                return
            df = pd.read_csv(zeek_logfile,
                             skiprows=8,
                             sep='\x09',
                             names=log_headers,
                             low_memory=False)
            df.drop(index=df.index[-1], axis=0, inplace=True)

            # Adjust time format and allow datetime parsing.
            df['ts'] = pd.to_numeric(df['ts'])
            df['ts'] = pd.to_datetime(df['ts'], unit='s')
            # Convert to 'Europe/Zurich' time zone
            df['ts'] = df['ts'].dt.tz_localize('UTC').dt.tz_convert('Europe/Zurich')

            self.log_df = df
        else:
            # console.log(Panel.fit(f"File {zeek_logfile} does not exist",
            #                       border_style='orange_red1',
            #                       title='WARNING',
            #                       title_align='left'))
            logger.warning(f"Zeeked Class: file {zeek_logfile} does not exist")
            self.log_df = pd.DataFrame()

        # INFO: could be removed as both apps are not G4M compatible.
        # Initialise Telegram and Messenger attributes.
        # self.telegram = False
        # self.messenger = False


def intro_message() -> None:
    '''Introduction message'''
    intro_msg = '''\
        Welcome to NetFLICC.py.

        Requirements:
        ▻ FLICC export data

        Upon fulfillment, the next processes will take place:
        ▻ copying exports into current location
        ▻ merging pcaps with mergecap
        ▻ processing pcaps with zeek
        ▻ parsing logs
        ▻ creating plots and maps
        ▻ creating report'''

    rprint(Panel(dedent(intro_msg),
                 border_style="yellow",
                 title="NetFLICC.py",
                 title_align="left"))

    # Check that no file exists in launching directory.
    curdir = os.getcwd()
    try:
        items_dir = os.listdir(curdir)
        if len(items_dir) > 0:
            warning_msg = dedent('''\
                The current directory is not empty.
                Continuing will irremediably erase everything!''')
            rprint(Panel.fit(warning_msg,
                             border_style='red',
                             title='[italic] WARNING[/]',
                             title_align='left',
                             style='red'))
            continue_cleanup = questionary.confirm("Continue? (yes)", qmark='').unsafe_ask()
            if continue_cleanup:
                logger.warning(f"Current directory not empty; continue: {continue_cleanup}")
                cleanup()
            else:
                sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(3)


# Questionary styling.
custom_style = Style([
    # ('qmark', 'fg:#673ab7 bold'),       # token in front of the question
    # ('question', 'bold'),               # question text
    # ('answer', 'fg:#f44336 bold'),      # submitted answer text behind the question
    ('pointer', 'fg:#f8b301 bold'),     # pointer used in select and checkbox prompts
    ('highlighted', 'fg:#f8b301 bold'), # pointed-at choice in select and checkbox prompts
    # ('selected', 'fg:#cc5454'),         # style for a selected item of a checkbox
    # ('separator', 'fg:#cc5454'),        # separator in lists
    # ('instruction', ''),                # user instructions for select, rawselect, checkbox
    ('text', 'fg:#f8b301'),                       # plain text
    # ('disabled', 'fg:#858585 italic')   # disabled choices for select and checkbox prompts
])


def case_metadata_collection():
    '''Collect case related information'''
    global INTERRUPT_RECEIVED
    operation_name = None
    user = None
    exports_path = None

    if TESTING:
        operation_name = 'test'
        user = 'lambda'
        exports_path = EXPORTS_PATH
        console.log(Panel.fit(f"[black on red]Testing with: {exports_path}[/]"))
        logger.info(f"Testing with: {exports_path}")

    else:
        try:
            here = os.getcwd()
            is_operation_name = os.path.basename(here)
            if questionary.confirm(
                f"Is operation name {is_operation_name}? (yes)", qmark='').unsafe_ask():
                operation_name = is_operation_name.upper()
            else:
                operation_name = questionary.text(
                    "Enter operation name:", qmark='').unsafe_ask().upper()
            logger.info(f"operation name: {operation_name}")

            counter = 0
            user = ''
            while counter < 3:
                user = questionary.text(
                    "Enter user abbreviation:", qmark='').unsafe_ask().lower()

                col = ['white', 'orange_red1', 'red']
                if not user.isalpha() or (len(user) < 3 or len(user) > 4):
                    print()
                    rprint(Panel.fit("Only 3 or 4 letters accepted!",
                                    border_style=f'{col[counter]}',
                                    subtitle=f"{counter + 1}/3",
                                    subtitle_align='right',
                                    padding=1))
                    logger.warning(f"User abbreviation not valid: {user}")
                    counter += 1
                else:
                    break
            logger.info(f"user: {user}")

            if counter == 3:
                rprint(Panel.fit("🤯 Too many wrong attempts!",
                                border_style="red",
                                title="[white italic]ByeBye[/]",
                                title_align="left",
                                padding=1))
                logger.error("User abbreviation: too many wrong attempts")
                sys.exit(2)

            exports_path = questionary.path("Enter path to exports: ", qmark='').unsafe_ask()
            logger.info(f"export path: {exports_path}")

        except KeyboardInterrupt:
            INTERRUPT_RECEIVED = True

        if INTERRUPT_RECEIVED:
            console.log(Panel.fit("User exit, cleaning up....",
                                  border_style='orange_red1',
                                  title=' ',
                                  title_align='left'))
            cleanup()
            console.log(Panel.fit(" Cleanup done.", style='green'))
            sys.exit(3)

    return operation_name, user, exports_path


def integrity_checks() -> tuple[str, bool, bool]:
    '''
    Verify that pcap and specific log files exist.

    Returns:
    pcap: str
    http_log: bool
    ssl_log: bool
    '''
    # Mandatory to continue otherwise exits.
    pcap = None
    try:
        pcap = gb.glob('*/*.pcap')[0]
    except IndexError:
        console.log(Panel.fit('pcap does not exist!', border_style='orange_red1'))
        logger.error('pcap does not exist')
        sys.exit(9)

    conn_log = os.path.exists('raw_data/conn.log')
    if not conn_log:
        console.log('conn.log does not exist!', style='red')
        logger.error('conn.log does not exist')
        console.log(Panel.fit("netflicc.py cleanup()",
                              border_style='orange_red1',
                              title=' ',
                              title_align='left'))
        logger.info("netflicc.py cleanup()")
        cleanup()
        sys.exit(4)

    # Non-mandatory log files.
    dns_log = os.path.exists('raw_data/dns.log')
    if not dns_log:
        console.log('dns.log does not exist!', style='italic orange_red1')
        logger.warning('dns.log does not exist')

    http_log = os.path.exists('raw_data/http.log')
    if not http_log:
        console.log('http.log does not exist!', style='italic orange_red1')
        logger.warning('http.log does not exist')

    ssl_log = os.path.exists('raw_data/ssl.log')
    if not ssl_log:
        console.log('ssl.log does not exist!', style='italic orange_red1')
        logger.warning('ssl.log does not exist')

    sip_log = os.path.exists('raw_data/sip.log')
    if not sip_log:
        console.log('sip.log does not exist!', style='italic orange_red1')
        logger.warning('sip.log does not exist')

    return pcap, http_log, ssl_log


def cleanup() -> None:
    '''Clean exit.'''
    curdir = os.getcwd()
    items = list(os.scandir(curdir))
    [shutil.rmtree(i.path, ignore_errors=True) if i.is_dir() else os.remove(i.path) for i in items]
    time.sleep(1.5)


def signal_handler(sig, frame) -> None:
    '''Handle ctrl-c.'''
    if interrupt_event.is_set():
        return
    interrupt_event.set()
    cleanup()
    sys.exit(3)


def move_log() -> None:
    '''Move netflicc.log which was created in /tmp.'''
    log = "/tmp/netflicc.log"
    current_dir = os.getcwd()
    try:
        shutil.move(log, current_dir)
    except Exception as e:
        logger.exception(e)


@timer
def main() -> None:
    '''
    Script launcher.
     DO NOT MODIFY THE LAUNCHING ORDER.
    '''
    signal.signal(signal.SIGINT, signal_handler)
    # global interrupt_event
    try:
        intro_message()
        print()
        console.rule("[green][i]Answer the next questions to continue[/]", align='center')
        operation_name, user, exports_path = case_metadata_collection()

        print()
        start_time = start_timer()
        case_meta = importXP.main(exports_path, interrupt_event)

        # Verify that zeek log files exist, boolean.
        pcap, http_log, ssl_log = integrity_checks()

        pcap_data, user_agent_df = meta_uAgent.main(case_meta.target_identifier, http_log)

        imeidf, gsmadf, iridf, msisdndf = gsma.main(pcap, case_meta.target_identifier)

        activity.main(http_log, ssl_log)

        # shift.py is only used if http.log or ssl_log exist.
        try:
            if http_log or ssl_log:
                shift.main()
        except Exception as exc:
            console.log(f"An error occured: {exc}", style='red')
            logger.exception(exc)

        # webhis.py is only used if http.log exists.
        urldf = ''
        try:
            if http_log:
                urldf = webhis.main()
            # Create an empty dataframe.
            else:
                urldf = pd.DataFrame()
        except Exception as exc:
            console.log(f"An error occured: {exc}", style='red')
            logger.exception(exc)

        ipmapfile, orig_ip, resp_ip = geoip_v2.main()

        cell_map_file = None
        cell_tower_df = None
        if iridf.empty:
            cell_tower_df = pd.DataFrame()
        else:
            try:
                cell_map_file, cell_tower_df = celloc.main()
            except Exception as exc:
                console.log(f"Error processing celloc.main(): {exc}", style='red')
                logger.exception(exc)

        # Gets conn_data dataframe via class Zeeked over SubZeeked.
        conn_data = newapps.SubZeeked('raw_data/conn.log')

        apps_list = None
        applications_df = None

        vpns_df = None
        try:
            applications_df, vpns_df, apps_list = newapps.main(conn_data)
        except Exception as exc:
            console.log(f"Error in newapps.py: {exc}", style='red')
            logger.exception(exc)

        try:
            reportGen.main(case_meta,
                           operation_name,
                           user,
                           pcap_data,
                           user_agent_df,
                           imeidf,
                           gsmadf,
                           msisdndf,
                           urldf,
                           apps_list,
                           ipmapfile,
                           orig_ip,
                           resp_ip,
                           cell_map_file,
                           cell_tower_df,
                           applications_df,
                           vpns_df)

        except Exception as exc:
            console.log(f"Error in reportGen.py: {exc}", style='red')
            logger.exception(exc)


        # Check if report exists.
        isreport = False
        report = './report.html'

        if os.path.isfile(report):
            isreport = True
            console.log(Panel.fit("report.html successfully created.", border_style='cyan'))
            logger.info(f"{report} successfully created.")
        else:
            console.log(Panel.fit("report.html not created.", border_style='orange_red1'))
            logger.info(f"{report} not created.")

        try:
            ftree.main()
        except Exception as exc:
            console.log(Panel.fit(f"Error: {exc}", border_style='orange_red1'))
            logger.exception(exc)


        if BROWSER:
            try:
                if isreport:
                    subprocess.run(
                        ['google-chrome', '--disable-breakpad', './report/report.html'],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=True)
                    logger.info("opening ./report/report.html in browser")

            except FileNotFoundError as err:
                console.log(Panel.fit(f"Error: {err}", border_style='orange_red1'))
                logger.error(err)
        else:
            console.log(
                Panel.fit(
                    "[black on red]Opening report in web browser disabled for testing purpose[/]"))
            logger.warning("Opening report in web browser disabled for testing purpose")

    except Exception as exc:
        console.print_exception(show_locals=True)
        logger.exception(exc)

    finally:
        if interrupt_event.is_set():
            console.log(Panel.fit(" Cleanup done.", style='orange_red1'))

    stop_timer(start_time)
    move_log()


if __name__ == "__main__":
    parMessage = dedent('''\
                        NetFLICC.py takes care of
                        ▻ fetching exports files in external drive;
                        ▻ unzipping;
                        ▻ merging;
                        ▻ parsing pcap;
                        ▻ analysing data;
                        ▻ creating plots and maps;
                        ▻ reporting.
                        ''')

    parser = ArgumentParser(description=parMessage, formatter_class=RawTextHelpFormatter)
    parser.usage = "NetFLICC.py does not take any argument."
    args = parser.parse_args()
    main()
    sys.exit(0)
