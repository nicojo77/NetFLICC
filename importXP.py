"""
version:        1.1
▻ check USB 
▻ copy, unzip and remove zip
▻ find and merge pcaps
▻ find iri file
▻ find target info file
▻ return metadata
"""
import csv
import concurrent.futures
import glob as gb
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from typing import List
from nfstream import NFStreamer
from rich.console import Console
from rich.panel import Panel
from rich.traceback import install

install(show_locals=False)
console = Console()
logger = logging.getLogger(__name__)

def start_timer() -> None:
    '''Timer function: start.'''
    global start_time
    start_time = time.perf_counter()


def stop_timer() -> None:
    '''Timer function: stop.'''
    stop_time = time.perf_counter()
    elapsed_time = stop_time - start_time
    min_time = elapsed_time / 60
    sec = elapsed_time % 60
    console.print(
        f"\nElapsed time: {int(min_time):02d}:{int(sec):02d} ({round(elapsed_time)})",
        style="italic dim")


lap = 0
def lap_timer() -> float:
    '''Timer function: lap time.'''
    global lap
    if lap == 0:
        lp = time.perf_counter()
        lap = lp - start_time
        return round(lap)

    lp = time.perf_counter()
    nlap = lp - (lap + start_time)
    lap = nlap +lap
    return round(nlap)


def path_to_zips(exports_path: str) -> None:
    '''Verify exports exist and copy zif files to current directory.'''
    # USB not plugged.
    if not os.path.exists(exports_path):
        console.log(Panel.fit("zip files not found or USB stick not plugged!", border_style='red'))
        sys.exit(9)
    else:
        # USB plugged, seek zip files and copy to disk..
        for _, _, files in os.walk(exports_path):
            for file in files:
                if file.endswith('.zip'):
                    root_dir = exports_path
                    export_zip = f"{root_dir}/{file}"
                    shutil.copy(export_zip, os.getcwd())
                    console.log(f"'{file}' copied ({lap_timer()})", style="green")
                    logger.info(f"'{file}' copied ({lap_timer()})")


zips = []
unzipped = []
def get_zip_files(curdir: str) -> tuple[list, list]:
    '''
        Find every zip files and save in zips [].
        Remove extension of zips and saved in unzipped [],
        for usage in in netflicc.py.
    '''
    for root, _, files in os.walk(curdir):
        for file in files:
            if file.endswith('.zip'):
                zips.append(os.path.join(root, file))
                unzipped.append(os.path.join(root, os.path.splitext(file)[0]))
    return zips, unzipped


def unzip_file(zip_file: str, interrupt_event) -> None:
    '''Process of unzipping zip files.'''
    if interrupt_event.is_set():
        console.log(Panel.fit(f"Skipping {zip_file} due to interrupt", border_style='yellow'))
        return

    extract_dir = os.path.splitext(zip_file)[0]

    try:
        with zipfile.ZipFile(zip_file, 'r') as myzip:
            file_list = myzip.infolist()
            for file_info in file_list:
                if interrupt_event.is_set():
                    status.stop()
                    return
                myzip.extract(file_info, extract_dir)

        zip_name = os.path.basename(zip_file)
        console.log(f"'{zip_name}' unzipped", style="green")
        logger.info(f"'{zip_name}' unzipped")

    except Exception as exc:
        console.log(Panel.fit(f"Error unzipping {zip_file}: {exc}", border_style='yellow'))
        logger.exception(f"Error unzipping {zip_file}: {exc}")


def multi_task_unzip(interrupt_event) -> None:
    '''Unzip every zip files simultaneously.'''
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(
            unzip_file, zip_file, interrupt_event): zip_file for zip_file in zips}
        try:
            for future in concurrent.futures.as_completed(futures):
                if interrupt_event.is_set():
                    console.log(Panel.fit("Interrupt detected, cancelling tasks...",
                                          border_style='yellow'))
                    executor.shutdown(wait=False)
                    break
                future.result()
        except Exception as exc:
            console.log(Panel.fit(f"Error during unzipping: {exc}", border_style='yellow'))
            logger.exception(f"Error during unzipping: {exc}")


def rmspace(curdir: str) -> None:
    '''
    Check for spaces and replace with '-'.
    Limits errors.
    '''
    for root, dirs, files in os.walk(curdir):
        # Modify files.
        for file in files:
            os.rename(os.path.join(root, file), os.path.join(root, file.replace(' ', '-')))

        # Modify directories.
        for i in range(len(dirs)):
            new_name = dirs[i].replace(' ', '-')
            os.rename(os.path.join(root, dirs[i]), os.path.join(root, new_name))
            dirs[i] = new_name


def remove_zips(zip_file: str) -> None:
    '''
    Process of removing zip files.
    Takes zips list from get_zip_files().
    '''
    os.remove(zip_file)
    zip_name = os.path.basename(zip_file)
    console.log(f"'{zip_name}' removed ({lap_timer()})", style="green")
    logger.info(f"'{zip_name}' removed ({lap_timer()})")


def multi_task_rmzips() -> None:
    '''
    Remove zips files simultaneously.
    Allow to spare space as pcaps could be big.
    '''
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(remove_zips, zips)


def get_products() -> list[str]: # Called in find_pcaps_in_products().
    '''Find products directories.'''
    products_list = []
    sub_dir = gb.glob('*/*/*')
    # Take only dirs into account(products).
    for item in sub_dir:
        if os.path.isdir(item):
            products_list.append(item)
    products_list = sorted(products_list)
    return products_list

# Called in find_pcaps_in_products().
def find_pcaps(product_folder: str) -> list:
    '''Find pcaps per products.'''
    # products = {}
    pcaps = []

    for root, _, files in os.walk(product_folder):
        for f in files:
            if f.endswith('.pcap'):
                pcaps.append(os.path.join(root, f))

    return pcaps


def get_pcap_files_size(pcaps: List[str]) -> int:
    '''
    Calculate size of each pcap file.
    Returns: total_size: int
    '''
    total_size = 0
    for pcap in pcaps:
        total_size += os.path.getsize(pcap)
    return total_size


def find_pcaps_in_products() -> None:
    '''
    Group pcaps by product.
    Call get_products() and find_pcaps().
    '''
    global pcaps_dict
    pcaps_dict = {}
    global pcap_size
    pcap_size = 0
    for product in get_products():
        product: str
        basename = os.path.basename(product)
        pcaps = find_pcaps(product)
        console.log(f'''Product: [grey70]'{product.split('/')[0]}'[/] n_pcaps: {len(pcaps)}''',
                    style="purple")
        logger.info(f'''Product: '{product.split('/')[0]}' n_pcaps: {len(pcaps)}''')

        sz = get_pcap_files_size(pcaps)
        pcap_size += sz

        if basename in pcaps_dict:
            pcaps_dict[basename].extend(pcaps)
        else:
            pcaps_dict[basename] = pcaps

    global pcaps_dictSorted
    pcaps_dictSorted = dict(sorted(pcaps_dict.items()))
    [console.log(f"LIID: [grey70]'{key}'[/] n_pcaps: {len(val)}", style="orange_red1")
        for key, val in pcaps_dictSorted.items()]
    [logger.info(f"LIID: '{key}' n_pcaps: {len(val)}")
        for key, val in pcaps_dictSorted.items()]

    if pcap_size <= 1024:
        console.log(Panel.fit(f"Size of pcaps: {pcap_size} bytes (gzip)", border_style='cyan'))
        logger.info(f"Size of pcaps: {pcap_size} bytes (gzip)")
    elif pcap_size <= 1047527424:
        pcap_size = (pcap_size / 1024**2)
        console.log(Panel.fit(f"Size of pcaps: {pcap_size:.2f} Mb (gzip)", border_style='cyan'))
        logger.info(f"Size of pcaps: {pcap_size:.2f} Mb (gzip)")
    else:
        pcap_size = (pcap_size / 1024**3)
        console.log(Panel.fit(f"Size of pcaps: {pcap_size:.2f} GB (gzip)", border_style='cyan'))
        logger.info(f"Size of pcaps: {pcap_size:.2f} GB (gzip)")


class Case():
    def __init__(self, parent_id, liid, interception_type, target_identifier,
                 target_type, is_confidential, order_date, activation_date,
                 interception_start_date, interception_end_date, provider_name,
                 authority_name, prosecutor_name, prosecutor_reference, merged_pcap_sz):
        self.parent_id = parent_id
        self.liid = liid
        self.interception_type = interception_type
        self.target_identifier = target_identifier
        self.target_type = target_type
        self.is_confidential = is_confidential
        self.order_date = order_date
        self.activation_date = activation_date
        self.interception_start_date = interception_start_date
        self.interception_end_date = interception_end_date
        self.provider_name = provider_name
        self.authority_name = authority_name
        self.prosecutor_name = prosecutor_name
        self.prosecutor_reference = prosecutor_reference
        self.merged_pcap_size = merged_pcap_sz


def find_target_info_csvfile(merged_pcap_size: str):
    '''Find and return content of target_info.csv'''

    def datetime_converter(raw_ts) -> str:
        '''
        Convert YYYY-MM-DDThh:mm:s.ns+tz to DD.MM.YYYY hh:mm:ss format.
        Example:
        original format: 2025-01-28T08:07:00.474000+0000
        output format:  28.01.2025 08:07:00
        '''
        raw_format = "%Y-%m-%dT%H:%M:%S.%f%z"
        converted_raw = datetime.strptime(raw_ts, raw_format)
        out_format = "%d.%m.%Y %H:%M:%S"
        out_ts = datetime.strftime(converted_raw, out_format)
        return out_ts

    current_dir = os.getcwd()
    for root, _, files in os.walk(current_dir):
        for file in files:
            if file == 'target_info.csv':
                f_path = os.path.join(root, file)
                tg_info_file = f"{current_dir}/{file.split('/')[-1]}"
                try:
                    shutil.copy2(f_path, tg_info_file)
                except shutil.SameFileError:
                    pass

                with open(f_path, 'r') as csv_file:
                    csv_reader = csv.reader(csv_file, delimiter=';')
                    next(csv_reader) # Skip headers.

                    for row in csv_reader:
                        parent_id = row[0]
                        liid = row[1]
                        interception_type = row[2]
                        target_identifier = row[3]
                        target_type = row[4]
                        is_confidential = row[5]
                        order_date = datetime_converter(row[6])
                        activation_date = datetime_converter(row[7])
                        interception_start_date = datetime_converter(row[8])
                        interception_end_date = datetime_converter(row[9])
                        provider_name = row[10]
                        authority_name = row[11]
                        prosecutor_name = row[12]
                        prosecutor_reference = row[13]

                        meta = Case(parent_id,
                                    liid,
                                    interception_type,
                                    target_identifier,
                                    target_type,
                                    is_confidential,
                                    order_date,
                                    activation_date,
                                    interception_start_date,
                                    interception_end_date,
                                    provider_name,
                                    authority_name,
                                    prosecutor_name,
                                    prosecutor_reference,
                                    merged_pcap_size)

                        return meta


def find_iri_csv() -> None:
    '''Find the csv iri file.'''
    current_dir = os.getcwd()
    for root, _, files in os.walk(current_dir):
        for file in files:
            if file.startswith('iri') and file.endswith('csv'):
                f_path = os.path.join(root, file)
                new_name = '/iri.csv'
                try:
                    shutil.copy2(f_path, current_dir + new_name)
                except shutil.SameFileError:
                    pass


def batch_mergecap(pcap_files: List[str], output_file: str, batch_size: int = 250):
    '''Merge pcap files in batches into avoid argument length errors.'''
    # Temporary directory to store pcap files.
    temp_dir = tempfile.mkdtemp()
    intermediate_files = []

    try:
        # Process files in batches.
        for i in range(0, len(pcap_files), batch_size):
            batch = pcap_files[i:i + batch_size]
            intermediate_file = os.path.join(temp_dir, f"batch_{i // batch_size}.pcap")

            # Run mergecap on the current batch.
            result = subprocess.run(
                    ['mergecap', '-F', 'pcap', '-w', intermediate_file] + batch,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    check=True
                )

            # Check for errors in the batch merge.
            if result.returncode != 0:
                print(f"Error merging batch {i // batch_size}: {result.stderr.decode()}")
                logger.error(f"Error merging batch {i // batch_size}: {result.stderr.decode()}")
                raise RuntimeError(f"mergecap failed for batch {i // batch_size}")

            # Add the intermediate file to the list.
            intermediate_files.append(intermediate_file)

        # Final merge of all intermediate files into the output file.
        result = subprocess.run(
                    ['mergecap', '-F', 'pcap', '-w', output_file] + intermediate_files,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    check=True
                )

        if result.returncode != 0:
            print(f"Error in final merge: {result.stderr.decode()}")
            logger.error(f"Error in final merge: {result.stderr.decode()}")
            raise RuntimeError("Final mergecap step failed")

    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir)


def mergecap_and_zeek(key: str) -> None:
    '''
    Merge pcap and process with zeek.

    pcap_size: calculated in find_pcaps_in_products().
    '''
    if pcap_size > 0:
        liid = key.split('-')[-1]
        start_location = os.getcwd()
        dest_folder = 'raw_data'
        os.makedirs(dest_folder, exist_ok=True)

        # mergecap - logging levels from lowest to highest order are:
        # "noisy", "debug", "info", "message", "warning", "critical", "error".
        outfile = f"{liid}_merged.pcap"
        pcap_list = pcaps_dictSorted[key]

        batch_mergecap(pcap_list, outfile, batch_size=250)
        console.log(f"{outfile} mergecap done", style="green")
        logger.info(f"{outfile} mergecap done")

        # zeek - log files are created from where zeek is run.
        # Change to merged.pcap location.
        shutil.move(outfile, dest_folder)
        os.chdir(dest_folder)

        zeek_plugin = '/home/anon/Documents/git/pythonScripts/netflicc/CONSTANTS/geoip.zeek'
        zeek_packages = '/opt/zeek/share/zeek/site/packages/'

        if not os.path.isfile(zeek_plugin):
            console.log(Panel.fit(f"geoip.zeek plugin not found: {zeek_plugin}", border_style='orange_red1'))
            logger.error(f"geoip.zeek plugin not found: {zeek_plugin}")
            sys.exit(9)
        else:
            subprocess.run(['zeek', '-Cr', outfile, zeek_plugin, zeek_packages], check=True)
            console.log(f"{outfile} zeek done", style="green")
            logger.info(f"{outfile} zeek done")
            os.chdir(start_location)


def multi_task_merging_zeek() -> None:
    '''
    Multiprocessing of mergecap and zeek.
    '''
    with concurrent.futures.ProcessPoolExecutor() as executor:
        futures = [executor.submit(mergecap_and_zeek, key) for key in pcaps_dict.keys()]
        for _ in concurrent.futures.as_completed(futures):
            pass

def get_merged_pcap_size() -> str:
    '''Get the size of the merged pcap to be used in metadata.'''
    merged = gb.glob("./*/*_merged.pcap")[0].split('/')[-1]
    basename = os.getcwd()
    outfile = f"{basename}/raw_data/{merged}"

    merged_pcap_size = os.path.getsize(outfile)

    if merged_pcap_size <= 1024:
        console.log(Panel.fit(f"Size of {merged}: {merged_pcap_size}bytes", border_style='cyan'))
        logger.info(f"Size of {merged}: {merged_pcap_size}bytes")
        merged_pcap_size = f"{merged_pcap_size} bytes"
    elif merged_pcap_size <= 1047527424:
        merged_pcap_size = (merged_pcap_size / 1024**2)
        console.log(Panel.fit(f"Size of {merged}: {merged_pcap_size:.2f} Mb", border_style='cyan'))
        logger.info(f"Size of {merged}: {merged_pcap_size:.2f} Mb")
        merged_pcap_size = f"{merged_pcap_size:.2f} Mb"
    else:
        merged_pcap_size = (merged_pcap_size / 1024**3)
        console.log(Panel.fit(f"Size of {merged}: {merged_pcap_size:.2f} GB", border_style='cyan'))
        logger.info(f"Size of {merged}: {merged_pcap_size:.2f} GB")
        merged_pcap_size = f"{merged_pcap_size:.2f} Gb"

    return merged_pcap_size


def pcap_to_nfstream() -> None:
    '''Convert pcap file to parquet.'''
    pcap = gb.glob('*/*.pcap')

    streamer = NFStreamer(source=pcap)
    df = streamer.to_pandas()
    output_file = "./raw_data/nfstreamed_pcap.parquet"
    df.to_parquet(output_file, index=False)


def remove_unzipped_dirs(uzip_file: str) -> None:
    '''
    Process of removing zip files.
    Takes zips list from get_zip_files().

    Arguments: uzip_file: list.
    '''
    shutil.rmtree(uzip_file)
    zip_name = os.path.basename(uzip_file)
    console.log(f"'{zip_name}' removed ({lap_timer()})", style="green")
    logger.info(f"'{zip_name}' removed ({lap_timer()})")


def multi_task_rmunzipped() -> None:
    '''
    Remove zips files simultaneously.
    Allow to spare space as pcaps could be big.
    '''
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(remove_unzipped_dirs, unzipped)


def main(exports_path: str, interrupt_event: bool) -> None|Case:
    '''
    Script launcher.

    Returns:
    metadata: None|Case
    '''
    metadata = None
    global status
    with console.status("[bold italic green]Processing importXP.py ...[/]") as status:
        try:
            start_timer()
            console.log(f"searching zip files in {exports_path}...",
                        style="italic yellow")
            path_to_zips(exports_path)
            get_zip_files(os.getcwd())

            console.log("zip files unzipping, could take some time...",
                        style="italic yellow")
            multi_task_unzip(interrupt_event)
            rmspace(os.getcwd())

            console.log("zip files removing to spare space...",
                        style="italic yellow")
            multi_task_rmzips()

            console.log("searching pcaps...",
                        style="italic yellow")
            find_pcaps_in_products()

            console.log("pcaps merging and parsing, could take some time...",
                        style="italic yellow")
            multi_task_merging_zeek()
            merged_pcap_size = get_merged_pcap_size()

            console.log("searching target info and iri files...",
                        style="italic yellow")
            find_iri_csv()
            metadata = find_target_info_csvfile(merged_pcap_size)
            pcap_to_nfstream()

            console.log("unzipped files removing to spare space...",
                        style="italic yellow")
            multi_task_rmunzipped()

            logger.info(f"module {__name__} done")
            return metadata

        except Exception as exc:
            console.log(Panel.fit(f"An error occured: {exc}",
                                  border_style='orange_red1'))
            logger.exception(f"An error occured: {exc}")

        logger.info(f"module {__name__} done")
        return metadata

if __name__ == "__main__":
    pass
