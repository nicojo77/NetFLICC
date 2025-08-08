"""
version:        1.3
Get imei numbers from pcap, find check-digit and retrieve device from gsma.
"""
import csv
import json
import logging
import os
import pytz
import re
import subprocess
import pandas as pd
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.traceback import install
import thy_constants

install(show_locals=True)
console = Console()
logger = logging.getLogger(__name__)

is_iri = False # iri.csv exist.
tid_is_imei = False # tid is IMEI number.
tid_is_ch = False # tid is a Swiss phone number.
is_imei = False # IMEI data exists, could be TID, IRI or SIP.
imei_in_iri = False # IMEI in iri data.
imei_dic = {}
devicesDic = {}
idx = 1
curdir = os.getcwd()
csv_file = f'{curdir}/iri.csv'
json_file = f'{curdir}/iri.json'

# Define device attributes.
class Device:
    '''Build device data based on TACDB.'''
    def __init__(self,
                    tac=None,
                    manufacturer_=None,
                    model_name_=None,
                    marketing_name_=None,
                    brandname_=None,
                    allocation_date_=None,
                    organisation_id_=None,
                    bluetooth_=None,
                    nfc_=None,
                    wlan_=None,
                    removable_uicc_=None,
                    removable_euicc_=None,
                    nonremovable_uicc_=None,
                    nonremovable_euicc_=None,
                    network_specific_identifier_=None,
                    device_type_=None,
                    sim_slot_=None,
                    imei_quantity_=None,
                    operating_system_=None,
                    oem_=None,
                    band_details_=None,
                    idx_=None):

        self.tac = str(tac)
        self.manufacturer = manufacturer_
        self.modelname = model_name_
        self.marketingname = marketing_name_
        self.brandname = brandname_
        self.allocationdate = allocation_date_
        self.organisationid = organisation_id_
        self.devicetype = device_type_
        self.bluetooth = bluetooth_
        self.nfc = nfc_
        self.wlan = wlan_
        self.removableuicc = str(removable_uicc_)
        self.removableeuicc = str(removable_euicc_)
        self.nonremovableuicc = str(nonremovable_uicc_)
        self.nonremovableeuicc = str(nonremovable_euicc_)
        self.networkspecificidentifier = str(network_specific_identifier_)
        self.simslot = str(sim_slot_)
        self.imeiquantity = str(imei_quantity_)
        self.operatingsystem = operating_system_
        self.oem = oem_
        self.banddetails = band_details_
        self.idx = idx_

    # Optional.
    def details(self):
        '''Returns instance Device details.'''
        return self.tac, self.manufacturer, self.modelname, self.marketingname,\
        self.brandname, self.allocationdate, self.organisationid, self.devicetype,\
        self.bluetooth, self.nfc, self.wlan, self.removableuicc, self.removableeuicc,\
        self.nonremovableuicc, self.nonremovableeuicc, self.networkspecificidentifier,\
        self.simslot, self.imeiquantity, self.operatingsystem, self.oem, self.banddetails


class Imei:
    '''Get specific data of each IMEI as well as counts.'''
    def __init__(self, imei_num_, tac_, serial_num_, check_digit_, idx_, source_, first_seen_, last_seen_):
        self.imei = imei_num_
        self.tac = tac_
        self.serial_n = serial_num_
        self.check_d = check_digit_
        self.idx = str(idx_)
        self.source = {source_} # set
        self.count_iri = 1 # Initialise counter for iri
        self.count_sip = 0 # Initialise counter for sip, iri already found
        self.first_seen = first_seen_
        self.last_seen = last_seen_

    def increment_count(self, source_):
        '''Counter for instance IMEI.'''
        if source_ == 'IRI':
            self.count_iri += 1
        if source_ == 'SIP':
            self.count_sip += 1


    def update_source_list(self, source_):
        '''Append list to instance IMEI.'''
        self.source.add(source_)

    def details(self):
        '''Returns instance IMEI details.'''
        return self.imei, self.tac, self.serial_n, self.check_d, self.idx, self.count, self.source


class MSISDN:
    '''
    Class MSISDN.
    Get counts, first and last seen.
    '''

    def __init__(self, source_, fseen_, lseen_):
        self.source = {source_} # set
        self.count_iri = 0 # Initialise counter for iri
        self.count_sip = 0 # Initialise counter for sip
        self.first_seen = fseen_
        self.last_seen = lseen_

    def increment_count(self, source_):
        '''Counter for instance IMEI.'''
        if source_ == 'IRI':
            self.count_iri += 1
        if source_ == 'SIP':
            self.count_sip += 1

    def update_source_list(self, source_):
        '''Append list to instance IMEI.'''
        self.source.add(source_)


def iri_parser(csv_f, json_f) -> None:
    '''
    Search iri.csv file.
    Transpose "normalized" field from iri.csv to json format.
    '''
    global is_iri

    # File iri.csv exists.
    if os.path.isfile(csv_f):
        is_iri = True
        console.log("processing and parsing iri.csv...", style='dim italic yellow')
        json_data = []
        with open(csv_f, 'r', newline='\n') as csvFile:
            csv_reader = csv.reader(csvFile, delimiter=';')
            next(csv_reader) # Skip headers.

            for row in csv_reader:
                raw_field = row[8] # Field: normalized.
                try:
                    json_object = json.loads(raw_field)
                    json_data.append(json_object)
                except json.JSONDecodeError:
                    console.log(Panel.fit(f"Error decoding json: {raw_field}",
                                          border_style='orange_red1'))
                    logger.exception(f"Error decoding json: {raw_field}")

        json_output = json.dumps(json_data, indent=2)
        with open(json_f, 'w') as wf:
            wf.write(json_output)

    # File iri.csv doesn't exist.
    else:
        console.log(Panel.fit("No iri file found!",
                              border_style='orange_red1',
                              title='[italic]Warning',
                              title_align='left'))
        console.log("Creating empty iri.csv...", style='dim italic yellow')
        logger.warning("No iri file found")
        logger.info("Creating empty iri.csv")
        iri_header = 'product_id;id;decoder_product_id;decoder_iri_id;type;subtype;decoder_date_created;header;normalized;beautified;raw'
        with open(csv_f, 'w') as of:
            of.write(iri_header + '\n')


def determine_tid_type(tid) -> None:
    '''Determine the target identifier format, msisdn or imei.'''
    # IDX is set to Target Identifier TID to differentiate the origin.
    global idx
    global is_imei
    global tid_is_ch
    global tid_is_imei

    if tid[0] != '+' and len(tid) == 15:
        tid_is_imei = True
        is_imei = True
        imei_num = tid[:14]
        tac = imei_num[:8]
        serial_num = imei_num[8:14]
        check_digit = luhn(tac + serial_num)
        index = idx
        source = 'TID'

        # Create mock timestamps to allow later comparison in iri_imei_xtract().
        # First seen.
        ts = datetime.now()
        zurich_tz = pytz.timezone('Europe/Zurich')
        ts1 = zurich_tz.localize(ts)
        # Last seen.
        ts = '01.01.2001 00:00:00'
        ts = datetime.strptime(ts, '%d.%m.%Y %H:%M:%S')
        ts2 = zurich_tz.localize(ts)

        imei_n = Imei(imei_num, tac, serial_num, check_digit, index, source, ts1, ts2)
        imei_dic[imei_num] = imei_n
        idx += 1
    if tid[1:3] == '41':
        tid_is_ch = True


def iri_imei_xtract() -> pd.DataFrame:
    '''
    Extract IMEI from IRI.
    Returns: iridf, contains cell-towers data.
    '''
    global is_imei
    global imei_in_iri
    global idx
    global imei_dic

    # Will be returned if IRI data not complete.
    empty_iridf = pd.DataFrame()

    if not is_iri:
        return empty_iridf

    # Load json file to dataframe.
    iridf = pd.read_json(json_file)

    # Iri file can exist but without any IMEI.
    # Takes only 14-digit number as n15 is check-digit.
    # Drop empty values and create list of IMEI(s).
    try:
        imei_df = iridf[['imei', 'iriTimestamp']]
        imei_df.dropna(subset=['imei'], inplace=True)
        imei_df['iriTimestamp'] = pd.to_datetime(imei_df['iriTimestamp'])
        imei_df['iriTimestamp'] = imei_df['iriTimestamp'].dt.tz_convert('Europe/Zurich')
        imei_df['imei'] = imei_df['imei'].astype(str).str[:14]
        is_imei = True
    except KeyError:
        console.log(Panel.fit("No IMEI in iri file found!",
                                border_style='orange_red1',
                                title='[italic]Warning',
                                title_align='left'))
        console.log("Creating empty iri.csv...", style='dim italic yellow')
        logger.warning("No IMEI in iri file found")
        logger.info("Creating empty iri.csv")
        iri_header = '''
                    product_id;id;decoder_product_id;decoder_iri_id;type;\
                    subtype;decoder_date_created;header;normalized;beautified;raw'''
        with open(csv_file, 'w') as of:
            of.write(iri_header + '\n')

        return empty_iridf

    # Format IMEI(s) to match those found in pcap.
    console.log("processing IMEIs found in IRI...", style='dim italic yellow')
    for _, row in imei_df.iterrows():
        imei = row['imei']
        tac = imei[:8]
        serial_num = imei[8:]
        imei = (tac + serial_num)
        check_digit = luhn(tac + serial_num)
        source = 'IRI'
        ts = row['iriTimestamp']

        # IMEI already found, only increase counter.
        if imei in imei_dic:
            imei_dic[imei].update_source_list(source)
            imei_dic[imei].increment_count(source)
            if ts < imei_dic[imei].first_seen:
                imei_dic[imei].first_seen = ts
            if ts > imei_dic[imei].last_seen:
                imei_dic[imei].last_seen = ts
 
        # New IMEI, setup values and append to list.
        else:
            new_imei = Imei(imei, tac, serial_num, check_digit, idx, source, ts, ts)
            imei_dic[imei] = new_imei
            idx += 1

    imei_in_iri = True

    return iridf


def ngrep_imei_xtract(pcap_file, tid) -> None:
    '''
    Extract IMEI from pcap with ngrep.
    Timestamp is only processed if no imei in IRI.
    '''
    global idx
    global is_imei
    global imei_dic
    global tid_is_ch

    subscriber_number = tid[1:]

    # Swiss MSISDN.
    if tid_is_ch:
        console.log(f"extracting IMEI in SIP protocol with ngrep...", style='dim italic yellow')
        p1 = subprocess.Popen(['ngrep', '-I', pcap_file, '-W', 'single', '-ti',
                            fr'(?<=P-Asserted-Identity: (<sip|<tel):\+){subscriber_number}'],
                            stdout=subprocess.PIPE)

        p2 = subprocess.Popen(['grep', '-Piv', r'(SIP/2.0\s+[1-6]\d{2}\s+)(\w+)(\s)?(\w+)(\.\.)'],
                            stdin=p1.stdout, stdout=subprocess.PIPE)

        p3 = subprocess.Popen(['grep', '-Pi', fr'(?<=From: (<sip|<tel):\+){subscriber_number}'],
                            stdin=p2.stdout, stdout=subprocess.PIPE)

        output, _ = p3.communicate()

    # Foreign MSISDN.
    else:
        console.log(f"extracting IMEI in SIP protocol with ngrep...", style='dim italic yellow')
        p1 = subprocess.Popen(['ngrep', '-I', pcap_file, '-W', 'single', '-ti',
                            fr'(?<=[^\s]{2}subscribe sip:\+){subscriber_number}'],
                            stdout=subprocess.PIPE)

        p2 = subprocess.Popen(['grep', '-Pi', fr'(?<=From: (<sip|<tel):\+){subscriber_number}'],
                            stdin=p1.stdout, stdout=subprocess.PIPE)

        output, _ = p2.communicate()

    decoded_output = output.decode('utf-8')
    undef_blocks = re.split('\n', decoded_output)

    # Take into account only blocks starting with UDP, TCP and undefined ?.
    # You can check it with a for loop and start_pattern = r'^.{1}(?=\s{1})'
    sip_blocks = []
    for block in undef_blocks:
        if block.startswith(('T', 'U', '?')):
            sip_blocks.append(block)

    # If no data found, returns.
    if not sip_blocks:
        return

    # Complete imei dictionary.
    for block in sip_blocks:
        if tid_is_ch:
            imei_pattern = r'(?<=instance-id-orig="urn:gsma:imei:)(\d{8}-\d{6})'
        else:
            imei_pattern = r'(?<=sip\.instance="<urn:gsma:imei:)(\d{8}-\d{6})'
        re.compile(imei_pattern, flags=re.IGNORECASE)
        imeis = re.findall(imei_pattern, block)

        if imeis:
            is_imei = True
            date_pattern = r'(?<=.{1} )\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}'
            re.compile(date_pattern, flags=0)
            sip_date = re.findall(date_pattern, block)
            if sip_date:
                sip_date_str = sip_date[-1]
                sip_date = datetime.strptime(sip_date_str, '%Y/%m/%d %H:%M:%S')
                # Add timezone to make comparison with imei_val.first|last_seen possible.
                zurich_tz = pytz.timezone('Europe/Zurich')
                ts = zurich_tz.localize(sip_date)
                imei = imeis[-1]
                tac, serial_num = imei.split('-')
                check_digit = luhn(tac + serial_num)
                imei_num = (tac + serial_num)
                source = 'SIP'

                # Known imei, increment count and adapt dates.
                if imei_num in imei_dic:
                    imei_dic[imei_num].update_source_list(source)
                    imei_dic[imei_num].increment_count(source)
                    # Process time only if no imei found in IRI.
                    if not imei_in_iri:
                        if ts < imei_dic[imei_num].first_seen:
                            imei_dic[imei_num].first_seen = ts
                        if ts > imei_dic[imei_num].last_seen:
                            imei_dic[imei_num].last_seen = ts
                # Unknown imei.
                else:
                    imei_n = Imei(imei_num, tac, serial_num, check_digit, idx, source, ts, ts)
                    imei_dic[imei_num] = imei_n
                    idx += 1


def adjust_counters() -> None:
    '''Adjust counters to match reality if IRI is missing.'''
    # No IRI file or imei.
    if not imei_in_iri:
        for imei, _ in imei_dic.items():
            imei_dic[imei].count_iri = 0
    # No IRI file or imei but imei in SIP.
    if not imei_in_iri and is_imei:
        for imei, _ in imei_dic.items():
            imei_dic[imei].increment_count('SIP')


def create_imei_table() -> tuple[pd.DataFrame, pd.DataFrame]:
    '''Create combined table with IRI and SIP data.'''
    # Create data structure for dataframe.
    imei_data = []
    for _, imei_val in imei_dic.items():
        imei_data.append({
            'IDX': imei_val.idx,
            'TAC#': imei_val.tac,
            'SN#': imei_val.serial_n,
            'Check-Digit': imei_val.check_d,
            'IMEI Full': imei_val.tac+imei_val.serial_n+imei_val.check_d,
            'Counts IRI (SIP)': f"{imei_val.count_iri} ({imei_val.count_sip})",
            'Source': sorted(list(imei_val.source)),
            'First seen IRI': imei_val.first_seen,
            'Last seen IRI': imei_val.last_seen
        })

    # Create dataframe.
    if len(imei_data) > 0:
        imei_df = pd.DataFrame(imei_data)
        # Remove rubbish characters.
        imei_df['Source'] = imei_df['Source'].astype(str)
        imei_df['Source'] = imei_df['Source'].apply(lambda x:
                                    x.replace('[', '').replace(']', '').replace("'", ''))
        # Add colour to check-digit and build full IMEI number.
        imei_df['Check-Digit'] = imei_df['Check-Digit'].apply(lambda x:
                                    f"<span style='color: orange;'>{x[-1]}</span>")
        imei_df['IMEI Full'] = imei_df['IMEI Full']\
            .apply(lambda x: f"{x[:-1]}<span style='color: orange;'>{x[-1]}</span>")
        # Format time to string.
        imei_df['First seen IRI'] = imei_df['First seen IRI'].apply(lambda x: x.strftime('%d.%m.%Y %H:%M:%S'))
        imei_df['Last seen IRI'] = imei_df['Last seen IRI'].apply(lambda x: x.strftime('%d.%m.%Y %H:%M:%S'))
    else:
        # Create an empty dataframe.
        imei_df = pd.DataFrame()

    # Create an empty dataframe to prevent errors later in the script.
    gsma_df = pd.DataFrame()

    return imei_df, gsma_df


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


def tac_to_gsma() -> list:
    '''Match TAC against GSMA database and return a list of dataframes.'''
    GSMA = thy_constants.GSMA
    try:
        os.path.isfile(GSMA)
        df = pd.read_csv(GSMA, sep='|', index_col='tac')
    except FileNotFoundError:
        console.log(Panel.fit(f"TACDB not found: {GSMA}", border_style='orange_red1'))
        logger.warning(f"TACDB not found: {GSMA}")
        gsma_df_list: list = []
        return gsma_df_list

    # 'tac' serie is of type int.
    for _, val in imei_dic.items():
        tac = int(val.tac) # tac value in imei_dic is str
        manufacturer = df.loc[tac, 'manufacturer']
        model_name = df.loc[tac, 'modelName']
        marketing_name = df.loc[tac, 'marketingName']
        brand_name = df.loc[tac, 'brandName']
        allocation_date = df.loc[tac, 'allocationDate']
        organisation_id = df.loc[tac, 'organisationId']
        device_type = df.loc[tac, 'deviceType']
        bluetooth = df.loc[tac, 'bluetooth']
        nfc = df.loc[tac, 'nfc']
        wlan = df.loc[tac, 'wlan']
        removable_uicc = df.loc[tac, 'removableUICC']
        removable_euicc = df.loc[tac, 'removableEUICC']
        nonremovable_uicc = df.loc[tac, 'nonremovableUICC']
        nonremovable_euicc = df.loc[tac, 'nonremovableEUICC']
        network_specific_identifier = df.loc[tac, 'networkSpecificIdentifier']
        sim_slot = df.loc[tac, 'simSlot']
        imei_quantity = df.loc[tac, 'imeiQuantity']
        operating_system = df.loc[tac, 'operatingSystem']
        oem = df.loc[tac, 'oem']
        band_details = df.loc[tac, 'bandDetails']
        idx = val.idx

        dev = Device(tac,
                     manufacturer,
                     model_name,
                     marketing_name,
                     brand_name,
                     allocation_date,
                     organisation_id,
                     bluetooth,
                     nfc,
                     wlan,
                     removable_uicc,
                     removable_euicc,
                     nonremovable_uicc,
                     nonremovable_euicc,
                     network_specific_identifier,
                     device_type,
                     sim_slot,
                     imei_quantity,
                     operating_system,
                     oem,
                     band_details,
                     idx)

        # devicesDic key (tac) is of type int, whereas val is of type str.
        tac = val.tac
        devicesDic[tac] = dev

        # INFO: as devicesDic has 'tac' for key, the index will show the highest ranking number.
        # Hence, the IMEI table will show every IDX, whereas the devices detail tables won't.
        # E.g.: a device is identified with same TAC but different SN, they could get assigned
        # IDX 1 and 3 or others. In that case, only IDX 3 will be shown in the devices details.

    # Prepare the data to match Pandas dataframe structure.
    tac_data = []
    gsma_df_list = []
    for tac, tac_val in devicesDic.items():
        tac_data.append([tac_val.idx, 'tac', tac_val.tac])
        tac_data.append([tac_val.idx, 'manufacturer', tac_val.manufacturer])
        tac_data.append([tac_val.idx, 'modelName', tac_val.modelname])
        tac_data.append([tac_val.idx, 'marketingName', tac_val.marketingname])
        tac_data.append([tac_val.idx, 'brandName', tac_val.brandname])
        tac_data.append([tac_val.idx, 'allocationDate', tac_val.allocationdate])
        tac_data.append([tac_val.idx, 'organisationId', tac_val.organisationid])
        tac_data.append([tac_val.idx, 'deviceType', tac_val.devicetype])
        tac_data.append([tac_val.idx, 'bluetooth', tac_val.bluetooth])
        tac_data.append([tac_val.idx, 'nfc', tac_val.nfc])
        tac_data.append([tac_val.idx, 'wlan', tac_val.wlan])
        tac_data.append([tac_val.idx, 'removableUICC', tac_val.removableuicc])
        tac_data.append([tac_val.idx, 'removableEUICC', tac_val.removableeuicc])
        tac_data.append([tac_val.idx, 'nonremovableUICC', tac_val.nonremovableuicc])
        tac_data.append([tac_val.idx, 'nonremovableEUICC', tac_val.nonremovableeuicc])
        tac_data.append([tac_val.idx, 'networkSpecificIdentifier', tac_val.networkspecificidentifier])
        tac_data.append([tac_val.idx, 'simSlot', tac_val.simslot])
        tac_data.append([tac_val.idx, 'imeiQuantity', tac_val.imeiquantity])
        tac_data.append([tac_val.idx, 'operatingSystem', tac_val.operatingsystem])
        tac_data.append([tac_val.idx, 'oem', tac_val.oem])
        tac_data.append([tac_val.idx, 'bandDetails', tac_val.banddetails])

        columns = ['IDX', 'Data type', 'Value']
        gsma_df_list.append(pd.DataFrame(tac_data, columns=columns))
        tac_data = []

    # Generate csv file with complete set of data.
    for df in gsma_df_list:
        index = df.iloc[0][0]
        output = f'device_idx_{index}.csv'
        df.to_csv(output, index=False)

    return gsma_df_list


def msisdn_parser(pcap_file: str, tid: str, iridf_: pd.DataFrame) -> pd.DataFrame:
    '''Search for msisdn in SIP protocol and iri.csv.'''
    global is_iri
    msisdn_dic = {}

    # Search MSISDN in iri.csv.
    if is_iri:
        console.log("parsing iri for msisdn...", style='dim italic yellow')

        # Load json file to dataframe.
        iridf = iridf_

        iridf['imei'] = iridf['imei'].astype(str).str[:14]
        iridf = iridf[['imei', 'targetAddress', 'iriTimestamp']]
        # Adjust time format and allow datetime parsing, convert to 'Europe/Zurich' time zone
        iridf['iriTimestamp'] = pd.to_datetime(iridf['iriTimestamp'])
        iridf['iriTimestamp'] = iridf['iriTimestamp'].dt.tz_convert('Europe/Zurich')

        tid = tid[:14]
        filt = (iridf['imei'] == tid)
        msisdn_list = iridf[filt]['targetAddress'].unique()

        for msisdn in msisdn_list:
            filt = (iridf['targetAddress'] == msisdn)
            fseen = iridf[filt]['iriTimestamp'].min()
            lseen = iridf[filt]['iriTimestamp'].max()
            counts = iridf[filt]['targetAddress'].value_counts().sum()
            msisdn = msisdn.astype(str)

            if msisdn in msisdn_dic:
                msisdn_dic[msisdn].count_iri = counts
                msisdn_dic[msisdn].update_source_list('IRI')
                if fseen < msisdn_dic[msisdn].first_seen:
                    msisdn_dic[msisdn].first_seen = fseen
                if lseen > msisdn_dic[msisdn].last_seen:
                    msisdn_dic[msisdn].last_seen = lseen

            else:
                new_msisdn = MSISDN('IRI', fseen, lseen)
                msisdn_dic[msisdn] = new_msisdn
                msisdn_dic[msisdn].count_iri = counts
                msisdn_dic[msisdn].update_source_list('IRI')

    # Search MSISDN in pcap.
    console.log("parsing pcap for msisdn...", style='dim italic yellow')
    dashed_imei = f"{tid[:8]}-{tid[8:14]}"

    # First process: ngrep for phone IMEI.
    p1 = subprocess.Popen(['ngrep', '-I', pcap_file, '-W', 'single', '-ti', dashed_imei],
                        stdout=subprocess.PIPE)

    # Second process: grep -Piv, searches SIP answers and invert match.
    p2 = subprocess.Popen(['grep', '-Piv', r'(SIP/2.0\s+[1-6]\d{2}\s+)(\w+)(\s)?(\w+)(\.\.)'],
                        stdin=p1.stdout, stdout=subprocess.PIPE)

    output, error = p2.communicate()

    # Decode subprocess output (binary) to text.
    decoded_output = output.decode('utf-8')
    undef_blocks = re.split('\n', decoded_output)

    # Take into account only blocks starting with UDP, TCP and undefined ?.
    # You can check it with a for loop and start_pattern = r'^.{1}(?=\s{1})'
    sip_blocks = []
    for block in undef_blocks:
        if block.startswith(('T', 'U', '?')):
            sip_blocks.append(block)

    # Search the 'SUBSCRIBE' method details.
    for block in sip_blocks:
        msisdn_pattern = r'(?<=[^\s{2}]SUBSCRIBE sip:\+)\d+'
        re.compile(msisdn_pattern, flags=re.IGNORECASE)
        msisdn = re.findall(msisdn_pattern, block)

        # MSISDN format is found, search for date.
        if msisdn:
            # date_pattern = r'\d{4}/\d{2}/\d{2}'
            # re.compile(date_pattern, flags=0)
            # sip_date = re.findall(date_pattern, block)
            # sip_date = datetime.strptime(sip_date[-1], '%Y/%m/%d').date()
            msisdn = msisdn[-1]

            # Create mock timestamps to allow later comparison in iri_imei_xtract().
            # First seen.
            ts = datetime.now()
            zurich_tz = pytz.timezone('Europe/Zurich')
            ts1 = zurich_tz.localize(ts)

            # Last seen.
            ts = '11.11.1111 11:11:11'
            ts = datetime.strptime(ts, '%d.%m.%Y %H:%M:%S')
            ts2 = zurich_tz.localize(ts)

            # Known MSISDN.
            if msisdn in msisdn_dic:
                msisdn_dic[msisdn].increment_count('SIP')
                msisdn_dic[msisdn].update_source_list('SIP')
                # if sip_date < msisdn_dic[msisdn].first_seen:
                #     msisdn_dic[msisdn].first_seen = sip_date
                # if sip_date > msisdn_dic[msisdn].last_seen:
                #     msisdn_dic[msisdn].last_seen = sip_date

            # Unknown MSISDN.
            else:
                new_msisdn = MSISDN('SIP', ts1, ts2)
                msisdn_dic[msisdn] = new_msisdn

    data = []
    for msisdn, msisdn_val in msisdn_dic.items():
        data.append({
            'MSISDN': msisdn,
            'Source': sorted(list(msisdn_val.source)),
            'Counts IRI (SIP)': f"{msisdn_val.count_iri} ({msisdn_val.count_sip})",
            'First seen IRI': msisdn_val.first_seen,
            'Last seen IRI': msisdn_val.last_seen,
        })

    if data:
        msisdndf = pd.DataFrame(data)
        msisdndf['Source'] = msisdndf['Source'].astype(str)
        msisdndf['Source'] = msisdndf['Source'].apply(lambda x:
                                    x.replace('[', '').replace(']', '').replace("'", ''))
        msisdndf['First seen IRI'] = msisdndf['First seen IRI'].apply(lambda x: x.strftime('%d.%m.%Y %H:%M:%S'))
        msisdndf['Last seen IRI'] = msisdndf['Last seen IRI'].apply(lambda x: x.strftime('%d.%m.%Y %H:%M:%S'))
        msisdndf.sort_values(['Counts IRI (SIP)'], ascending=False, inplace=True)
        msisdndf['MSISDN'] = msisdndf['MSISDN'].apply(lambda x: f'+{x}')
    else:
        msisdndf = pd.DataFrame()

    return msisdndf


def main(pcap_file_, tid) -> tuple[pd.DataFrame, list|pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    '''
    Script launcher.

    Returns:
    imei_df: pd.DataFrame
    gsma_df: list|pd.DataFrame
    iri_df: pd.DataFrame
    '''
    with console.status("[bold italic green]Processing gsma.py ...[/]") as _:
        console.log("checking for IMEIs...", style="italic yellow")
        iri_parser(csv_file, json_file)
        determine_tid_type(tid)
        iri_df = iri_imei_xtract()

        # Check for IMEI only if TID is MSISDN.
        if not tid_is_imei:
            ngrep_imei_xtract(pcap_file_, tid)

        adjust_counters()
        imei_df, gsma_df = create_imei_table()

        # Check for MSISDN only if TID is imei.
        if tid_is_imei:
            msisdndf = msisdn_parser(pcap_file_, tid, iri_df)
        else:
            data = {'MSISDN': [tid],
                    'Source': ['TID']}
            msisdndf = pd.DataFrame(data)

        # Check gsma database only if TID is IMEI or at least one IMEI has been found.
        if is_imei:
            console.log("checking GSMA database...", style="italic yellow")
            gsma_df = tac_to_gsma()
            logger.info(f"module {__name__} done")
            return imei_df, gsma_df, iri_df, msisdndf

        logger.info(f"module {__name__} done")
        return imei_df, gsma_df, iri_df, msisdndf


if __name__ == "__main__":
    pass
