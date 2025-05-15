"""
version:        1.2
Get imei numbers from pcap, find check-digit and retrieve device from gsma.
"""
import csv
import json
import logging
import os
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
    def __init__(self, imei_num_, tac_, serial_num_, check_digit_, idx_, source_):
        self.imei = imei_num_
        self.tac = tac_
        self.serial_n = serial_num_
        self.check_d = check_digit_
        self.idx = str(idx_)
        self.source = [source_]
        self.count = 0 # Initialise counter

    def increment_count(self):
        '''Counter for instance IMEI.'''
        self.count += 1

    def update_source_list(self, source_):
        '''Append list to instance IMEI.'''
        self.source.append(source_)

    def details(self):
        '''Returns instance IMEI details.'''
        return self.imei, self.tac, self.serial_n, self.check_d, self.idx, self.count


class MSISDN:
    '''
    Class MSISDN.
    Get counts, first and last seen.
    '''

    def __init__(self, source, fseen, lseen):
        self.source = source
        self.first_seen = fseen
        self.last_seen = lseen


curdir = os.getcwd()
csv_file = f'{curdir}/iri.csv'
json_file = f'{curdir}/iri.json'
imei_dic = {}


def iri_parser(csv_f, json_f) -> tuple[pd.DataFrame, list, bool]:
    '''
    Parse iri.csv for IMEI numbers.

    Transpose "normalized" field from iri.csv to json format.
    Load iri.json to pd.DataFrame().

    Return:
    df (pd df):         dataframe
    imei_list (list):   IMEI(s) list.
    '''
    # isiri = True
    isiri = False

    # File iri.csv exists.
    if os.path.isfile(csv_f):
        isiri = True
        console.log("processing and parsing iri.csv...", style='italic yellow')
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

        # Load json file to dataframe.
        df = pd.read_json(json_f)

        # Iri file can exist but without any IMEI.
        # Takes only 14-digit number as n15 is check-digit.
        # Drop empty values and create list of IMEI(s).
        imei_df = df
        try:
            imei_df.dropna(subset=['imei'], inplace=True)
            imei_df['imei'] = imei_df['imei'].astype(str).str[:14].astype('Int64')
            imei_list = imei_df['imei'].unique()
        except KeyError:
            console.log(Panel.fit("No IMEI in iri file found!",
                                  border_style='orange_red1',
                                  title='[italic]Warning',
                                  title_align='left'))
            console.log("Creating empty iri.csv...", style='italic yellow')
            logger.warning("No IMEI in iri file found")
            logger.info("Creating empty iri.csv")
            iri_header = '''
                        product_id;id;decoder_product_id;decoder_iri_id;type;\
                        subtype;decoder_date_created;header;normalized;beautified;raw'''
            with open(csv_f, 'w') as of:
                of.write(iri_header + '\n')

            df = pd.DataFrame()
            imei_list = []
            isiri = False

    # File iri.csv doesn't exist.
    else:
        console.log(Panel.fit("No iri file found!",
                              border_style='orange_red1',
                              title='[italic]Warning',
                              title_align='left'))
        console.log("Creating empty iri.csv...", style='italic yellow')
        logger.warning("No iri file found")
        logger.info("Creating empty iri.csv")
        iri_header = '''
                    product_id;id;decoder_product_id;decoder_iri_id;type;\
                    subtype;decoder_date_created;header;normalized;beautified;raw'''
        with open(csv_f, 'w') as of:
            of.write(iri_header + '\n')

        df = pd.DataFrame()
        imei_list = []
        isiri = False

    return df, imei_list, isiri


def imei_parser(pcap_file, tid, iri_list, iridf, isiri=True) -> tuple[bool, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    '''
    Build IMEI(s) dataframe.

    Parse pcap at binary level with ngrep and embed IMEI(s) found in iri.csv.
    Returns:
    imei_df: dataframe with index, imei, tac, serial_num, counts, source and check-d.
    gsma_df: empty dataframe.
    '''
    isimei = False
    idx = 1

    msisdndf = pd.DataFrame()

    # Verify first if target id (tid) is IMEI and complete imei_dic if so.
    # IDX is set to Target Identifier TID to differentiate the origin.
    if tid[0] != '+' and len(tid) == 15:
        isimei = True
        imei_num = tid[:14]
        tac = imei_num[:8]
        serial_num = imei_num[8:14]
        check_digit = luhn(tac + serial_num)
        index = idx
        source = 'TID'
        imei_n = Imei(imei_num, tac, serial_num, check_digit, index, source)
        imei_dic[imei_num] = imei_n
        idx += 1
        # msisdndf = msisdn_parser(pcap_file, tid)

    console.log("processing sip.log for IMEI...", style='italic yellow')
    # Search the pcap file (binary) for imei data.
    # ngrep searches for plain text which is the format type used by SIP protocol.
 
    # The next subprocesses replace ngrep/grep combo.
    # ngrep -I pcap -W single -tiq '\+41000000000' | grep -Piv '(SIP/2.0\s+[1-6]\d{2}\s+)(\w+)(\s)?(\w+)(\.\.)' |\
    # grep -Pi 'From: <sip:\+41000000000@' | grep -Poi '(?<=urn:gsma:imei:)[0-9]{8}-[0-9]{6}'

    escaped_tid = f"\\{tid}" # escaping tid's [+] necessary for ngrep.
    # First process: ngrep for phone number.
    p1 = subprocess.Popen(['ngrep', '-I', pcap_file, '-W', 'single', '-ti', escaped_tid],
                        stdout=subprocess.PIPE)

    # Second process: grep -Piv, searches SIP answers and invert match.
    # Get only requests.
    p2 = subprocess.Popen(['grep', '-Piv', r'(SIP/2.0\s+[1-6]\d{2}\s+)(\w+)(\s)?(\w+)(\.\.)'],
                        stdin=p1.stdout, stdout=subprocess.PIPE)

    # Third process: grep -Pi, searches tid once more in contact 'From: <sip:' only.
    p3 = subprocess.Popen(['grep', '-Pi', f'From: <sip:{escaped_tid}@'],
                        stdin=p2.stdout, stdout=subprocess.PIPE)

    output, error = p3.communicate()

    if output:
        # Decode subprocess output (binary) to text.
        # Search text file for imei pattern.
        match_txt = output.decode('utf-8')
        re_pattern = r'(?<=sip.instance="<urn:gsma:imei:)[0-9]{8}-[0-9]{6}'
        re.compile(re_pattern, flags=0)
        match = re.findall(re_pattern, match_txt)
        if match:
            isimei = True

        # Create dictionary with matched IMEI as key.
        # Split each IMEI into specific values, TAC and SN.
        # Remove hyphen of IMEI number.
        for imei in match:
            tac, serial_num = imei.split('-')
            check_digit = luhn(tac + serial_num)
            imei_num = (tac + serial_num)
            source = 'SIP'

            # IMEI already found, only increase counter.
            if imei_num in imei_dic:
                imei_dic[imei_num].increment_count()
            # New IMEI, setup values and append to list.
            else:
                imei_n = Imei(imei_num, tac, serial_num, check_digit, idx, source)
                imei_dic[imei_num] = imei_n
                imei_dic[imei_num].increment_count() # Start from 0.
                idx += 1

    if isiri:
        # Format IMEI(s) to match those found in pcap.
        console.log("processing IMEIs found in iri.csv...", style='italic yellow')
        if len(iri_list) > 0:
            isimei = True
            for imei in iri_list:
                imei = str(imei)
                tac = imei[:8]
                serial_num = imei[8:]
                imei_num = (tac + serial_num)
                check_digit = luhn(tac + serial_num)
                source = 'IRI'

                if imei_num in imei_dic:
                    imei_dic[imei_num].update_source_list(source)
                else:
                    imei_n = Imei(imei_num, tac, serial_num, check_digit, idx, source)
                    imei_dic[imei_num] = imei_n
                    idx += 1

    # Create data structure for dataframe.
    imei_data = []
    for _, imei_val in imei_dic.items():
        imei_data.append({
            'IDX': imei_val.idx,
            'TAC#': imei_val.tac,
            'SN#': imei_val.serial_n,
            'Check-Digit': imei_val.check_d,
            'IMEI Full': imei_val.tac+imei_val.serial_n+imei_val.check_d,
            'Counts (pcap)': imei_val.count,
            'Source': imei_val.source
        })

    # Create dataframe.
    if len(imei_data) > 0:
        imei_df = pd.DataFrame(imei_data)
        # Remove rubbish characters.
        imei_df['Source'] = imei_df['Source'].astype(str)
        imei_df['Source'] = imei_df['Source'].apply(lambda x:
                                    x.replace('[', '').replace(']', '').replace("'", ''))
        imei_df['Check-Digit'] = imei_df['Check-Digit'].apply(lambda x:
                                    f"<span style='color: orange;'>{x[-1]}</span>")
        imei_df['IMEI Full'] = imei_df['IMEI Full']\
            .apply(lambda x: f"{x[:-1]}<span style='color: orange;'>{x[-1]}</span>")
    else:
        # Create an empty dataframe.
        imei_df = pd.DataFrame()

    # Create an empty dataframe to prevent errors later in the script.
    gsma_df = pd.DataFrame()

    return isimei, imei_df, gsma_df, msisdndf




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




devicesDic = {}
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

def msisdn_parser(pcap_file: str, tid: str, isiri=False) -> pd.DataFrame:
    '''Search for msisdn in SIP protocol and iri.csv.'''

    # INFO: IMEI hits in pcap/SIP have not been observed so far, script works though.

    # Search for MSISDN in pcap SIP protocol only if tid is IMEI.
    if tid[0] == '+':
        data = {'MSISDN': [tid],
                'Source': 'TID'}
        msisdndf = pd.DataFrame(data)
        return msisdndf

    dashed_imei = f"{tid[:8]}-{tid[8:14]}"

    console.log("parsing pcap for msisdn...", style='italic yellow')

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

    # Search the 'from' contact detail for MSISDN.
    msisdn_dic = {}
    for block in sip_blocks:
        msisdn_pattern = r'(?<=From: <sip:)(\+\d*)(?=@ims)'
        re.compile(msisdn_pattern, flags=re.IGNORECASE)
        msisdn = re.findall(msisdn_pattern, block)

        # MSISDN format is found, search for date.
        if msisdn:
            date_pattern = r'\d{4}/\d{2}/\d{2}'
            re.compile(date_pattern, flags=0)
            sip_date = re.findall(date_pattern, block)
            sip_date = datetime.strptime(sip_date[-1], '%Y/%m/%d').date()
            msisdn = msisdn[-1]

            # Known MSISDN.
            if msisdn in msisdn_dic:
                # msisdn_dic[msisdn].increment_count()
                if sip_date < msisdn_dic[msisdn].first_seen:
                    msisdn_dic[msisdn].first_seen = sip_date
                if sip_date > msisdn_dic[msisdn].last_seen:
                    msisdn_dic[msisdn].last_seen = sip_date

            # Unknown MSISDN.
            else:
                newua = MSISDN('SIP', sip_date, sip_date)
                msisdn_dic[msisdn] = newua

    # Create the data structure for dataframe.
    data = []
    for msisdn, msisdn_val in msisdn_dic.items():
        data.append({
            'MSISDN': msisdn,
            'Source': msisdn_val.source,
            'First seen': msisdn_val.first_seen,
            'Last seen': msisdn_val.last_seen
        })

    # Create the dataframe or an empty one.
    if data:
        sip_msisdndf = pd.DataFrame(data)
        sip_msisdndf['First seen'] = sip_msisdndf['First seen'].apply(lambda x: x.strftime('%d.%m.%Y'))
        sip_msisdndf['Last seen'] = sip_msisdndf['Last seen'].apply(lambda x: x.strftime('%d.%m.%Y'))
        sip_msisdndf.sort_values(['Counts'], ascending=False, inplace=True)
    else:
        sip_msisdndf = pd.DataFrame()

    # Search msisdn in iri.csv.
    if isiri:
        console.log("parsing iri for msisdn...", style='italic yellow')

        # Load json file to dataframe.
        iridf = pd.read_json(json_file)

        iridf['imei'] = iridf['imei'].astype(str).str[:14]
        iridf = iridf[['imei', 'targetAddress', 'iriTimestamp']]
        iridf['iriTimestamp'] = pd.to_datetime(iridf['iriTimestamp'])

        tid = tid[:14]
        filt = (iridf['imei'] == tid)
        msisdn_list = iridf[filt]['targetAddress'].unique()

        msisdn_dic = {}
        for msisdn in msisdn_list:
            filt = (iridf['targetAddress'] == msisdn)
            fseen = iridf[filt]['iriTimestamp'].min()
            lseen = iridf[filt]['iriTimestamp'].max()
            if msisdn in msisdn_dic:
                pass
            else:
                new_msisdn = MSISDN('IRI', fseen, lseen)
                msisdn_dic[msisdn] = new_msisdn

        data = []
        for msisdn, msisdn_val in msisdn_dic.items():
            data.append({
                'MSISDN': msisdn,
                'Source': msisdn_val.source,
                'First seen': msisdn_val.first_seen,
                'Last seen': msisdn_val.last_seen,
            })


        if data:
            iri_msisdndf = pd.DataFrame(data)
            iri_msisdndf['First seen'] = iri_msisdndf['First seen'].apply(lambda x: x.strftime('%d.%m.%Y'))
            iri_msisdndf['Last seen'] = iri_msisdndf['Last seen'].apply(lambda x: x.strftime('%d.%m.%Y'))
        else:
            iri_msisdndf = pd.DataFrame()


        frame = [sip_msisdndf, iri_msisdndf]
        msisdndf = pd.concat(frame, axis=0).reset_index(drop=True)
        msisdndf['MSISDN'] = msisdndf['MSISDN'].apply(lambda x: f"+{x}")

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
        iri_df, imei_list, isiri = iri_parser(csv_file, json_file)
        isimei, imei_df, gsma_df, msisdndf = imei_parser(pcap_file_, tid, imei_list, iri_df, isiri)
        msisdndf = msisdn_parser(pcap_file_, tid, isiri)

        if isimei:
            console.log("checking GSMA database...", style="italic yellow")
            gsma_df = tac_to_gsma()
            logger.info(f"module {__name__} done")
            return imei_df, gsma_df, iri_df, msisdndf

        logger.info(f"module {__name__} done")
        return imei_df, gsma_df, iri_df, msisdndf


if __name__ == "__main__":
    pass
