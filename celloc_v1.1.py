"""
version:        1.1
Convert iri.csv file to json and extracts IMEI related information as well as locations.

iri.csv is made of several pieces of data and cannot be parsed without additional formating.
Only normalized field (standard data) is processed and converted to json file. This simplify
data processing.

Both Google and Combain apis share the same error codes.
400 = Parse Error / Invalid key.
403 = Out of credits.
404 = Not found (meaning cell tower not found, api is ok).
"""
import csv
import json
import logging
import os
import sys
import time
from textwrap import dedent
import pandas as pd
import numpy as np
import requests
import mobile_codes
from geopy.distance import geodesic
import folium
from folium.plugins import ScrollZoomToggler, HeatMap, Draw, MarkerCluster
from rich import inspect
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.traceback import install
import thy_constants

install(show_locals=False)
console = Console()
logger = logging.getLogger(__name__)

OPENCELLID = thy_constants.OPENCELLID
API_CACHED_ONEYEAR = thy_constants.API_CACHED_ONEYEAR
UNLOCALISED_CACHED_ONEDAY = thy_constants.UNLOCALISED_CACHED_ONEDAY
IRI_FILE = "iri.csv"
IRI_JSON_FILE = "iri.json"

def csv_to_json(csv_f: str, js_file: str) -> None:
    '''Transpose "normalized" field from iri.csv to json format.'''
    json_data = []
    with open(csv_f, newline='\n') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=';')
        next(csv_reader) # Skip headers.

        for row in csv_reader:
            raw_field = row[8] # Field: normalized.
            try:
                json_object = json.loads(raw_field)
                json_data.append(json_object)
            except json.JSONDecodeError:
                print(f"Error decoding json: {raw_field}")

    json_output = json.dumps(json_data, indent=2)
    with open(js_file, 'w') as wf:
        wf.write(json_output)


def json_to_dataframe(js_file: str) -> tuple[pd.DataFrame, dict]:
    '''
    Load json file into a dataframe, flatten its structure and return df.

    Handle both Swiss and non-Swiss cell ids.

    Returns:
    initial_df: nominal dataframe, pd.DataFrame.
    tot_cells_dic: dictionary, dict.
    '''

    # Load json file to dataframe.
    df = pd.read_json(js_file)
    df['imei'] = df['imei'].astype('Int64', copy=False)

    # WARNING: dropna() appears to crash the structure.
    # df = df.dropna()

    # Takes only 14-digit number as n15 is check-digit.
    df.dropna(subset=['imei'], inplace=True)
    df['imei'] = df['imei'].astype(str).str[:14].astype('Int64')

    # Check the content of columns for dictionaries.
    hasdic = []
    cols = df.columns

    def identify_column_content_type(column, col_name):
        '''Check if column contains dictionary values to flatten.'''
        for item in column:
            if isinstance(item, dict):
                hasdic.append(col_name)
                return

    for col in cols:
        identify_column_content_type(df[col], col)

    # rprint(f"Needs flattening:\n[green]{hasdic}[/]")
    # ['domainId',
    #  'targetIPAddress',
    #  'correlationNumber',
    #  'area',
    #  'cell',
    #  'location',
    #  'additionalProperties']

    # If 'location' column not found, it means only non-Swiss cells found.
    # The column is created with np.nan values to get same location format.
    isloc = 'location'
    if isloc not in hasdic:
        hasdic.append(isloc)
        nan = np.nan
        data = [{
                "location": {
                    "lv03": {"e": nan, "n": nan},
                    "lv95": {"e": nan, "n": nan},
                    "wgs84": {"latitude": nan, "longitude": nan},
                    "azimuth": nan}
                }]
        df['location'] = pd.DataFrame(data)

    # Prevent flattening column "addtionalProperties" (redundant data).
    # Only found in non-Swiss data.
    try:
        hasdic.remove('additionalProperties')
    except ValueError:
        pass
    except Exception as exc:
        rprint(f"[red]Exception: [/]{exc}")

    # Flattening columns.
    flattened_dfs = {}
    for col in hasdic:
        try:
            # Split columns.
            flattened_df = pd.json_normalize(df[col])
            # Rename colums.
            flattened_df.columns = [f'{col}_{subcol}' for subcol in flattened_df.columns]
            flattened_dfs[col] = flattened_df
        except Exception as exc:
            rprint(f"[red]{exc}[/]")

    # Drop the original column in original df and concat new columns.
    df = df.drop(hasdic, axis=1)
    for col in hasdic:
        df = pd.concat([df, flattened_dfs[col]], axis=1)

    # Remove empty cell_id.
    base_df = df.dropna(subset=['cell_id'])

    # Split column 'cell_id' (dtypes: object) into values' specific element.
    copy_df = base_df.copy() # Ensure working on copy.

    # ECGI may have NaN values in 'area_id', which must be dropped.
    copy_df = copy_df[~((copy_df['cell_idtype'] == 'ECGI') & (copy_df['area_id'].isna()))]

    copy_df['mcc'] = copy_df['cell_id'].apply(lambda x: x.split('-')[0])
    copy_df['mnc'] = copy_df['cell_id'].apply(lambda x: x.split('-')[1])
    copy_df['lac'] = copy_df.apply(
        lambda row: row['cell_id'].split('-')[2] if row['cell_idtype'] in ['CGI', 'SAI', 'UMTS Cell ID']
        else (row['area_id'].split('-')[2] if row['cell_idtype'] == 'ECGI' else np.nan),
        axis=1)
    copy_df['cid'] = copy_df['cell_id'].apply(lambda x: x.split('-')[-1])

    # Get the initial counts for each cell.
    # This never changes and is only used in mcc_checker().
    copy_df['mcc'] = copy_df['mcc'].astype(str)
    mcc_list = copy_df['mcc'].unique()
    tot_cells_dic = {}
    for mcc in mcc_list:
        filt = (copy_df['mcc'] == mcc)
        tot_cells = copy_df[filt]['cell_id'].count()
        tot_cells_dic[mcc] = tot_cells

    # Remove un-wanted columns dynamically with sets.
    actual_cols = set(copy_df.columns)
    wanted_cols = set([
                    'imei',
                    'imsi',
                    'liid',
                    'iriTimestamp',
                    'targetAddress',
                    'networkElementId',
                    'area_id',
                    'area_idtype',
                    'cell_id',
                    'cell_idtype',
                    'cell_timestamp',
                    'location_azimuth',
                    'location_wgs84.latitude',
                    'location_wgs84.longitude',
                    'targetIPAddress_IPv4Address',
                    'targetIPAddress_IPv6Address',
                    'mcc',
                    'mnc',
                    'lac',
                    'cid',
                    'ecid_short',
                    'area'
                    ])

    to_remove_cols = actual_cols.difference(wanted_cols)
    initial_df = copy_df.drop(list(to_remove_cols), axis=1)
    # Remove leading '0' in mnc.
    initial_df['mnc'] = initial_df['mnc'].str.lstrip('0')

    # HACK: un-comment next 4 lines to test and get only small amount of data.
    # mcc = '222'
    # filt = (initial_df['mcc'] == mcc)
    # initial_df = initial_df[filt]
    # console.log(Panel.fit(f"Filtered on mcc {mcc}",
    #                       border_style='orange_red1',
    #                       title=f'[italic]Testing[/]',
    #                       title_align='left'))

    # Collect statistical data.
    global missing_cells
    missing_cells = 0
    missing_coordinates = initial_df.drop_duplicates(subset=['cell_id'])
    missing_cells = missing_coordinates['location_wgs84.latitude'].isna().value_counts()[0]

    return initial_df, tot_cells_dic


def check_cached_oneyear_db(initial_df_: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    '''
    Cell-towers localisation process:
    1. checking API_CACHED_ONEYEAR <---
    2. checking OpenCellID
    3. checking UNLOCALISED_CACHED_ONEDAY
    4. checking online apis

    Check unknown cell-towers against API_CACHED_ONEYEAR.

    Parameters:
    initial_df_: initial dataframe properly formatted.

    Returns:
    # localised:                    cell-towers localised in API_CACHED_ONEYEAR.
    api_cached_oneyear_init_df:     current API_CACHED_ONEYEAR database.
    api_cached_oneyear_final_df:    new dataframe with updated coordinates (localised []).
    '''
    # API_CACHED_ONEYEAR.parquet only contains data from online API sources.

    init_df = initial_df_

    # Check if API_CACHED_ONEYEAR.parquet exists.
    if os.path.isfile(API_CACHED_ONEYEAR):
        api_cached_oneyear_init_df = pd.read_parquet(API_CACHED_ONEYEAR)
        # Filter on current year.
        ts_cut = int(time.time()) - 31536000 # 1 year.
        filt = (api_cached_oneyear_init_df['ts'] > ts_cut)
        api_cached_oneyear_init_df = api_cached_oneyear_init_df[filt]

    # API_CACHED_ONEYEAR.parquet does not exist, create empty template with columns.
    else:
        cols = ['cell_id', 'lat', 'lon', 'ts', 'source']
        api_cached_oneyear_init_df = pd.DataFrame(columns=cols)
        api_cached_oneyear_init_df.astype({'cell_id': str,
                                           'lat': 'Float64',
                                           'lon': 'Float64',
                                           'ts': 'Int64',
                                           'source': str})

    final_df = init_df.merge(api_cached_oneyear_init_df[['cell_id',
                                                         'lat',
                                                         'lon']],
                                                         on=['cell_id'],
                                                         how='left')

    final_df['lat'] = pd.to_numeric(final_df['lat'], errors='coerce')
    final_df['lon'] = pd.to_numeric(final_df['lon'], errors='coerce')

    # Populate coordinates (lat, lon) to empty location_wgs84 when matches occur.
    # Drop un-necessary columns.
    final_df['location_wgs84.latitude'] = final_df['location_wgs84.latitude']\
                                                            .fillna(final_df['lat'])
    final_df['location_wgs84.longitude'] = final_df['location_wgs84.longitude']\
                                                            .fillna(final_df['lon'])
    api_cached_oneyear_final_df = final_df.drop(['lat', 'lon'], axis=1)

    return api_cached_oneyear_init_df, api_cached_oneyear_final_df


def check_opencellid(
                init_df_: pd.DataFrame,
                api_cached_oneyear_final_df_: pd.DataFrame
                ) -> pd.DataFrame:
    '''
    Cell-towers localisation process:
    1. checking API_CACHED_ONEYEAR
    2. checking OpenCellID <---
    3. checking UNLOCALISED_CACHED_ONEDAY
    4. checking online apis

    Check unknown cell-towers against OpenCellID db.

    Parameters:
    init_df_:                       initial dataframe returned by json_to_dataframe()
    api_cached_oneyear_final_df_:   returned by check_cached_oneyear_db()

    Returns:
    opencellid_df:      dataframe to be used in check_online_apis(), i.e. un-localised.
    '''
    init_df = init_df_
    init_df = init_df.astype({'mcc': 'Int64',
                              'mnc': 'Int8',
                              'lac': 'Int64',
                              'cid':'Int64'})

    df = api_cached_oneyear_final_df_

    # Get un-localised cells, get a copy, remove duplicates on cell_id.
    with_missing_df = df[df['location_wgs84.latitude'].isna()].copy()
    with_missing_df = with_missing_df.drop_duplicates(subset=['cell_id'])
    with_missing_df = with_missing_df.astype({'mcc': 'Int64',
                                              'mnc': 'Int8',
                                              'lac': 'Int64',
                                              'cid': 'Int64'})

    # Load OpenCellID database.
    ocid_df = pd.read_parquet(OPENCELLID, columns=['mcc', 'net', 'area', 'cell', 'lon', 'lat'])

    with_missing_df = with_missing_df.merge(ocid_df[['mcc', 'net', 'area', 'cell', 'lat', 'lon']],
                                    left_on=['mcc', 'mnc', 'lac', 'cid'],
                                    right_on=['mcc', 'net', 'area', 'cell'],
                                    how='left')

    # Ensure proper handling of NaN values.
    with_missing_df['lat'] = pd.to_numeric(with_missing_df['lat'], errors='coerce')
    with_missing_df['lon'] = pd.to_numeric(with_missing_df['lon'], errors='coerce')

    # Populate coordinates (lat, lon) to empty location_wgs84 when matches occur.
    # Drop nan and duplicates.
    with_missing_df['location_wgs84.latitude'] = with_missing_df['location_wgs84.latitude']\
                                                            .fillna(with_missing_df['lat'])
    with_missing_df['location_wgs84.longitude'] = with_missing_df['location_wgs84.longitude']\
                                                            .fillna(with_missing_df['lon'])
    with_missing_df = with_missing_df.drop(['lat', 'lon', 'cell', 'area', 'net'], axis=1)
    with_missing_df.dropna(subset=['location_wgs84.latitude'], inplace=True)
    with_missing_df.drop_duplicates(subset=['cell_id'], inplace=True)

    # Collect statistical data.
    global opencellid_localised
    opencellid_localised = 0
    stat_df = with_missing_df.drop_duplicates(subset=['cell_id'])
    opencellid_localised = stat_df['location_wgs84.latitude'].isna().value_counts().sum()

    # Get a copy of df from precend stage.
    # Merge new localised coordinates with df copy.
    final_df = df.copy()
    final_df = final_df.merge(
                            with_missing_df[[
                                            'cell_id',
                                            'location_wgs84.latitude',
                                            'location_wgs84.longitude'
                                            ]],
                                            on=['cell_id'],
                                            how='left',
                                            suffixes=('', '_updated'))

    # Populate coordinates (_updated) to empty location_wgs84 when matches occur, drop _updated.
    final_df['location_wgs84.latitude'] = final_df['location_wgs84.latitude']\
                                            .fillna(final_df['location_wgs84.latitude_updated'])
    final_df['location_wgs84.longitude'] = final_df['location_wgs84.longitude']\
                                            .fillna(final_df['location_wgs84.longitude_updated'])
    final_df = final_df.drop(
                        ['location_wgs84.latitude_updated', 'location_wgs84.longitude_updated'],
                        axis=1)

    opencellid_df = final_df

    return opencellid_df


# TODO: split check_online_apis() and check_cached_oneday()
# UNLOCALISED_CACHED_ONEDAY will always exist, so no need to check this

def check_online_apis(
                      api_cached_oneyear_init_df_: pd.DataFrame,
                      opencellid_df_: pd.DataFrame
                      ) -> pd.DataFrame:
    '''
    Cell-towers localisation process:
    1. checking API_CACHED_ONEYEAR
    2. checking OpenCellID
    3. checking UNLOCALISED_CACHED_ONEDAY <---
    4. checking online apis <---

    Check unknown cell-towers against online apis db.

    Parameters:
    api_cached_oneyear_init_df_:   data from API_CACHED_ONEYEAR.parquet.
    opencellid_df_:                data from OpenCellID.

    Returns:
    final_df:   final dataframe.
    '''
    # The purpose of UNLOCALISED_CACHED_ONEDAY is to prevent duplicate requests on paid services.

    api_cached_oneyear_init_df = api_cached_oneyear_init_df_
    df = opencellid_df_

    # Get rid off every cell-towers identified by OpenCellID.
    with_missing_df = df[df['location_wgs84.latitude'].isna()].copy()

    # Create a set with (cell_id, mcc, mnc, lac and cid).
    # Set will get rid off duplicates automatically.
    data = set()
    for _, row in with_missing_df.iterrows():
        cell_data = (row['cell_id'], row['mcc'], row['mnc'], row['lac'], row['cid'])
        data.add(cell_data)
    console.log(inspect(data, title='check_online_apis - data set', all=False))

    # HACK: un-comment 4 next lines to limit data to n number of cells (modify n accordingly).
    # n = 0
    # data = sorted(data)
    # data = list(data)[:n]
    # console.log(Panel.fit(f"Restricted to [cyan]{n}[/] cells.",
    #                       border_style='orange_red1',
    #                       title='[italic]Testing online APIs[/]',
    #                       title_align='left'))

    # TODO: if file exist first check if modification date > 24 hours.
    # if > 24, then remove and continue like if not exist
    # else check_cached_oneday()
 
    # Check on UNLOCALISED_CACHED_ONEDAY first.
    # Un-localised cell-towers are stored for 1 day to prevent re-checks.
    if os.path.isfile(UNLOCALISED_CACHED_ONEDAY):
        console.log(Panel.fit("check_cached_oneday()"))
        in_cached_oneday = check_cached_oneday(data)
        console.log(inspect(in_cached_oneday, title='411 in_cached_oneday', all=False))

        if len(in_cached_oneday) == len(data):
            console.log(Panel.fit
                            ("Every cell-tower already checked in the past 24 hours.",
                            border_style='orange_red1')
                        )
            logger.info("Every cell-tower already checked in the past 24 hours.")
            return df

    else:
        # WARNING: in this current version summary() will trigger errors if the file UNLOCALISED_CACHED_ONEDAY exists!

        # Perform the checks in google and combain apis.
        localised_list, api_localised_df, api_unlocalised_df = check_cell_towers(data)

        # Create dataframe with cell tower locations.
        cols = ['cell_id', 'lat', 'lon', 'ts', 'source']
        new_loc_df = pd.DataFrame(localised_list, columns=cols)

        global number_cellid
        global n_google
        global google_ratio
        global n_combain
        global combain_ratio

        number_cellid = new_loc_df.shape[0]
        n_google = new_loc_df[new_loc_df['source'] == 'google'].value_counts().sum()
        n_combain = new_loc_df[new_loc_df['source'] == 'combain'].value_counts().sum()
        if number_cellid != 0:
            google_ratio = ((n_google * 100) / number_cellid) if (n_google > 0) else 0
            combain_ratio = ((n_combain * 100) / (number_cellid - n_google)) if (n_combain > 0) else 0
        else:
            combain_ratio = 0
            google_ratio = 0

        # Continue with updating API_CACHED_ONEYEAR.parquet.
        updated_cached_oneyear_df = pd.concat([api_cached_oneyear_init_df, new_loc_df])
        updated_cached_oneyear_df = updated_cached_oneyear_df.sort_values('ts')\
                                                .drop_duplicates(subset=['cell_id'], keep='last')
        updated_cached_oneyear_df.to_parquet(API_CACHED_ONEYEAR, index=False)

        # Create UNLOCALISED_CACHED_ONEDAY.parquet only if un-localised cells found.
        # api_unlocalised_df is created in check_cell_towers().
        if not api_unlocalised_df.empty:
            api_unlocalised_df.to_parquet(UNLOCALISED_CACHED_ONEDAY, index=False)

    # Merge coordinates found in check_cell_towers()
    with_missing_df = with_missing_df.merge(
                                            api_localised_df[['cell_id', 'lat', 'lon']],
                                            on=['cell_id'],
                                            how='left'
                                            )

    # # Ensure proper handling of NaN values.
    with_missing_df['lat'] = pd.to_numeric(with_missing_df['lat'], errors='coerce')
    with_missing_df['lon'] = pd.to_numeric(with_missing_df['lon'], errors='coerce')

    # Populate coordinates (lat, lon) to empty location_wgs84 when matches occur.
    # Drop un-necessary columns.
    with_missing_df['location_wgs84.latitude'] = with_missing_df['location_wgs84.latitude']\
                                                        .fillna(with_missing_df['lat'])
    with_missing_df['location_wgs84.longitude'] = with_missing_df['location_wgs84.longitude']\
                                                        .fillna(with_missing_df['lon'])
    with_missing_df = with_missing_df.drop(['lat', 'lon'], axis=1)

    with_missing_df.dropna(subset=['location_wgs84.latitude'], inplace=True)
    with_missing_df.drop_duplicates(subset=['cell_id'], inplace=True)

    final_df = df.copy()
    final_df = final_df.merge(
                            with_missing_df[['cell_id',
                                            'location_wgs84.latitude',
                                            'location_wgs84.longitude']],
                                            on=['cell_id'],
                                            how='left',
                                            suffixes=('', '_updated')
                            )

    final_df['location_wgs84.latitude'] = final_df['location_wgs84.latitude']\
                                            .fillna(final_df['location_wgs84.latitude_updated'])
    final_df['location_wgs84.longitude'] = final_df['location_wgs84.longitude']\
                                            .fillna(final_df['location_wgs84.longitude_updated'])
    final_df = final_df.drop(
                            ['location_wgs84.latitude_updated', 'location_wgs84.longitude_updated'],
                            axis=1
                            )

    return final_df


def check_cached_oneday(data_: set) -> set:
    '''
    Check non-localised cells against UNLOCALISED_CACHED_ONEDAY.parquet.
    This is the list of non-localised cell-towers that have been
    already checked in the past 24 hours (prevent re-checks).

    Parameters:
    data_: un-localised data.

    Returns:
    in_cached_oneday_set: cell-towers found in UNLOCALISED_CACHED_ONEDAY.parquet.

    '''
    # Load UNLOCALISED_CACHED_ONEDAY.parquet data.
    api_cached_oneday_df = pd.read_parquet(UNLOCALISED_CACHED_ONEDAY)
    ts_cut = (int(time.time()) - 86400) # 1 day.
    filt = (api_cached_oneday_df['ts'] > ts_cut)
    df = api_cached_oneday_df[filt]

    in_cached_oneday_set = set()
    cellt_list = list(data_)
    for cell in cellt_list:
        if cell[0] in df['cell_id'].values:
            in_cached_oneday_set.add(cell[0])
    console.log(inspect(in_cached_oneday_set, title='in_cached_oneday_set', all=False))


    # HACK: not tested yet!
    # new (now, rows) and modifications.
    now = int(time.time()) # new.
    rows = [(cid, now) for cid in in_cached_oneday_set] # new.

    cols = ['cell_id', 'ts']
    now_in_cached_oneday_df = pd.DataFrame(rows, columns=cols) # modified.
    updated_cached_oneday_df = pd.concat([api_cached_oneday_df, now_in_cached_oneday_df])
    updated_cached_oneday_df = updated_cached_oneday_df.sort_values('ts')\
                                    .drop_duplicates(subset=['cell_id'], keep='last')
    updated_cached_oneday_df.to_parquet(UNLOCALISED_CACHED_ONEDAY, index=False)

    # INFO: original version.
    # Load current UNLOCALISED_CACHED_ONEDAY.parquet and update.
    # cols = ['cell_id', 'ts']
    # now_in_cached_oneday_df = pd.DataFrame(in_cached_oneday_set, columns=cols)
    # now_in_cached_oneday_df['ts'] = int(time.time())
    # updated_cached_oneday_df = pd.concat([api_cached_oneday_df, now_in_cached_oneday_df])
    # updated_cached_oneday_df = updated_cached_oneday_df.sort_values('ts')\
    #                                 .drop_duplicates(subset=['cell_id'], keep='last')
    # updated_cached_oneday_df.to_parquet(UNLOCALISED_CACHED_ONEDAY, index=False)

    return in_cached_oneday_set


def check_cell_towers(cell_tower_data_list_: set) -> tuple[list[int], pd.DataFrame, pd.DataFrame]:
    '''
    Take list(set) of cell-towers which are not identified by OpenCellID.
    Feed api_requester() with a set of cell-towers, parse answers.

    Parameters:
    cell_tower_data_list_: set of cell-towers to be checked.

    Return:
    localised:          data format of cell-towers (cell_id, lat, lon, ts).
    api_localised_df:   dataframe of localised cell-towers by apis.
    api_unlocalised_df: dataframe of un_localised cell-towers.
    '''

    ctdl = cell_tower_data_list_

    global launch_google_api
    global launch_combain_api
    global error_google_api
    global error_combain_api

    localised = []
    not_localised = []

    # Determine if google and combain works properly.
    # False: errors 400 or 403.
    # Do not put inside while loop.
    error_google_api = False
    error_combain_api = False
    i = 0
    while i < len(ctdl):
        launch_google_api = True
        launch_combain_api = False

        cell_tower_data = [
            {
                "mobileCountryCode": list(ctdl)[i][1], # mcc.
                "mobileNetworkCode": list(ctdl)[i][2], # mnc.
                "locationAreaCode": list(ctdl)[i][3],  # lac.
                "cellId": list(ctdl)[i][4]             # cid.
            }
        ]

        # Google Api.
        if launch_google_api and not error_google_api:
            GOOGLE_API_KEY = thy_constants.GOOGLE_API_KEY
            url = f"https://www.googleapis.com/geolocation/v1/geolocate?key={GOOGLE_API_KEY}"
            result = api_requester('google', url, cell_tower_data)
            if result:
                lat = result['location']['lat']
                lon = result['location']['lng']
                ts = int(time.time())
                localised.append([list(ctdl)[i][0], lat, lon, ts, 'google'])
        # Combain api.
        if launch_combain_api and not error_combain_api:
        # if not error_combain_api:
            COMBAIN_API_KEY = thy_constants.COMBAIN_API_KEY
            url = f"https://apiv2.combain.com?key={COMBAIN_API_KEY}"
            result = api_requester('combain', url, cell_tower_data)
            if result:
                lat = result['location']['lat']
                lon = result['location']['lng']
                ts = int(time.time())
                localised.append([list(ctdl)[i][0], lat, lon, ts, 'combain'])
            else:
                not_localised.append(list(ctdl)[i][0])

        # Do not make api requests anymore.
        if error_google_api and error_combain_api:
            break

        i += 1

    # Create dataframe with cell tower locations.
    cols = ['cell_id', 'lat', 'lon', 'ts', 'source']
    api_localised_df = pd.DataFrame(localised, columns=cols)

    # Create dataframe with un-localised cell_id.
    cols = ['cell_id']
    api_unlocalised_df = pd.DataFrame(not_localised, columns=cols)
    api_unlocalised_df['ts'] = int(time.time())

    return localised, api_localised_df, api_unlocalised_df


def api_requester(api: str, url_: str, celltower_data: list):
    '''
    Handle POST requests process on Cell-Towers db and apis.

    Called in check_cell_towers().

    Parameters:
    api: name of api being checked, str.
    celltower_data: contains unique cell tower data, dict.

    Returns:
    response: should be dict[str, any].
    '''
    global launch_google_api
    global launch_combain_api
    global error_google_api
    global error_combain_api

    headers = {
        "Content-Type": "application/json"
    }
    request_data = {
        "considerIp": False,
        "cellTowers": celltower_data
    }

    current_delay = 0.1 # Set initial retry delay to 100ms.
    max_delay = 3 # Set maximum retry delay to 3s (5 attempts).
    while True:
        try:
            response = requests.post(url_, headers=headers, json=request_data)
            response.raise_for_status() # Raise an exception for 4xx/5xx errors.
            return  response.json() # If successful, return the result.

        except requests.exceptions.ConnectionError:
            rprint("[red]Network error: unable to connect to Internet.")
            logger.error("Network error: unable to connect to Internet.")
            sys.exit(9)

        except requests.exceptions.HTTPError:
            status_code = response.status_code

            # Cell tower not found, no point retrying.
            if status_code == 404:
                if api == 'google':
                    launch_combain_api = True
                break

            # Api issues (limit or key), no point retrying.
            error_msg = dedent('''\
                                400 = Parse Error / Invalid key.
                                403 = Out of credits.''')

            if status_code in (400, 403):
                if api == 'google':
                    console.log(Panel.fit(
                        f"Something went wrong with Google api: {status_code = }\n{error_msg}",
                        border_style='red'))
                    logger.error(
                        f"Something went wrong with Google api: {status_code = }\n{error_msg}")
                    error_google_api = True
                    launch_combain_api = True
                elif api == 'combain':
                    console.log(Panel.fit(
                        f"Something went wrong with Combain api: {status_code = }\n{error_msg}",
                        border_style='red'))
                    logger.error(
                        f"Something went wrong with Combain api: {status_code = }\n{error_msg}")
                    error_combain_api = True
                break

        # Too many attempts, meaning something is wrong with internet connection.
        # If both Google and Combain encounter issues, script should stop.
        if current_delay > max_delay:
            if api == 'google':
                rprint("[red]Google api not reachable! Continuing with Combain only[/]")
                logger.error("Google api not reachable! Continuing with Combain only")
                launch_google_api = False
            elif api == 'combain':
                rprint("[red]Combain api not reachable either![/]")
                logger.error("Combain api not reachable either")
                launch_combain_api = False
            raise Exception("Too many retry attempts.")

        # For other errors (like network issues), retry with exponential backoff.
        print(f"Waiting {current_delay}s before retrying.")
        logger.info(f"Waiting {current_delay}s before retrying.")
        time.sleep(current_delay)
        current_delay *= 2 # Increase delay at each retrial.


class Cell():
    '''Instantiate cell-tower data.'''
    def __init__(self,
                 id_,
                 imei_,
                 latitude_,
                 longitude_,
                 azimuth_,
                 first_seen_,
                 last_seen_,
                 count_,
                 mcc_,
                 source_):

        self.id: str = id_
        self.imei: int = imei_
        self.latitude: float = latitude_
        self.longitude: float = longitude_
        self.azimuth: list[int] = [azimuth_]
        self.first_seen: str = first_seen_
        self.last_seen: str = last_seen_
        self.count: int = count_
        self.mcc: str = mcc_
        self.source: str = source_

    def increment_cell_count(self):
        '''Increment counter per cell.'''
        self.count += 1

    def append_azimuth(self, azimuth: int):
        '''Add azimuth data per cell.'''
        self.azimuth.append(azimuth)

    def update_time_seen(self, first_seen: str, last_seen: str):
        '''Add time information per cell.'''
        self.first_seen = first_seen
        self.last_seen = last_seen


def dataframe_parser(dataframe: pd.DataFrame) -> pd.DataFrame:
    '''
    Parse the dataframe to get unique cell location related data only.
    Called in transpose_cells_on_map().

    dataframe: should be final_df (other possible too).

    Returns:
    celldf: data used in the map, pd.DataFrame.
    '''

    df = dataframe[['cell_id', 'imei', 'location_wgs84.latitude', 'location_wgs84.longitude',
             'location_azimuth', 'cell_timestamp', 'mcc']]

    # Convert timestamp to datetime, this will be beneficial later.
    pd.set_option('mode.chained_assignment', None)
    df['cell_timestamp'] = pd.to_datetime(df.loc[:, 'cell_timestamp'])

    # DO NOT REMOVE!
    df = df.dropna(subset=['location_wgs84.latitude', 'location_wgs84.longitude'], how='any')

    # Fill in empty azimuth with 0, will only apply on non-Swiss cells.
    df['location_azimuth'] = df['location_azimuth'].fillna(0)

    # Convert time from UTC to Europe/Zurich.
    df['cell_timestamp'] = pd.to_datetime(df['cell_timestamp'])
    df['cell_timestamp'] = df['cell_timestamp'].dt.tz_convert('UTC')
    df['cell_timestamp'] = df['cell_timestamp'].dt.tz_convert('Europe/Zurich')

    # Get unique cells.
    cells: list[str] = df['cell_id'].unique()

    cell_dic: dict = {}
    firstseen = ''
    lastseen = ''

    # Load cached data to assign source to each cell-tower.
    cols = ['cell_id', 'source']
    api_cached_oneyear = pd.read_parquet(API_CACHED_ONEYEAR, columns=cols)

    for cell in cells:
        # Filter on iri data.
        filt = (df['cell_id'] == cell)
        cellid = cell
        mcc = df[filt]['mcc'].unique()[0]
        imei = df[filt]['imei'].unique()[0]
        lat = df[filt]['location_wgs84.latitude'].unique()[0]
        long = df[filt]['location_wgs84.longitude'].unique()[0]
        azimuth = df[filt]['location_azimuth'].unique()
        firstseen = df[filt]['cell_timestamp'].min()
        lastseen = df[filt]['cell_timestamp'].max()
        counts = df[filt].value_counts().sum()

        # Filter on cached data.
        filt = (api_cached_oneyear['cell_id'] == cell)
        source = api_cached_oneyear[filt]['source']
        # If no match, size == 0.
        if source.size > 0:
            source = api_cached_oneyear[filt]['source'].item().capitalize()
        elif cell.startswith('228'):
            source = 'Swiss Network'
        else:
            source = 'OpenCelliD'

        cell = Cell(cellid, imei, lat, long, azimuth, firstseen, lastseen, counts, mcc, source)
        cell_dic[cellid] = cell

    # Build cells data and create dataframe.
    cell_data: list = []
    for _, val in cell_dic.items():
        try:
            cell_data.append({
                'Cell_id': val.id,
                'mcc': val.mcc,
                'IMEI': val.imei,
                'Counts': val.count,
                'lat': val.latitude,
                'long': val.longitude,
                'azimuth': val.azimuth,
                'First_seen': val.first_seen,
                'Last_seen': val.last_seen,
                'source': val.source
            })
        except Exception as exc:
            print(f"Error: {exc}")

    celldf = pd.DataFrame(cell_data)
    # Folium heatmap requires weight from 0 to 1.
    max_counts = celldf['Counts'].max()
    zeros = int(len(str(max_counts))) # e.g.: int(1234) = str(4).
    divider = 10**zeros # e.g.: for 1234 => 10000.
    celldf['weight'] = (celldf['Counts'] / divider)
    celldf['First_seen'] = celldf['First_seen'].dt.strftime('%d.%m.%Y %H:%M:%S %z')
    celldf['Last_seen'] = celldf['Last_seen'].dt.strftime('%d.%m.%Y %H:%M:%S %z')

    return celldf


def add_azimuth_line(
                    map_object,
                    start_lat: float,
                    start_lon: float,
                    azimuth: int,
                    length_km: float,
                    tool_tip: int
                    ) -> None:
    '''
    Add azimuth line to each cell using geodesic calculation.
    map_object: folium object.
    '''
    cell_location = (start_lat, start_lon)
    end_point = geodesic(kilometers=length_km).destination(cell_location, azimuth)
    end_lat, end_lon = end_point.latitude, end_point.longitude
    folium.PolyLine([(start_lat, start_lon), (end_lat, end_lon)],
                    weight=5, opacity=0.4, color='#08F7FE', tooltip=tool_tip).add_to(map_object)


def transpose_cells_on_map(dataframe: pd.DataFrame) -> str:
    '''
    Transpose cell tower coordinates on map.
    dataframe: final_df.
    '''
    celldf = dataframe_parser(dataframe)

    # Center map on Switzerland centre position.
    m = folium.Map(location=[46.8182, 8.2275], zoom_start=2, tiles="Cartodb voyager")
    # m = folium.Map(location=[46.8182, 8.2275], zoom_start=2, tiles="Cartodb positron")
    # m = folium.Map(location=[46.8182, 8.2275], zoom_start=2, tiles="Cartodb dark_matter")
    # m = folium.Map(location=[46.8182, 8.2275], zoom_start=2, tiles="openstreetmap")

    # Block scroll zoom by default.
    scrollonoff = ScrollZoomToggler()
    m.add_child(scrollonoff)

    # Allow to draw shapes and add markers.
    Draw(export=False).add_to(m)

    # Add search tool to map.
    folium.plugins.Geocoder().add_to(m)

    # Add features on upper right handside corner.
    heat = folium.FeatureGroup("Cell HeatMap", show=True).add_to(m)
    cell_azimuth = folium.FeatureGroup("Cell Azimuth", show=False).add_to(m)
    cell_data = folium.FeatureGroup("Cell Data", show=False).add_to(m)
    m_cluster = MarkerCluster().add_to(cell_data)

    # Create popup content for cell_data (iterrows: index, row).
    for _, row in celldf.iterrows():
        popup_content = f"""
                        <strong>Cell id: {row['Cell_id']}</strong><br>
                        Source: {row['source']}<br>
                        Latitude: {row['lat']}<br>
                        Longitude: {row['long']}<br>
                        Azimuth: {int(row['azimuth'][0][0])}<br>
                        <br>
                        IMEI: {row['IMEI']}<br>
                        First seen: {row['First_seen']}<br>
                        Last seen: {row['Last_seen']}<br>
                        Counts: {row['Counts']}
                        """

        # popup: on click, tooltip: on hover.
        folium.Marker(location=[row['lat'], row['long']],
                      popup=folium.Popup(popup_content, max_width=250),
                      tooltip=f"{row['Cell_id']} ({row['source'][0]})")\
                      .add_to(m_cluster)

    # Get each cell-tower coordinates, longitude: x-axis, latitude: y-axis.
    data = []
    for _, row in celldf.iterrows():
        # Get cell location and cell counter.
        cell_data = [row['lat'], row['long'], row['weight']]
        data.append(cell_data)

        # Draw azimuth line.
        latitude = row['lat']
        longitude = row['long']
        km = 2.5

        # Add azimuth for Swiss cell only.
        if row['Cell_id'].startswith('228'):
            for azimuth_list in row['azimuth']:
                for azimuth in azimuth_list:
                    tool_tip_tag = int(azimuth)
                    add_azimuth_line(cell_azimuth, latitude, longitude, azimuth, km, tool_tip_tag)

    # Default, radius=25, blur=15.
    HeatMap(data).add_to(heat)

    folium.LayerControl().add_to(m)

    map_file = 'cells.html'

    m.save(map_file)

    return map_file


# WARNING: in this current version summary() will trigger errors if the file UNLOCALISED_CACHED_ONEDAY exists!
def summary() -> None:
    '''
    Display some statistics.

    The data in API_CACHED_ONEYEAR.parquet only concerns cell-towers whose coordinates
    have been found by Google and Combain APIS.

    missing_cells, opencellid_localised, n_google and n_combain are global variables.
    '''
    def ratios(n_by_api: int) -> str:
        '''Return ratios.'''
        ratio = (n_by_api * 100) / missing_cells
        return f"{ratio:.2f}%"

    output = dedent(f'''\
        Unique un-localised cell-towers:        {missing_cells}
        Cell-towers identified by openCellId:   {str(opencellid_localised).ljust(8)}{ratios(opencellid_localised)}
        Cell-towers identified by Google:       {str(n_google).ljust(8)}{ratios(n_google)}
        Cell-towers identified by Combain:      {str(n_combain).ljust(8)}{ratios(n_combain)}''')

    console.log(Panel.fit(output,
                          border_style='cyan',
                          title='[italic]󰐻 Cell-Towers Geolocation Stats[/]',
                          title_align='left'))
    logger.info(f"\n{output}")


def mcc_checker(finaldf_: pd.DataFrame, cell_counter_dic: dict) -> pd.DataFrame:
    '''
    Statistics on cell-towers and localisation ratios.
    '''
    # Counters for initial cells do not change over time.
    # Values comes from json_to_dataframe().
    tot_cell = cell_counter_dic

    # Get the list of unique mcc.
    df = finaldf_
    df['mcc'] = df['mcc'].astype(str)
    mcc_list = df['mcc'].unique()

    # Create the data structure for statistics.
    data = []
    for mcc in mcc_list:
        filt = (df['mcc'] == mcc)
        country_name = mobile_codes.mcc(mcc)[0].name if mobile_codes.mcc(mcc) else "UNKNOWN"
        unique_cells = df[filt]['cell_id'].nunique()
        unique_cell_df = df[filt].drop_duplicates(subset=['cell_id'])
        unique_localised = unique_cell_df[unique_cell_df['location_wgs84.latitude']\
                            .notna()]['cell_id'].nunique()
        loc_success = ((unique_localised * 100) / unique_cells) if (unique_cells > 0) else 0
        data.append([mcc,
                     country_name,
                     tot_cell[mcc],
                     unique_cells,
                     unique_localised,
                     f"{loc_success:.2f}"])

    cols = ['MCC', 'Country', 'Total_cells', 'Unique_cells', 'Localised', 'Loc_Rates (%)']
    stat_df = pd.DataFrame(sorted(data), columns=cols)

    return stat_df


def main() -> tuple[str, pd.DataFrame]:
    '''
    Script launcher.

    Cell-towers localisation process:
    1. checking API_CACHED_ONEYEAR
    2. checking OpenCellID
    3. checking UNLOCALISED_CACHED_ONEDAY
    4. checking online apis
    '''
    with console.status("[bold italic green]Processing celloc.py...[/]") as _:
        console.log("converting csv to json to dataframe...", style="italic yellow")
        csv_to_json(IRI_FILE, IRI_JSON_FILE)
        initial_df, counter_dic = json_to_dataframe(IRI_JSON_FILE)

        console.log("checking cached data...", style="italic yellow")
        api_cached_oneyear_init_df, api_cached_oneyear_final_df = check_cached_oneyear_db(initial_df)

        console.log("checking cells...", style="italic yellow")
        opencellid_df = check_opencellid(initial_df, api_cached_oneyear_final_df)
        final_df = check_online_apis(api_cached_oneyear_init_df, opencellid_df)

        # WARNING: in this current version summary() will trigger errors if the file UNLOCALISED_CACHED_ONEDAY exists!
        console.log("transposing cells on map...", style="italic yellow")
        cell_mapfile = transpose_cells_on_map(final_df)
        try:
            summary()
        except Exception as exc:
            console.log(Panel.fit(f"Error: {exc}"))

        stat_df = mcc_checker(final_df, counter_dic)
        inspect(stat_df, title='1054', all=False)

    logger.info(f"module {__name__} done")
    return cell_mapfile, stat_df


if __name__ == "__main__":
    pass
