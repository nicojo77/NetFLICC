"""
version:        1.2
Get IP geolocation with MAXMIND databases.
"""
import ipaddress
import linecache
import logging
import sys
from functools import lru_cache
import glob as gb
import pandas as pd
import folium
from folium.plugins import MarkerCluster, ScrollZoomToggler
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.traceback import install

install(show_locals=False)
console = Console()
logger = logging.getLogger(__name__)

@lru_cache
def logfile_to_dataframe(log: str) -> pd.DataFrame:
    '''Format zeek log files to Pandas dataframe'''
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

    # Ensure no trailing new line character exists.
    df.columns = df.columns.str.strip()

    return df


class IP:
    '''Instantiate IP element.'''
    def __init__(self,
                 count_,
                 country_code_,
                 region_,
                 city_,
                 lat_,
                 lon_,
                 asn_,
                 as_org_,
                 first_seen_,
                 last_seen_):

        self.counts = count_
        self.country_c = country_code_
        self.region = region_
        self.city = city_
        self.lat = lat_
        self.lon = lon_
        self.asn = asn_
        self.as_org = as_org_
        self.first_seen = first_seen_
        self.last_seen = last_seen_


def geolocation_dataframe(id_type: str) -> pd.DataFrame:
    '''
    Create dataframe with geolocation data.

    id_type is either: 'orig' or 'resp'.

    Returns: geoip.
    '''
    conn_df = logfile_to_dataframe('conn.log')

    geo_df = conn_df[[
                    'ts',
                    f'id.{id_type}_h',
                    f'geo.{id_type}.country_code',
                    f'geo.{id_type}.region',
                    f'geo.{id_type}.city',
                    f'geo.{id_type}.latitude',
                    f'geo.{id_type}.longitude',
                    f'geo.{id_type}.as_number',
                    f'geo.{id_type}.as_org'
                    ]]

    geo_df.sort_values(f'geo.{id_type}.as_number', ascending=False, inplace=True)

    ips_dic = {}

    # Use values[0] instead of unique() to prevent treating data as array element,
    # which adds extra surrounding characters later in dataframe [''].
    for ip in geo_df[f'id.{id_type}_h'].unique():
        if not isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address): # Reject ipv6.
            filt = (geo_df[f'id.{id_type}_h'] == ip )
            countrycode = geo_df[filt][f'geo.{id_type}.country_code'].values[0]
            region = geo_df[filt][f'geo.{id_type}.region'].values[0]
            city = geo_df[filt][f'geo.{id_type}.city'].values[0]
            latitude = geo_df[filt][f'geo.{id_type}.latitude'].values[0]
            longitude = geo_df[filt][f'geo.{id_type}.longitude'].values[0]
            asn = geo_df[filt][f'geo.{id_type}.as_number'].values[0]
            asorg = geo_df[filt][f'geo.{id_type}.as_org'].values[0]
            counts = geo_df[filt][f'id.{id_type}_h'].value_counts().values[0]
            firstseen = geo_df[filt]['ts'].min()
            firstseen = firstseen.strftime('%d.%m.%Y %H:%M:%S %z')
            lastseen = geo_df[filt]['ts'].max()
            lastseen = lastseen.strftime('%d.%m.%Y %H:%M:%S %z')

            # Folium will not process empty values.
            if latitude == '-' or longitude == '-':
                continue

            # Assign values to the ips.
            processed_ip = IP(counts,
                              countrycode,
                              region,
                              city,
                              latitude,
                              longitude,
                              asn,
                              asorg,
                              firstseen,
                              lastseen)
            # Build the dictionary.
            if ip not in ips_dic:
                ips_dic[ip] = processed_ip

    data = []
    for ip, ip_val in ips_dic.items():
        data.append({
            'Source_ip': ip,
            'Counts': ip_val.counts,
            'CC': ip_val.country_c,
            'Rgn': ip_val.region,
            'City': ip_val.city,
            'Lat.': ip_val.lat,
            'Long.': ip_val.lon,
            'ASN': ip_val.asn,
            'ASN_org': ip_val.as_org,
            'First_seen': ip_val.first_seen,
            'Last_seen': ip_val.last_seen
        })

    geoip = pd.DataFrame(data)

    # Process only if geoip is not empty.
    if not geoip.empty:
        geoip.sort_values(['Counts'], ascending=False, inplace=True)

    return geoip


def transpose_ips_on_map() -> tuple[str, pd.DataFrame, pd.DataFrame]:
    '''
    Transpose ip addresses to map.

    Returns:
    map_file: file name.
    orig_ip and resp_ip: pd.DataFrame.
    '''
    orig_ip = geolocation_dataframe('orig')
    resp_ip = geolocation_dataframe('resp')

    if orig_ip.empty and resp_ip.empty:
        map_file = ''
    else:
        # Center map on Switzerland centre position.
        m = folium.Map(location=[46.8182, 8.2275], zoom_start=2, tiles="Cartodb voyager")
        # m = folium.Map(location=[46.8182, 8.2275], zoom_start=2, tiles="openstreetmap")
        # m = folium.Map(location=[46.8182, 8.2275], zoom_start=2, tiles="Cartodb dark_matter")
        # m = folium.Map(location=[46.9545639, 7.3123655], zoom_start=2, tiles="Cartodb dark_matter")

        # Allow to scrolling if button pressed.
        scrollonoff = ScrollZoomToggler()
        m.add_child(scrollonoff)

        # Group_1: id.orig_h.
        group_1 = folium.FeatureGroup("Incoming traffic (originator)").add_to(m)
        m_cluster = MarkerCluster().add_to(group_1)
        for _, row in orig_ip.iterrows():
            popup_content = f"""
                            <strong>{row['Source_ip']}</strong><br>
                            Traffic direction: incoming<br>
                            Counts: {row['Counts']}<br>
                            First seen: {row['First_seen']}<br>
                            Last seen: {row['Last_seen']}<br>
                            AS: {row['ASN']} ({row['ASN_org']})<br>
                            City: {row['City']}<br>
                            Region: {row['Rgn']}<br>
                            Country: {row['CC']}
                            """
            # popup: on hover, tooltip: on click.
            folium.Marker(location=[row['Lat.'], row['Long.']],
                        popup=folium.Popup(popup_content, max_width=250),
                        tooltip=f"{row['Source_ip']}")\
                        .add_to(m_cluster)

        # Group_2: id.resp_h.
        group_2 = folium.FeatureGroup("Outgoing traffic (responder)").add_to(m)
        m_cluster = MarkerCluster().add_to(group_2)
        for _, row in resp_ip.iterrows():
            popup_content = f"""
                            <strong>{row['Source_ip']}</strong><br>
                            Traffic direction: outgoing<br>
                            Counts: {row['Counts']}<br>
                            First seen: {row['First_seen']}<br>
                            Last seen: {row['Last_seen']}<br>
                            AS: {row['ASN']} ({row['ASN_org']})<br>
                            City: {row['City']}<br>
                            Region: {row['Rgn']}<br>
                            Country: {row['CC']}
                            """
            folium.Marker(location=[row['Lat.'], row['Long.']],
                        popup=folium.Popup(popup_content, max_width=250),
                        tooltip=f"{row['Source_ip']}")\
                        .add_to(m_cluster)

        folium.LayerControl().add_to(m)

        map_file = 'ipsmap.html'
        m.save(map_file)

    return map_file, orig_ip, resp_ip


def main() -> tuple[str, pd.DataFrame, pd.DataFrame]:
    '''
    Script launcher.

    Returns:
    ip_mapfile: tuple[str, pd.DataFrame, pd.DataFrame]
    '''
    with console.status("[bold italic green]Processing geoip_v2.py...[/]") as _:
        console.log("processing ips for mapping...", style="italic yellow")
        ip_mapfile, orig_ip, resp_ip = transpose_ips_on_map()

    logger.info(f"module {__name__} done")
    return ip_mapfile, orig_ip, resp_ip

if __name__ == "__main__":
    pass
