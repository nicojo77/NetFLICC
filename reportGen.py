"""
version:        1.1
Generate html report data.
"""
import base64
import datetime
import logging
import os
import pandas as pd
from bs4 import BeautifulSoup
from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.traceback import install
import thy_constants

install(show_locals=False)
console = Console()
logger = logging.getLogger(__name__)


def bar_style(row, df: pd.DataFrame, col) -> list[str]:
    '''Display bar chart of ['counts'] into ['user_agent']'''
    total_count = df['Counts'].sum()
    norm = row['Counts'] / total_count
    # Generate CSS style.
    bar_style = f'background: linear-gradient(to right, rgba(78,171,235,0),\
                rgba(78,171,235,0.75){norm * 100}%, transparent {norm * 100}%);'
    styles = ['background: #212946;' for _ in row]
    # Assign bar_style to the desired column: e.g. user_agent.
    styles[row.index.get_loc(col)] = bar_style
    return styles


def add_rowspan(html) -> str:
    '''Allow to merge several cells vertically (gsmadf).'''
    soup = BeautifulSoup(html, 'html.parser')
    rows = soup.find_all('tr')
    rowspan = len(rows) - 1
    first_td = rows[1].find_all('td')[0]
    first_td['rowspan'] = str(rowspan)

    for row in rows[2:]:
        row.find_all('td')[0].extract()
    return str(soup)

def add_colspan(html) -> str:
    '''Allow to merge several headers horizontally.'''
    soup = BeautifulSoup(html, 'html.parser')
    # Find the first header row (usually <thead><tr>)
    header_row = soup.find('thead').find('tr')
    # Merge the first two <th> headers by using colspan
    first_th = header_row.find_all('th')[0]
    second_th = header_row.find_all('th')[1]
    first_th.string = second_th.string
    # Set colspan for the first header to cover both columns
    first_th['colspan'] = '2'
    # Remove the second header
    second_th.extract()
    return str(soup)


def highlight_min_font(min_time) -> list[str]:
    '''Highlight min value font instead of cell.'''
    s_datetime = pd.to_datetime(min_time, format='%d.%m.%Y')
    min_value = s_datetime.min()
    return ['color: #4eabeb; font-weight: bold;' if v == min_value.strftime('%d.%m.%Y') else '' for v in min_time]


def highlight_max_font(max_time) -> list[str]:
    '''Hightlight max value font instead of cell.'''
    s_datetime = pd.to_datetime(max_time, format='%d.%m.%Y')
    max_value = s_datetime.max()
    return ['color: #4eabeb; font-weight: bold;' if v == max_value.strftime('%d.%m.%Y') else '' for v in max_time]


def generate_html(metadata_,
                  logo_,
                  nophonelogo_,
                  uadf_,
                  imeidf_,
                  gsmadf_,
                  activityplot_,
                  heatmapplot_,
                  applist_,
                  urldf_,
                  nocross_,
                  geoip_map_,
                  originatorip_,
                  responderip_,
                  geocell_map_,
                  celltower_df_,
                  applications_df_,
                  vpns_df_,
                  vpnlogo_) -> None:

    '''Generate html report based on ./templates/template.html.'''
    file_templates = thy_constants.TEMPLATES
    env = Environment(loader=FileSystemLoader(file_templates))
    template = env.get_template('template.html')

    try:
        if uadf_.empty:
            columns = ['User-agent', 'Counts', 'First seen', 'Last seen']
            uadf_ = pd.DataFrame(columns=columns)
    except Exception as exc:
        console.log(f"reportGen.py, error: {exc}", style='red')
        logger.exception(f"reportGen.py, error: {exc}")

    tstyle = {
        'selector': 'td',
        'props': 'background-color: #212946;'
    }

    # User-agent data.
    styled_uadf = uadf_.style\
                .set_table_styles([tstyle])\
                .apply(lambda row: bar_style(row, uadf_, 'User-agent'), axis=1)\
                .apply(lambda col: highlight_min_font(col), subset=['First seen'])\
                .apply(lambda col: highlight_max_font(col), subset=['Last seen'])\
                .hide(subset=None)

    # Imei data table.
    styled_imeidf = imeidf_.style.hide(subset=None)

    # Web-history data table.
    styled_urldf = urldf_.style\
                .set_table_styles([tstyle])\
                .apply(lambda row: bar_style(row, urldf_, 'Requests'), axis=1)\
                .hide(subset=None)

    # Orig_ip data table.
    styled_origdf = originatorip_.style\
                .set_table_styles([tstyle])\
                .apply(lambda row: bar_style(row, originatorip_, 'Source_ip'), axis=1)\
                .hide(subset=None)

    # resp_ip data table.
    styled_respdf = responderip_.style\
                .set_table_styles([tstyle])\
                .apply(lambda row: bar_style(row, responderip_, 'Source_ip'), axis=1)\
                .hide(subset=None)

    styled_cellt_df = celltower_df_.style\
                .set_table_styles([tstyle])\
                .hide(subset=None)

    styled_applications_df = applications_df_.style\
                .set_table_styles([tstyle])\
                .hide(subset=None)

    styled_vpns_df = vpns_df_.style\
                .set_table_styles([tstyle])\
                .hide(subset=None)

    # GENERATE TABLES BASED ON PRE-DEFINED STYLING.
    if uadf_.empty:
        ua_table = uadf_
    else:
        ua_table = styled_uadf.to_html()

    gsmadf_list = []
    if imeidf_.empty:
        imeidf_table = imeidf_
    else:
        imeidf_table = styled_imeidf.to_html()
        for i in gsmadf_:
            indexes_list = [0,1,2,3,4,5,18] # Filter to only report listed rows from the TACDB.
            i = i.iloc[indexes_list]
            styled_df = i.style.hide(subset=None)
            gsmadf_table = styled_df.to_html()
            gsmadf_table = add_rowspan(gsmadf_table)
            gsmadf_list.append(gsmadf_table)

    if urldf_.empty:
        urldf_table = urldf_
    else:
        urldf_table = styled_urldf.to_html()

    if originatorip_.empty:
        origdf_table = originatorip_
    else:
        origdf_table = styled_origdf.to_html()

    if responderip_.empty:
        respdf_table = responderip_
    else:
        respdf_table = styled_respdf.to_html()

    if celltower_df_.empty:
        celltower_df_table = celltower_df_
    else:
        celltower_df_table = styled_cellt_df.to_html()

    if applications_df_.empty:
        applications_table = applications_df_
    else:
        applications_table = styled_applications_df.to_html(index=False, header=False)
        applications_table = add_colspan(applications_table)

    if vpns_df_.empty:
        vpns_table = vpns_df_
    else:
        vpns_table = styled_vpns_df.to_html(index=False, header=False)
        vpns_table = add_colspan(vpns_table)


    html_content = template.render(meta=metadata_,
                                   # logo=logo_,
                                   nophoneLogo=nophonelogo_,
                                   ua_table=ua_table,
                                   imeidf=imeidf_table,
                                   gsmadf_list=gsmadf_list,
                                   urldf=urldf_table,
                                   activityPlot=activityplot_,
                                   heatmapPlot=heatmapplot_,
                                   applist=sorted(applist_),
                                   nocross=nocross_,
                                   geomap=geoip_map_,
                                   origdf=origdf_table,
                                   respdf=respdf_table,
                                   geocell=geocell_map_,
                                   celltdf=celltower_df_table,
                                   applicationsdf=applications_table,
                                   vpnsdf=vpns_table,
                                   vpnlogo=vpnlogo_)

    with open('report.html', 'w') as f:
        f.write(html_content)


def metadata(operation_name_: str, user_: str, pcap_data_: list, case_meta_) -> dict:
    '''Return data used in template.html'''
    today = datetime.datetime.now()
    meta = {
    # General and pcap data:
    'opName': operation_name_,
    'genBy': 'IFC3',
    'user': user_,
    'genDate': today.strftime('%d.%m.%Y'),
    'nPcap': pcap_data_[0],
    'szPcap': case_meta_.merged_pcap_size,
    'fPcap': pcap_data_[1].strftime('%d.%m.%Y %H:%M:%S'),
    'lPcap': pcap_data_[2].strftime('%d.%m.%Y %H:%M:%S'),
    'per': pcap_data_[3],
    # target_info.csv data:
    'parent_id': case_meta_.parent_id,
    'liid': case_meta_.liid,
    'interception_type': case_meta_.interception_type,
    'target_identifier': case_meta_.target_identifier,
    'target_type': case_meta_.target_type,
    'is_confidential': case_meta_.is_confidential,
    'order_date': case_meta_.order_date,
    'activation_date': case_meta_.activation_date,
    'interception_start_date': case_meta_.interception_start_date,
    'interception_end_date': case_meta_.interception_end_date,
    'provider_name': case_meta_.provider_name,
    'authority_name': case_meta_.authority_name,
    'prosecutor_name': case_meta_.prosecutor_name,
    'prosecutor_reference': case_meta_.prosecutor_reference
    }
    return meta


def png_to_base64(png_file_: str) -> str:
    '''Convert png to base64.'''
    with open(png_file_, 'rb') as image_file_:
        png_base64 = base64.b64encode(image_file_.read()).decode('utf-8')
    return png_base64


def convert_plot_to_base64(plot_: str) -> str|None:
    '''
    If argument file exists, convert to base64.

    Returns:
    base64_plot: str
    '''
    png_file = plot_
    base64_plot = None
    if os.path.isfile(png_file):
        try:
            base64_plot = png_to_base64(png_file)
        except Exception as exc:
            console.log(f'Error: {exc}', style='red')
            logger.exception(f'Error: {exc}')
    return base64_plot


def main(casemeta,
         operation_name,
         user,
         pcap_data,
         uadf,
         imeidf,
         gsmadf,
         url_df,
         apps_list,
         ip_mapfile,
         orig_ip,
         resp_ip,
         cell_mapfile,
         celltower_df,
         applications_df,
         vpns_df) -> None:

    '''reportGen.py launcher.'''

    with console.status("[bold italic green]Processing reportGen.py ...[/]") as _:
        console.log("generating report.html...", style="italic yellow")
        meta = metadata(operation_name, user, pcap_data, casemeta)

        activity_plot = convert_plot_to_base64('plot_daily_activity.png')
        heatmap_plot = convert_plot_to_base64('plot_shift.png')

        generate_html(meta,
                      logo,
                      nophone_logo,
                      uadf,
                      imeidf,
                      gsmadf,
                      activity_plot,
                      heatmap_plot,
                      apps_list,
                      url_df,
                      no_cross,
                      ip_mapfile,
                      orig_ip,
                      resp_ip,
                      cell_mapfile,
                      celltower_df,
                      applications_df,
                      vpns_df,
                      vpn_logo)

    logger.info(f"module {__name__} done")


logo = png_to_base64('/home/anon/Documents/git/pythonScripts/zeekpy/templates/betaTesting.png')
nophone_logo = png_to_base64('/home/anon/Documents/git/pythonScripts/zeekpy/templates/noPhone.png')
no_cross = png_to_base64('/home/anon/Documents/git/pythonScripts/zeekpy/templates/no_cross.png')
vpn_logo = png_to_base64('/home/anon/Documents/git/pythonScripts/zeekpy/templates/vpn.png')

if __name__ == "__main__":
    pass
