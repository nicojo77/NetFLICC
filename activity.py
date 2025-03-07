"""
version:        1.1
Check conn.log and http.log for daily activity.
"""
import glob as gb
import linecache
import logging
import os
import sys
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.traceback import install
from scipy.interpolate import interp1d

install(show_locals=False)
console = Console()
logger = logging.getLogger(__name__)


def logfile_to_dataframe(log) -> pd.DataFrame:
    '''Format zeek log files to Pandas dataframe'''
    # Get line 7 which has headers.
    zeek_log = gb.glob(f'*/{log}')[0]
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


def index_for_activity_dataframe() -> pd.DataFrame:
    '''Create index 0-23 for dataframe.'''
    index = [f"{i:02d}" for i in range(24)]
    data = {'idx': index}
    idx_df = pd.DataFrame(data)
    idx_df = idx_df.set_index(['idx'])
    return idx_df


def get_http_activity() -> pd.DataFrame:
    '''Search for activity in http.log.'''
    # Load dataframe and modifiy time format.
    http_df = logfile_to_dataframe('http.log')
    http_df['ts'] = http_df['ts'].dt.strftime('%H')

    http_events_hour = http_df['ts'].value_counts()
    http_events_hour = http_events_hour.reset_index()
    http_events_hour = http_events_hour.sort_values('ts', ascending=True)

    percentage = ((http_events_hour['count'] * 100) / http_events_hour['count'].sum()).round(2)
    http_events_hour['%_http'] = percentage
    http_events_hour = http_events_hour.set_index(['ts'])
    return http_events_hour


def get_ssl_activity() -> pd.DataFrame:
    '''Search for activity in ssl.log.'''
    # Load dataframe and modifiy time format.
    ssl_df = logfile_to_dataframe('ssl.log')
    ssl_df['ts'] = ssl_df['ts'].dt.strftime('%H')

    ssl_events_hour = ssl_df['ts'].value_counts()
    ssl_events_hour = ssl_events_hour.reset_index()
    ssl_events_hour = ssl_events_hour.sort_values('ts', ascending=True)

    percentage = ((ssl_events_hour['count'] * 100) / ssl_events_hour['count'].sum()).round(2)
    ssl_events_hour['%_ssl'] = percentage
    ssl_events_hour = ssl_events_hour.set_index(['ts'])
    return ssl_events_hour


def connexion_activity_not_sorted() -> pd.DataFrame:
    '''Search for activity in conn.log.'''
    # Load dataframe and modifiy time format.
    conn_df = logfile_to_dataframe('conn.log')
    conn_df['ts'] = conn_df['ts'].dt.strftime('%H')

    conn_ns_events_hour = conn_df['ts'].value_counts()
    conn_ns_events_hour = conn_ns_events_hour.reset_index()
    conn_ns_events_hour = conn_ns_events_hour.sort_values('ts', ascending=True)

    percentage = (
        (conn_ns_events_hour['count'] * 100) / conn_ns_events_hour['count'].sum()
                ).round(2)
    conn_ns_events_hour['%_connNS'] = percentage
    conn_ns_events_hour = conn_ns_events_hour.set_index(['ts'])
    return conn_ns_events_hour


def connexion_activity_sorted() -> pd.DataFrame:
    '''Search for activity in conn.log, remove duplicate timestamps.'''
    pd.options.mode.copy_on_write = True

    # Load dataframe and modifiy time format.
    conn_df = logfile_to_dataframe('conn.log')
    conn_df['ts'] = conn_df['ts'].dt.strftime('%H%M%S')

    # Drop duplicated values in ['ts'] seconds range.
    conn_df_unique = conn_df.drop_duplicates(subset=['ts'])

    # Reset and set time format.
    conn_df_unique['ts'] = pd.to_datetime(conn_df_unique['ts'], format='%H%M%S')

    conn_df_unique['ts'] = conn_df_unique['ts'].dt.strftime('%H')
    conn_s_events_hour = conn_df_unique['ts'].value_counts().reset_index()
    conn_s_events_hour = conn_s_events_hour.sort_values('ts', ascending=True)

    percentage = ((conn_s_events_hour['count'] * 100) / conn_s_events_hour['count'].sum()).round(2)
    conn_s_events_hour['%_connS'] = percentage
    conn_s_events_hour = conn_s_events_hour.set_index(['ts'])
    return conn_s_events_hour


def process_data_to_plot(idx_df_: pd.DataFrame,
                         http_events_hour_: pd.DataFrame,
                         ssl_events_hour_: pd.DataFrame,
                         conn_ns_events_hour_: pd.DataFrame,
                         conn_s_events_hour_: pd.DataFrame) -> pd.DataFrame:
    '''Concatenate the dataframes into one.'''
    # Concatenate dataframes.
    # Ensure to keep the order similar to colour_data in matplot().
    idx_df = idx_df_
    http_events_hour = http_events_hour_
    ssl_events_hour = ssl_events_hour_
    # conn_ns_events_hour = conn_ns_events_hour_
    conn_s_events_hour = conn_s_events_hour_

    frames = [idx_df, http_events_hour, ssl_events_hour, conn_s_events_hour]
    # frames = [idx_df, http_events_hour, ssl_events_hour, conn_s_events_hour, conn_ns_events_hour]
    new_df = pd.concat(frames, axis=1)
    # Remove un-necessary data, replace NaN to 0, calculate mean values.
    cols = ['count']
    new_df = new_df.drop(cols, axis=1)
    new_df = new_df.fillna(0)
    new_df['mean'] = new_df.mean(axis=1).round(2)
    return new_df


def smooth_curve(x, y, num_points=1000) -> tuple[float, float]:
    '''Smooth the curves of matplotlib for better rendering.'''
    # Create interpolation function.
    f = interp1d(x, y, kind='cubic')
    # Create new x values for smooth curve.
    x_smooth = np.linspace(min(x), max(x), num_points)
    # Compute corresponding y values.
    y_smooth = f(x_smooth)
    # Ensure y_smooth remains above 0
    y_smooth = np.maximum(y_smooth, 0)

    return x_smooth, y_smooth


def matplot(idx_df_: pd.DataFrame,
            http_events_hour_: pd.DataFrame|None,
            ssl_events_hour_: pd.DataFrame|None,
            conn_ns_events_hour_: pd.DataFrame,
            conn_s_events_hour_: pd.DataFrame) -> None:
    '''Plot the dataframe.'''
    df = process_data_to_plot(idx_df_,
                              http_events_hour_,
                              ssl_events_hour_,
                              conn_ns_events_hour_,
                              conn_s_events_hour_)

    # Size not so important, at least for html.
    cm = 1/2.54
    size = (30*cm, 10*cm)

    # Reset index to ensure it is numeric and sorted.
    df.reset_index(inplace=True)

    # sns.set_style('darkgrid', rc={'axes.facecolor': '0.88'})
    plt.style.use('cyberpunk')
    plt.figure(figsize=size)

    # Define colour and line width for each column.
    colour_data = {'%_http': ['htpp.log', 'violet', 1],
             '%_ssl': ['ssl.log', 'yellow', 1],
             '%_connS': ['conn.log (sorted)', 'blue', 1],
             # '%_connNS': ['conn.log (not sorted)', 'green', 1],
             'mean': ['mean', 'red', 3]}

    # Plot each column regarding colour_data, except index.
    for column in df.columns:
        if column == 'index':
            pass
        else:
            x_smooth, y_smooth = smooth_curve(df.index, df[column])
            plt.plot(x_smooth, y_smooth,
                    label=f'{colour_data[column][0]}',
                    # color=f'{colour_data[column][1]}',
                    linewidth=f'{colour_data[column][2]}')

    # Set x and y labels.
    plt.title("Daily Activity Summary\n(Sampling: whole period)")
    plt.xlabel("Time of Day")
    plt.ylabel("Events / Day (%)")
    plt.legend()
    # Set x-axis ticks matching the index
    plt.xticks(df.index, df['index'])
    # mplcyberpunk.make_lines_glow()

    file = 'plot_daily_activity.png'
    # Remove old plot to ensure actual data.
    try:
        os.remove(file)
    except FileNotFoundError:
        pass
    except Exception as exc:
        console.log(f'Error: {exc}', style='red')
        logger.exception(f'Error: {exc}')

    plt.savefig(file)


def main(http_log=False, sll_log=False) -> None:
    '''Script launcher.'''
    with console.status("[bold italic green]Processing activity.py ...[/]") as _:
        console.log("[i]processing http activity...[/]", style="yellow")
        idx_df = index_for_activity_dataframe()

        # http.log must exist for the next function to be called.
        http_events_hour = None
        try:
            if http_log:
                http_events_hour = get_http_activity()
            else:
                http_events_hour = pd.DataFrame()
        except Exception as exc:
            console.print_exception(show_locals=True)
            logger.exception(f'Error: {exc}')

        # ssl.log must exist for the next function to be called.
        ssl_events_hour = None
        try:
            if sll_log:
                ssl_events_hour = get_ssl_activity()
            else:
                ssl_events_hour = pd.DataFrame()
        except Exception as exc:
            console.print_exception(show_locals=True)
            logger.exception(f'Error: {exc}')

        conn_ns_events_hour = connexion_activity_not_sorted()
        conn_ns_events_hour = connexion_activity_sorted()
        console.log("[i]processing http plot...[/]", style="yellow")
        matplot(idx_df,
                http_events_hour,
                ssl_events_hour,
                conn_ns_events_hour,
                conn_ns_events_hour)

        logger.info(f"module {__name__} done")


if __name__ == "__main__":
    pass
