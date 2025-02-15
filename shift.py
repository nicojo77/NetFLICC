"""
version:        1.1
Plot a heatmap based on http.log
"""
import glob as gb
import linecache
import logging
import os
import sys
import pandas as pd
import seaborn as sns
from datetime import datetime
import mplcyberpunk
from matplotlib import pyplot as plt
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.traceback import install

install(show_locals=False)
console = Console()
logger = logging.getLogger(__name__)


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


def heatmap_and_scatter_dataframe() -> tuple[pd.DataFrame, str, str]:
    '''
    Create a dataframe format with "dates", "hours" and "counts"
    Returns:
    finalDf ('dates', type=object; 'hours', type=object; 'count', type=float64)
    mindate (type=object)
    maxdate (type=object)
    '''
    # Merge http.log and ssl.log on field ts.
    http_df = logfile_to_dataframe('http.log')
    ssl_df = logfile_to_dataframe('ssl.log')
    http_df = http_df[['ts']]
    ssl_df = ssl_df[['ts']]
    frame = [http_df, ssl_df]
    http_df = pd.concat(frame, axis=0)

    # HACK: un-comment next line and adapt log file.
    # http_df = logfile_to_dataframe('ssl.log')

    # ts type: datetime64, hence needs converting to strftime.
    # 0   ts                 2558 non-null   datetime64[ns, Europe/Zurich]
    mindate = http_df['ts'].dt.strftime('%Y.%m.%d').min()
    maxdate = http_df['ts'].dt.strftime('%Y.%m.%d').max()

    time_range = pd.date_range(f"{mindate} 00:00:00", f"{maxdate} 23:00:00", freq='h' )

    # Create the index, Index: [2024-03-13 00:00:00,...
    index_data = {'tr': time_range}
    idx = pd.DataFrame(index_data)
    idx.set_index(['tr'], inplace=True)

    # Format 'ts' to have single 'H', necessary to sort per hours.
    # 0    2024.03.13 15
    http_df['ts'] = http_df['ts'].dt.strftime('%Y.%m.%d %H')

    # Count the value per hours. sort=True will sort count.
    # 2024.03.13 15     1
    val_counts = http_df['ts'].value_counts(sort=False)

    # Reset the index, will give columns 'ts' and 'count'.
    val_counts = val_counts.reset_index()

    # At that stage, 'ts' is of type object, so needs converting to datetime.
    # 0 2024-03-13 15:00:00      1
    val_counts['ts'] = pd.to_datetime(val_counts['ts'], format='%Y.%m.%d %H')

    # Set index with 'ts' vaues. This is necessare for later concat.
    val_counts.set_index(['ts'], inplace=True)

    # Concatenate the created index with all hour values,
    # with the real values. This will fill in the gaps with NaN.
    frame = [idx, val_counts]
    final_df = pd.concat(frame, axis=1)

    # The values of 'data' are set as index. They need resetting and
    # then renaming to "dates".
    final_df.reset_index(inplace=True)
    final_df = final_df.rename(columns={'index':'dates'})

    # At that stage, the dataframe consist of 3 columns:
    # dates, count and hours
    # dates and hours need re-formating to match x and y axis values
    # that will be used with matplotlib
    final_df['hours'] = final_df['dates'].dt.strftime('%H')
    final_df['dates'] = final_df['dates'].dt.strftime('%Y.%m.%d')

    return final_df, mindate, maxdate


def heatmap_wd_grid() -> None:
    '''Plot matplotlib heatmap grid of week days.'''

    # Load the dataframe.
    df, _, _ = heatmap_and_scatter_dataframe()
    # df, minDate, maxDate = heatmap_and_scatter_dataframe()

    # Create the figure and set seaborn style.
    cm = 1/2.54
    size = (30*cm, 15*cm)
    plt.style.use('cyberpunk')

    fig, _ = plt.subplots(figsize=size)

    # Format data for heatmap.
    heatmap_data = df.pivot_table(index='hours',
                                    columns='dates',
                                    values='count',
                                    dropna=False)

    # Replace NaN with negative value -1
    heatmap_data = heatmap_data.fillna(-1)

    date_objects = [datetime.strptime(date, '%Y.%m.%d') for date in heatmap_data.columns]

    # Necessary to prevent overlapping axes, axes.remove() also possible.
    plt.clf()

    ax_heatmap_full = plt.subplot2grid(shape=(2,7), loc=(0,0), colspan=7)

    # Optional, only needed for scaling down.
    # Get the max value.
    max_val = (df['count'].max() * 60) / 100

    # If there a less than 21 days, show them all.
    if len(date_objects) < 21:
        sns.heatmap(heatmap_data,
                    cmap='plasma',
                    cbar_kws={'label': 'Events/Hour (Re-scaling factor: 0.6)'},
                    xticklabels=[date.strftime('%d.%m.%y %a') for date in date_objects],
                    ax=ax_heatmap_full,
                    vmax=max_val)

        # Show only Mondays.
    else:
        # Find position of Mondays in the list.
        monday_indices = [i for i, date in enumerate(date_objects) if date.weekday() == 0]
        # Create a list of labels where Mon are labeled and other position left empty.
        xlabels = ['' for _ in date_objects]
        for idx in monday_indices:
            xlabels[idx] = date_objects[idx].strftime('%d.%m.%y %a')

        # Plot the heatmap with the modified lables.
        sns.heatmap(heatmap_data,
                    cmap='plasma',
                    cbar_kws={'label': 'Events/Hour (Re-scaling factor: 0.6)'},
                    xticklabels=xlabels,
                    ax=ax_heatmap_full,
                    vmax=max_val)

    # Set heatmap properties.
    ax_heatmap_full.set_title("Internet Browsing Activity\n(Sampling: http.log - ssl.log)")
    ax_heatmap_full.invert_yaxis()
    ax_heatmap_full.set_xlabel(None)
    ax_heatmap_full.set_ylabel('Time of Day')
    plt.xticks(rotation=60, rotation_mode='anchor', ha='right')
    plt.yticks(rotation=0)

    # Generate heatmap plots for each day of the week.
    # Grid row 2
    days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    for i, day in enumerate(days):
        empty_df = False
        df, _, _ = heatmap_and_scatter_dataframe()

        # Compulsory data, max value will be used with all plots.
        # Allow to scale down the color map.
        max_val = (df['count'].max() * 60) / 100

        df['dates'] = [datetime.strptime(date, '%Y.%m.%d') for date in df['dates']]
        df['days'] = [date.strftime('%a') for date in df['dates']]

        # Filter per day.
        filt = (df['days'] == day)
        df = df[filt]
        # Format dates with year first allow to sort data for the grid.
        df['dates'] = df['dates'].dt.strftime('%y.%m.%d')

        # Format data for heatmap.
        columns = ['days', 'dates']
        heatmap_data = df.pivot_table(index='hours', columns=columns, values='count', dropna=False)

        # Replace NaN with negative value -1
        heatmap_data = heatmap_data.fillna(-1)

        # Handle missing days, e.g. no monday (Mon(0)).
        # Generate a fake df, index 00 to 23, with -1 values.
        if heatmap_data.empty:
            empty_df = True
            index_labels = [f"{i:02}" for i in range(24)]
            data = {'hours': [-1] * 24}
            heatmap_data = pd.DataFrame(data, index=index_labels)

        ax = plt.subplot2grid(shape=(2,7), loc=(1,i))
        if i == 0:
            sns.heatmap(heatmap_data, cmap='plasma', vmax=max_val,
                        cbar=False, xticklabels=False, ax=ax)
        else:
            sns.heatmap(heatmap_data, cmap='plasma', vmax=max_val,
                        cbar=False, xticklabels=False, yticklabels=False, ax=ax)

        # Get counts/day for subgrid titles.
        if not empty_df:
            days_count = (len(heatmap_data.columns))
        else:
            days_count = 0

        ax.invert_yaxis()
        ax.set_title(f"{day} ({days_count})")
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        plt.yticks(rotation=0)

        plt.tight_layout()

    file = f'plot_shift.png'
    # file = f'heatmap_daysGrid.png'
    # Remove old plot to ensure actual data.
    try:
        os.remove(file)
    except FileNotFoundError:
        pass
    except Exception as exc:
        console.log(f'Error: {exc}', style='red')
        logger.exception(f'Error: {exc}')

    fig.savefig(file)


def main() -> None:
    '''Script launcher.'''
    with console.status("[bold italic green]Processing shift.py ...[/]") as _:
        console.log("processing dataframe...", style="italic yellow")
        console.log("processing shift heatmap plot...", style="italic yellow")
        heatmap_wd_grid()

        logger.info(f"module {__name__} done")


if __name__ == "__main__":
    pass
