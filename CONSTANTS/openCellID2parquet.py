"""
Convert OpenCellID csv file to parquet
creds:
opencellid.jubilant827@passmail.net
https://opencellid.org/downloads.php?token=pk.254e269341ea44cf3a584ccf92d94f8c
"""

# import questionary
import os
import subprocess
import pandas as pd
# from questionary import Style
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from mydebug import timer

console = Console()

# # Questionary styling.
# custom_style = Style([
#     # ('qmark', 'fg:#673ab7 bold'),       # token in front of the question
#     # ('question', 'bold'),               # question text
#     # ('answer', 'fg:#f44336 bold'),      # submitted answer text behind the question
#     ('pointer', 'fg:#f8b301 bold'),     # pointer used in select and checkbox prompts
#     ('highlighted', 'fg:#f8b301 bold'), # pointed-at choice in select and checkbox prompts
#     # ('selected', 'fg:#cc5454'),         # style for a selected item of a checkbox
#     # ('separator', 'fg:#cc5454'),        # separator in lists
#     # ('instruction', ''),                # user instructions for select, rawselect, checkbox
#     ('text', 'fg:#f8b301'),                       # plain text
#     # ('disabled', 'fg:#858585 italic')   # disabled choices for select and checkbox prompts
# ])

# setup(){ rm cell_towers.csv; cp ~/Downloads/cell_towers.csv.gz .; }
def gunzip_celltowers() -> None:
    '''Use gunzip on celltowers.csv.gz'''
    file = '/tmp/testy/cell_towers.csv.gz'
    # file = '/home/anon/Documents/git/pythonScripts/netflicc/CONSTANTS/cell_towers.csv.gz'
    subprocess.run(['gunzip', '-f', file], check=True)


@timer
def convert_csv_to_parquet():
    '''Identify the csv file and convert to parquet'''

    # # Ask user for path and csv file.
    # csv_path = questionary.path("Indicate path to csv file:").unsafe_ask()
    # files_at_path = os.listdir(csv_path)
    # files = [file for file in files_at_path]
    # csv_file = questionary.select("Choose a file", choices=files, style=custom_style).unsafe_ask()

    csv_file = './cell_towers.csv'

    # Create output parquet name.
    file_name = os.path.splitext(csv_file)[0]
    parquet_file = (file_name + '.parquet')

    # Load csv and create parquet file.
    with console.status(f"[bold italic green]Creating parquet file ...[/]"):
        df = pd.read_csv(csv_file, dtype={'radio': 'object',
                                          'mcc': 'Int32',
                                          'net': 'Int8',
                                          'area': 'Int32',
                                          'cell': 'Int64',
                                          'unit': 'Int8',
                                          'lon': 'Float64',
                                          'lat': 'Float64',
                                          'range': 'Int32',
                                          'samples': 'Int32',
                                          'changeable': 'Int8',
                                          'created': 'Int64',
                                          'updated': 'Int64',
                                          'averageSignal': 'Int32'})
        df.to_parquet(parquet_file)

    rprint(Panel.fit(f'Parquet file "{parquet_file}" successfully created.', border_style='green'))

# TODO: 
# add gunzip to console
# remove cell_towers.csv

def main():
    gunzip_celltowers()
    convert_csv_to_parquet()


if __name__ == "__main__":
    main()
