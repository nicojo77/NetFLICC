"""
version:        1.1
Create and move files to get the final folder hierarchy.
"""
import os
import logging
import shutil
from rich.panel import Panel
from rich.traceback import install
from rich.console import Console

install(show_locals=False)
console = Console()
logger = logging.getLogger(__name__)
current_dir = os.getcwd()


def create_folders() -> None:
    '''Create folders'''
    folders = {'devices', 'diverse', 'report', 'ip_lists', 'iri'}
    console.log("creating folders tree...", style='italic yellow')
    for folder in folders:
        try:
            os.mkdir(folder)
        except FileExistsError:
            pass
        except Exception as exc:
            console.log(Panel.fit(f"Error: {exc}", style='orange_red1'))
            logger.exception(exc)

    try:
        os.mkdir('raw_data/zeek')
        os.mkdir('raw_data/nfstream')
    except Exception as exc:
        console.log(Panel.fit(f"Error: {exc}", border_style='orange_red1'))
        logger.exception(exc)

    # Move zeek.log to ./raw_data/zeek and nfstreamed files to ./raw_data/nfstream.
    try:
        files = os.scandir('raw_data/')
        for file in files:
            if os.path.splitext(file)[-1] == '.log':
                shutil.move(file, 'raw_data/zeek/')
            elif file.name.startswith('nfstreamed_'):
                shutil.move(file, 'raw_data/nfstream')
    except Exception as exc:
        console.log(Panel.fit(f"Error: {exc}", border_style='orange_red1'))
        logger.exception(exc)


def move_files_to_folders() -> None:
    '''Move each file to appropriate folder.'''
    files = os.scandir(current_dir)
    for file in files:
        # Process only files, no directory.
        if os.path.isfile(file):
            try:
                if file.name.startswith('iri'):
                    shutil.move(file, 'iri')

                elif file.name.startswith('device_idx'):
                    shutil.move(file, 'devices')

                elif file.name.startswith('web_history'):
                    shutil.move(file, 'diverse')

                elif file.name.startswith('plot_'):
                    shutil.move(file, 'report')

                elif file.name.startswith('nfstreamed_'):
                    shutil.move(file, 'raw_data/nfstream')

                elif os.path.splitext(file)[-1] == '.txt':
                    shutil.move(file, 'ip_lists')

                elif os.path.splitext(file)[-1] == '.html':
                    shutil.move(file, 'report')

                elif os.path.splitext(file)[-1] == '.log':
                    shutil.move(file, 'script_logs')

                elif os.path.splitext(file)[-1] == '.csv':
                    shutil.move(file, 'diverse')

                elif os.path.splitext(file)[-1] == '.parquet':
                    shutil.move(file, 'diverse')

            except Exception as exc:
                console.log(Panel.fit(f"Error: {exc}", border_style='orange_red1'))


def main() -> None:
    '''Script launcher function.'''
    with console.status("[bold italic green]Sorting folders and files...[/]") as _:
        console.log("moving files...", style='italic yellow')
        create_folders()
        move_files_to_folders()

        logger.info(f"module {__name__} done")

if __name__ == "__main__":
    pass
