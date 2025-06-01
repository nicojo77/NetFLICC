"""
version:        1.2
Allow logging and RichHandler capabilites.
"""
import datetime
import logging
import os

logfile = "/tmp/netflicc.log"
logging_format = '[%(asctime)s] %(levelname)-9s %(name)-11s (%(lineno)-4s) %(message)s'
time_format = '%H:%M:%S'

# Ensure no remnants of logfile still exist.
# Needs performing before configuring the logger.
try:
    os.remove(logfile)
except FileNotFoundError:
    pass

# Configure file logging with standard logging.FileHandler.
formatter = logging.Formatter(logging_format, time_format)
file_handler = logging.FileHandler(logfile)
file_handler.setFormatter(formatter)

# Get the root logger and configure it.
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(file_handler)

# Logging file  headers.
cur_date = datetime.datetime.now()
today = cur_date.strftime('%d.%m.%Y')
title = 'NetFLICC logfile'
ts = 'TIME'
db_level = 'DEBUG'
module = 'MODULE'
l_num = 'L_NUM'
msg = 'MESSAGE'

# Logging file creation.
with open(logfile, 'a') as lf:
    lf.writelines(f"{title}: {today}\n\n")
    lf.writelines(f"{ts.ljust(11)}{db_level.ljust(10)}{module.ljust(12)}{l_num.ljust(6)}{msg}\n")

if __name__ == "__main__":
    pass
