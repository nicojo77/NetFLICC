---
id: readme
aliases: []
tags: []
---
Currently the download of tacdb cannot be done via FARCO. 

The reason is fedpol does no longer has an api with GSMA, hence the database is outdated.

KA division still has a mean to provide the db, but it could be in excel format.


The next python snippet creates tacdb.parquet from the excel file. 
It has not been embedded in netflicc.py as the is not known whether the situation is temporary or not.
As soon as the situation is clarified, an update of netflicc.py must take place.

TEMPORARY SOLUTION:
```py
import pandas as pd

file = '/tmp/testy/20251106093109-TACDB-GSMA_TAC-Database.xlsx'

df = pd.read_excel(file, index_col='tac')

df.info()

df.to_parquet('tacdb.parquet')
```

TEMPORARY MODIFICATIONS:
thy_constants.py:
```py
# Location of tacdb.txt: gsma.py.
# GSMA = f"{installation_path}TACDB/tacdb.txt"
GSMA = f"{installation_path}TACDB/tacdb.parquet" # temporary
```

gsma.py:
```py
def tac_to_gsma() -> list:
    '''Match TAC against GSMA database and return a list of dataframes.'''
    GSMA = thy_constants.GSMA
    try:
        os.path.isfile(GSMA)
        # df = pd.read_csv(GSMA, sep='|', index_col='tac')
        df = pd.read_parquet(GSMA) # temporary
```




