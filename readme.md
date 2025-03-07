---
id: readme
aliases: []
tags:
  - netflicc
---
# <a id="top"></a>NetFLICC

<!-- toc -->

- [Resources](#resources)
- [Introduction](#introduction)
- [Installation](#installation)
  * [Virtual Environment](#virtual-environment)
  * [Requirements](#requirements)
  * [Constants](#constants)
- [netflicc.py Usage](#netfliccpy-usage)
  * [Exports](#exports)
  * [netflicc](#netflicc)

<!-- tocstop -->

## Resources
- [zeek doc](https://docs.zeek.org/en/master/)
- [zeek-spicy-wireguard](https://github.com/corelight/zeek-spicy-wireguard)
## Introduction
NetFLICC facilitates the analysis of data obtained from FLICC pcaps.

Upon fulfillment, the next processes will take place:  
    ▻ copying exports into case location  
    ▻ merging pcaps with mergecap  
    ▻ processing pcaps with zeek and nfstream  
    ▻ parsing data  
    ▻ creating plots and maps  
    ▻ creating report  

[_ToTop_](#top) 
## Installation
### Virtual Environment
- Create a virtual environment dedicated to NetFLICC (see requirements below).
- Create a netflicc folder in appropriate location, up to you.

### Requirements
NetFLICC has been coded with python=3.10.4, however newer versions may work.

environment.yaml: contains a full package list which was installed on the developing system (netflicc310).
requirements.txt: contains the package list used in NetFLICC.

You can either use anaconda, micromamba or Linux in-built virtual environment management system (venv).

### Constants
constants.py contains constant variables necessary for NetFLICC to work.  
Those must be changed according to your installation paths.

The next commands could help you to figure out your system's constants:

To get the absolute path of the installation directory, run:
```sh
pwd
```
To get the absolute path of Zeek installation:
```sh
which zeek
```
_Note: for Zeek packages you should probably check sub-directories._

[_ToTop_](#top) 
## netflicc.py Usage
### Exports
> [!WARNING]
> In FLICC, if you rename the search, __do not use special characters and under no circumstances [/].__

Copy FLICC export(s) (zip file) to an external drive.

Move to your case folder and launch netflicc.py.

### netflicc
It is strongly advised to create an executable link of netflicc.py. This would allow launching the script from different locations of your system without the need to copy the whole path.

```py
py netflicc.py
```

_Note: netflicc.py would be sufficient if executable._

![NetFLICC](./documents/pictures/rec.gif)
_NetFLICC in action 🤩 (launched from /tmp/testy/)_

As you can see, the user will have to answer some questions before continuing. This is not rocket science and the trickiest part would be to enter the path.  
- simply start with [/] then [tab].
- enter first letter(s), e.g. m for media and press [tab]
- pressing several times [tab] allow to change directories on the same level
- repeat till export location is reached
- press [enter] twice

[_ToTop_](#top)

