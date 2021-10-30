# Execution Timeliner

:tw-1f31f: A tool created for SIT ICT2202 project - Designing and developing a solution for an existing problem in Digital Forensics. :tw-1f31f:

The tool tackles the issue on manual processing and analysis of individual artifacts (e.g. Prefetch, Amcache etc) by timelining every execution artifacts using readily available parsers. 

The tool is designed and recommended to be used after extraction of artifacts using KAPE. The construction of the folder structure done by KAPE after extraction will be referred as **root folder** for the rest of the documentation. 

## Pre-requisite
1. Python 3. The tool has been developed and tested with Python 3.10 (latest version as of writing)

## Usage:
```bash
python main.py <root folder>
```

## Output:
The output will be saved in the **output** folder named in the format of YYYY-MM-DDTHHMMSS_output.csv e.g. 2021-10-30T203959_output.csv 



> # :tw-2764: Credit :tw-2764:
Eric Zimmerman parsers - https://ericzimmerman.github.io/#!index.md 
RegRipper - https://github.com/keydet89/RegRipper3.0 

The tool couldn't be done without these wonderful parsers! 