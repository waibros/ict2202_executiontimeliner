import os, json, datetime

EXECUTION_LIST = []

def timeline_amcache():
    pass

def timeline_userassist():
    pass

def timeline_runmru():
    pass

def timeline_eventlog():
    pass

def timeline_prefetch():
    ts_pattern = "%Y-%m-%dT%H:%M:%S.%f"
    # command = '.\\bin\\PECmd.exe -q -d "sample\C\Windows\prefetch" --json output --jsonf temp.json'
    # os.system(command)
    with open("output\\temp.json") as jsonfile:
        for line in jsonfile:
            first_run_list = ["Prefetch"]
            last_run_list = ["Prefetch"]
            
            executable_path = ""
            parsed_json = json.loads(line)
            executable_name = parsed_json["ExecutableName"]
            files_loaded = parsed_json["FilesLoaded"]
            executable_path = ""
            for file in files_loaded.split(","):
                if executable_name in file:
                    executable_path = file

            # Reference: https://stackoverflow.com/questions/55586325/python-parse-timestamp-string-with-7-digits-for-microseconds-to-datetime 
            # Datetime cannot parse milliseconds more than 6 characters. 
            # Output a datetime object tuple. 
            parsed_first_run_ts = datetime.datetime.strptime(parsed_json["SourceCreated"][:26], ts_pattern).utctimetuple()
            parsed_last_run_ts = datetime.datetime.strptime(parsed_json["SourceModified"][:26], ts_pattern).utctimetuple()

            # Reference: https://stackoverflow.com/questions/11743019/convert-python-datetime-to-epoch-with-strftime
            first_run_epoch = datetime.datetime(parsed_first_run_ts.tm_year,
                                    parsed_first_run_ts.tm_mon,
                                    parsed_first_run_ts.tm_mday,
                                    parsed_first_run_ts.tm_hour,
                                    parsed_first_run_ts.tm_min,
                                    parsed_first_run_ts.tm_sec).timestamp()

            last_run_epoch = datetime.datetime(parsed_last_run_ts.tm_year,
                                    parsed_last_run_ts.tm_mon,
                                    parsed_last_run_ts.tm_mday,
                                    parsed_last_run_ts.tm_hour,
                                    parsed_last_run_ts.tm_min,
                                    parsed_last_run_ts.tm_sec).timestamp()              

            first_run_list.append(int(first_run_epoch)) # first run
            first_run_list.append(executable_path)
            last_run_list.append(int(last_run_epoch)) # last run
            last_run_list.append(executable_path)

            # EXECUTION_LIST.append(first_run_list)
            EXECUTION_LIST.append(last_run_list)

def main():
    timeline_prefetch()
    timeline_amcache()
    timeline_runmru()
    timeline_userassist()
    timeline_eventlog
    # Reference: https://www.geeksforgeeks.org/python-sort-list-according-second-element-sublist/
    # Sort the nested list EXECUTION_LIST by second element. 
    sorted_execution_list = sorted(EXECUTION_LIST, key = lambda x: x[1])
    for item in sorted_execution_list:
        print(item)
    # TO-DO: Convert EPOCH time back to date and time format
    # TO-DO: Save the list into CSV. 

if __name__ == "__main__":
    main()