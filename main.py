import os, json, datetime, io

EXECUTION_LIST = []

def convert_to_epoch(datetime_string):
    # Defining the timestamp pattern to parse into Epoch. 
    ts_pattern = "%Y-%m-%dT%H:%M:%S.%f"

    # Reference: https://stackoverflow.com/questions/55586325/python-parse-timestamp-string-with-7-digits-for-microseconds-to-datetime 
    # Datetime cannot parse milliseconds more than 6 characters. 
    # Output a datetime object tuple.
    datetime_tuple = datetime.datetime.strptime(datetime_string[:26], ts_pattern).utctimetuple()

    # Reference: https://stackoverflow.com/questions/11743019/convert-python-datetime-to-epoch-with-strftime    
    epoch_time = datetime.datetime(datetime_tuple.tm_year,
                                    datetime_tuple.tm_mon,
                                    datetime_tuple.tm_mday,
                                    datetime_tuple.tm_hour,
                                    datetime_tuple.tm_min,
                                    datetime_tuple.tm_sec).timestamp()
    
    return(int(epoch_time))

def timeline_amcache():
    pass

def timeline_userassist():
    pass

def timeline_runmru():
    pass

def timeline_eventlog():
    command = '.\\bin\\EvtxECmd\\EvtxECmd.exe -f "sample\C\Windows\System32\winevt\logs\Security.evtx" --inc 4688 --json output --jsonf evtx.json'
    os.system(command)
    first_line_flag = 1
    with open("output\\evtx.json") as jsonfile:
        for line in jsonfile:
            evtx_list = ["Event Log"]

            # 3 bad character for first json data
            if first_line_flag: 
                line = line[3:]
                first_line_flag = 0

            parsed_json = json.loads(line)
            execution_time_epoch = convert_to_epoch(parsed_json["TimeCreated"])
            payload_json = json.loads(parsed_json["Payload"])
            payload_items = payload_json["EventData"]["Data"]
            process_name = payload_items[5]['#text']
            parent_process_name = ""

            # Would need a try-except statement for parent process name as some process on-boot does not have a parent; system process. 
            try:
                parent_process_name = payload_items[13]['#text']
            except:
                parent_process_name = "NULL"
                
            # TO-DO: Need better formatting. 
            message = parent_process_name + " => SPAWNS => " + process_name
            
            evtx_list.append(execution_time_epoch)
            evtx_list.append(message)

            EXECUTION_LIST.append(evtx_list)
                
            
def timeline_lnkfiles():
    pass

def timeline_prefetch():
    
    command = '.\\bin\\PECmd.exe -q -d "sample\C\Windows\prefetch" --json output --jsonf temp.json'
    os.system(command)
    with open("output\\temp.json", encoding="utf8") as jsonfile:
        for line in jsonfile:
            
            first_run_list = ["Prefetch (First Run)"]
            last_run_list = ["Prefetch (Last Run)"]
            
            executable_path = ""
            parsed_json = json.loads(line)
            executable_name = parsed_json["ExecutableName"]
            files_loaded = parsed_json["FilesLoaded"]
            executable_path = ""
            for file in files_loaded.split(","):
                if executable_name in file:
                    executable_path = file

            first_run_epoch = convert_to_epoch(parsed_json["SourceCreated"])  
            last_run_epoch = convert_to_epoch(parsed_json["SourceModified"])    

            first_run_list.append(int(first_run_epoch)) # first run
            first_run_list.append(executable_path)
            last_run_list.append(int(last_run_epoch)) # last run
            last_run_list.append(executable_path)

            EXECUTION_LIST.append(first_run_list)
            EXECUTION_LIST.append(last_run_list)

def main():
    timeline_prefetch()
    timeline_amcache()
    timeline_runmru()
    timeline_userassist()
    # timeline_eventlog()
    timeline_lnkfiles()
    # Reference: https://www.geeksforgeeks.org/python-sort-list-according-second-element-sublist/
    # Sort the nested list EXECUTION_LIST by second element. 
    sorted_execution_list = sorted(EXECUTION_LIST, key = lambda x: x[1])

    for item in sorted_execution_list:
        # Reference: https://www.javatpoint.com/python-epoch-to-datetime 
        converted_datetime = datetime.datetime.fromtimestamp(item[1])
        execution_source = item[0]
        execution_sourcepath = item[2]
        print(converted_datetime, execution_source, execution_sourcepath)
        # TO-DO: Save the list into CSV. 

if __name__ == "__main__":
    main()