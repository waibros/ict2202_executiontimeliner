import os, json, datetime, io, re, time
from glob import glob

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
    # A list to store all users' NTUSER.DAT (in case of shared computer)
    ntuser_list = []
    for root, dirs, files in os.walk("sample/C/Users"):
        if 'NTUSER.DAT' in files and 'Default' not in root:
            print(root, "NTUSER.DAT")
            ntuser_list.append(os.path.join(root, "NTUSER.DAT"))

    for file in ntuser_list:
        command = '.\\bin\\regripper\\rip.exe -r ' + file + ' -p userassist_tln | findstr /C:"exe" /C:"lnk"'
        command_output = os.popen(command).read().split('\n')[:-1]
        for lines in command_output:
            for line in lines.split('\n'):
                userassist_list = ["Userassist"]
                epoch_time = line.split('|')[0]
                # Further slice the 4th field of command output with '-' character to extract only the Executable path
                executable_path = ''.join(line.split('|')[4].split('-')[1:])
                userassist_list.append(int(epoch_time))
                userassist_list.append(executable_path)

                EXECUTION_LIST.append(userassist_list)

def timeline_eventlog():
    # command = '.\\bin\\EvtxECmd\\EvtxECmd.exe -f "sample\C\Windows\System32\winevt\logs\Security.evtx" --inc 4688 --json output --jsonf evtx.json'
    # os.system(command)
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

def timeline_srum():
    filersrc=""
    # command = '.\\bin\\SrumECmd.exe -d "sample\C" --csv output'
    # os.system(command)
    outputdirectory = os.fsencode(".\\output")
    for file in os.listdir(outputdirectory):
        filename=os.fsdecode(file)
        if filename.endswith("AppResourceUseInfo_Output.csv"):
            filersrc=filename
            continue
        elif filename.endswith(".csv") and not filename.endswith("AppResourceUseInfo_Output.csv"):
            os.remove(".\\output\\"+filename)
        else:
            continue
            
    with open(".\\output\\"+filersrc, newline='', encoding='utf8') as csvfile:
        srumreader = csv.DictReader(csvfile, delimiter=',')
        #print(srumreader.fieldnames)
        pattern = '%Y-%m-%d %H:%M:%S'
        srum_list =[]
        for row in srumreader:
            srum_entry_time_epoch = int(time.mktime(time.strptime(row["Timestamp"], pattern)))
            srum_executable = row["ExeInfo"]
            srum_list.append(srum_entry_time_epoch)
            srum_list.append(srum_executable)
            EXECUTION_LIST.append(srum_list)
    
    os.remove(".\\output\\"+filersrc)
            
        
    
    
    pass
                
def timeline_jumplist():
    filelist=[]
    # command = '.\\bin\\JLECmd.exe -q -d "sample\C" --json output'
    # os.system(command)
    outputdirectory = os.fsencode(".\\output")
    for file in os.listdir(outputdirectory):
        filename = os.fsdecode(file)
        if filename.endswith("automaticDestinations-ms.json"): 
            filelist.append(filename)
            continue
        elif filename.endswith("customDestinations-ms.json"):
            os.remove(".\\output\\"+filename)
        else:
            continue
    
    for file in filelist:
        with open("output\\"+file, encoding="utf8") as jsonfile:
            for line in jsonfile:
                jmp_list=["Jmp Log"]
                
                parsed_json = json.loads(line)
                #print(parsed_json.keys())
                directory_json = parsed_json["Directory"]
                execution_time_epoch = directory_json[0]["ModifiedTime"]
                jmp_list.append(re.sub("[^0-9]", "", execution_time_epoch))
                EXECUTION_LIST.append(jmp_list)
        os.remove(".\\output\\"+file)
                
    pass
            
def timeline_lnkfiles():
    # command = '.\\bin\\LECmd.exe -q -d "sample\C" --json output'
    # os.system(command)
    # f = glob(os.path.join(".\\output","*_LECMD_Output.json"))[0]
    # if os.path.isfile('.\\output\\lnktmp.json'):
    #     os.remove(".\\output\\lnktmp.json")
    # os.rename(f, os.path.join(".\\output","lnktmp.json"))
    with open("output\\lnktmp.json") as jsonfile:
        for line in jsonfile:
            lnk_list = ["Lnk Log"]
            
            parsed_json = json.loads(line)
            execution_time_epoch = convert_to_epoch(parsed_json["SourceAccessed"])
            try:
                executable_path = parsed_json["LocalPath"]
            except:
                executable_path = "NULL"
            if executable_path != "NULL":
                lnk_list.append(execution_time_epoch)
                lnk_list.append(executable_path)
                EXECUTION_LIST.append(lnk_list)


def timeline_prefetch():
    # command = '.\\bin\\PECmd.exe -q -d "sample\C\Windows\prefetch" --json output --jsonf temp.json'
    # os.system(command)
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

def timeline_shimcache():
    command = '.\\bin\\regripper\\rip.exe -r "sample/C/Windows/System32/config/SYSTEM" -p appcompatcache_tln'
    # Read from 7th line onwards as the first 7 lines are plugin information
    # Last line is ommited as it is a blank line
    command_output = os.popen(command).read().split('\n')[7:-1]

    # Command output is delimited with '|' character
    for line in command_output:
        shimcache_list = ["Shimcache"]
        epoch_time = line.split('|')[0]
        # Further slice the 4th field of command output with '-' character to extract only the Executable path
        # TO-DO: Further improve by checking if executable path starts with drive letter. 
        executable_path = line.split('|')[4].split('-')[1]
        shimcache_list.append(int(epoch_time))
        shimcache_list.append(executable_path)
        EXECUTION_LIST.append(shimcache_list)

def timeline_bam():
    command = '.\\bin\\regripper\\rip.exe -r "sample/C/Windows/System32/config/SYSTEM" -p bam_tln | findstr "exe"'
    command_output = os.popen(command).read().split('\n')[:-1]

    for line in command_output:
        bam_list = ["BAM"]
        epoch_time = line.split('|')[0]
        executable_path = line.split('|')[4]

        bam_list.append(int(epoch_time))
        bam_list.append(executable_path)

        EXECUTION_LIST.append(bam_list)

def main():
    
    # timeline_prefetch()
    # timeline_amcache()
    timeline_userassist()
    # timeline_shimcache()
    # timeline_eventlog()
    # timeline_lnkfiles()
    # timeline_bam()
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