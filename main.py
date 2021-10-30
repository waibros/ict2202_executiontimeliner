import os, json, datetime, re, time, csv, sys
from multiprocessing import Process, Queue
from glob import glob
    
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

def timeline_amcache(TARGET_PATH,timeline_queue):
    print("Processing amcache...")
    path = TARGET_PATH + r"\Windows\AppCompat\Programs\Amcache.hve"
    command = '.\\bin\\AmcacheParser.exe -f "' + path + '" --csv ".\output" --csvf amcache.csv -i --dt "yyyy-MM-ddTHH:mm:ss.fff" >NUL'
    os.system(command)

    # List to control which amcache output to parse
    amcache_to_delete = ["DeviceContainers", "DevicePnps", "DriveBinaries", "DriverPackages", "ShortCuts", "UnassociatedFileEntries",
                        "AssociatedFileEntries", "ProgramEntries"]
    amcache_files = ["UnassociatedFileEntries", "AssociatedFileEntries", "ProgramEntries"]
    
    source_directory = os.path.dirname(os.path.realpath(__file__))

    for name in amcache_files:
        print("Parsing " + name)
        data_name = "Amcache (" + name + ")"
        target = source_directory + "\\output\\amcache_" + name + ".csv"
        data = []

        #Open the CSV file, reading each line as a dictionary
        with open(target, encoding='utf-8') as csvFile:
            csvFileReader = csv.DictReader(csvFile)

            #Set different headers for different csv file content type
            full_path = "FullPath"
            product_name = "ProductName"
            key_lastwrite = "FileKeyLastWriteTimestamp"
            if name == "ProgramEntries":
                full_path = "RootDirPath"
                product_name = "Name"
                key_lastwrite = "KeyLastWriteTimestamp"

            for row in csvFileReader:
                amcache_data_list = []
                file_timestamp = row[key_lastwrite].strip()
                #Check if the File write time is empty
                if not file_timestamp:
                    #Handle empty time and set it to 0 for epoch
                    file_timestamp = "1970-1-1T00:00:00"
                    amcache_data_message = "Source: " + row[full_path] + " | ProductName: " + row[product_name]
                    amcache_data_list.append(convert_to_epoch(file_timestamp))
                    amcache_data_list.append(amcache_data_message)
                    timeline_queue.put(amcache_data_list)
                    # data.append(amcache_data_list)
                else:
                    amcache_data_message = "Source: " + row[full_path] + " | ProductName: " + row[product_name]
                    amcache_data_list.append(data_name)
                    amcache_data_list.append(int(convert_to_epoch(file_timestamp)))
                    amcache_data_list.append(amcache_data_message)
                    timeline_queue.put(amcache_data_list)
                    # data.append(amcache_data_list)

        #After processing for a file, push the data into execution_list
        # print(data)
        # EXECUTION_LIST.append(data)

    #Delete csv files
    for filename in amcache_to_delete:
        target = source_directory + "\\output\\amcache_" + filename + ".csv"
        os.remove(target)
    print("Amcache processing completed!")
    timeline_queue.put("DONE")
    sys.exit()

def timeline_userassist(TARGET_PATH,timeline_queue):
    print("Processing userassist...")
    path = TARGET_PATH + r"\Users"
    # A list to store all users' NTUSER.DAT (in case of shared computer)
    ntuser_list = []
    for root, dirs, files in os.walk(path):
        # Reference: https://newbedev.com/python-os-walk-to-certain-level 
        if root[len(path):].count(os.sep) < 2:
            if 'NTUSER.DAT' in files and 'Default' not in root:
                ntuser_list.append(os.path.join(root, "NTUSER.DAT"))

    for file in ntuser_list:
        command = '.\\bin\\regripper\\rip.exe -r "' + file + '" -p userassist_tln | findstr /C:"exe" /C:"lnk"'
        command_output = os.popen(command).read().split('\n')[:-1]
        for lines in command_output:
            for line in lines.split('\n'):
                userassist_list = ["Userassist"]
                epoch_time = line.split('|')[0]
                # Further slice the 4th field of command output with '-' character to extract only the Executable path
                executable_path = ''.join(line.split('|')[4].split('-')[1:])
                userassist_list.append(int(epoch_time) - int(-time.timezone))
                userassist_list.append(executable_path)

                timeline_queue.put(userassist_list)
    print("Userassist processing completed!")
    timeline_queue.put("DONE")
    sys.exit()

def timeline_eventlog(TARGET_PATH,timeline_queue):
    print("Processing event logs...")
    path = TARGET_PATH + r"\Windows\System32\winevt\logs\Security.evtx"
    command = '.\\bin\\EvtxECmd\\EvtxECmd.exe -f "' + path + '" --inc 4688 --json output --jsonf evtx.json >NUL'
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
            message = parent_process_name + "[PARENT] -> " + process_name + "[CHILD]"
            
            evtx_list.append(execution_time_epoch)
            evtx_list.append(message)

            timeline_queue.put(evtx_list)
    
    os.remove(".\\output\\evtx.json")
    print("Event log processing completed!")
    timeline_queue.put("DONE")
    sys.exit()

def timeline_srum(TARGET_PATH,timeline_queue):
    print("Processing srum entries...")
    filersrc=""

    command = '.\\bin\\SrumECmd.exe -d "' + TARGET_PATH + '" --csv output >NUL'
    os.system(command)

    outputdirectory = os.fsencode(".\\output")
    for file in os.listdir(outputdirectory):
        filename=os.fsdecode(file)
        if filename.endswith("AppResourceUseInfo_Output.csv"):
            filersrc=filename
            continue
        elif "SrumECmd" in filename and not filename.endswith("AppResourceUseInfo_Output.csv"):
            os.remove(".\\output\\"+filename)
        else:
            continue
            
    with open(".\\output\\"+filersrc, newline='', encoding='utf8') as csvfile:
        
        pattern = '%Y-%m-%d %H:%M:%S'
        srum_dict = {}
        srum_list = []
        srum_reader = csv.DictReader(csvfile, delimiter=',')
        sorted_reader = sorted(srum_reader, key=lambda d: int(d['AppId']))

        for row in sorted_reader:
            if row['ExeInfo'].endswith("exe"):
                if row['AppId'] in srum_dict:
                    # If the AppId appears again, increment RunCount.
                    srum_dict[row['AppId']][2] += 1
                else:
                    # Initialize dictionary key-pair of AppId: Timestamp, ExecutablePath, RunCount
                    # First occurence of the executable is captured as first run is more valuable than last run.
                    epoch_time = int(time.mktime(time.strptime(row["Timestamp"], pattern)))
                    srum_dict[row['AppId']] = [epoch_time, row['ExeInfo'], 1]
    
        for key, value in srum_dict.items():
            srum_list = ["Srum"]
            message = value[1] + " (" + str(value[2]) + ")"
            srum_list.append(value[0])
            srum_list.append(message)
            timeline_queue.put(srum_list)

    os.remove(".\\output\\"+filersrc)
    print("Srum processing completed!")
    timeline_queue.put("DONE")
    sys.exit()
            
def timeline_jumplist(TARGET_PATH,timeline_queue):
    print("Processing jumplist...")
    macroext=[".docm",".dotm",".xlm",".xlsm",".xltm",".xla",".xlam",".pptm",".ppsm",".sldm", ".docx"]

    command = '.\\bin\\JLECmd.exe -q -d "' + TARGET_PATH + '" --json output >NUL'
    os.system(command)

    source_directory = os.path.dirname(os.path.realpath(__file__))

    outputdirectory = os.fsencode(".\\output")
    for file in os.listdir(outputdirectory):
        filename = os.fsdecode(file)
        if filename.endswith("automaticDestinations-ms.json"): 
            with open("output\\"+filename, encoding="utf8") as jsonfile:
                for line in jsonfile:
                    for ext in macroext:
                        if ext in line:
                            parsed_json = json.loads(line)
                            for i in range(len(parsed_json["DestListEntries"])):
                                recentdoc = parsed_json["DestListEntries"][i]["Path"]
                                # Extracts only first 10 digits of the epoch time as the last 3 digits are milliseconds. 
                                execution_time_epoch = int(re.sub("[^0-9]", "", parsed_json["DestListEntries"][i]["LastModified"])[:10]) - int(-time.timezone)
                                for ext in macroext:
                                    if recentdoc.endswith(ext):
                                        jmp_list=["Jmp Log"]
                                        jmp_list.append(execution_time_epoch)
                                        jmp_list.append(recentdoc)
                                        timeline_queue.put(jmp_list)
            #Remove specific jumplist file when done
            os.remove("output\\"+filename)
        #Remove other ignored jumplist type file
        if filename.endswith("customDestinations-ms.json"):
            os.remove("output\\"+filename)
    print("Jumplist processing completed!")
    timeline_queue.put("DONE")
    sys.exit()
          
def timeline_lnkfiles(TARGET_PATH,timeline_queue):
    print("Processing link files...")
    command = '.\\bin\\LECmd.exe -q -d "'+ TARGET_PATH +'" --json output >NUL'
    os.system(command)

    f = glob(os.path.join(".\\output","*_LECMD_Output.json"))[0]
    if os.path.isfile('.\\output\\lnktmp.json'):
        os.remove(".\\output\\lnktmp.json")
    os.rename(f, os.path.join(".\\output","lnktmp.json"))

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
                timeline_queue.put(lnk_list)
    os.remove(".\\output\\lnktmp.json")
    print("Link files processing completed!")
    timeline_queue.put("DONE")
    sys.exit()

def timeline_prefetch(TARGET_PATH,timeline_queue):
    print("Processing prefetch...")
    path = TARGET_PATH + r"\Windows\prefetch"
    command = '.\\bin\\PECmd.exe -q -d "' + path + '" --json output --jsonf temp.json >NUL'
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

            timeline_queue.put(first_run_list)
            timeline_queue.put(last_run_list)

    os.remove("output\\temp.json")
    print("Prefetch processing completed!")
    timeline_queue.put("DONE")
    sys.exit()

def timeline_shimcache(TARGET_PATH,timeline_queue):
    print("Processing shimcache...")
    path = TARGET_PATH + r"\Windows\System32\config\SYSTEM"
    command = '.\\bin\\regripper\\rip.exe -r "' + path + '" -p appcompatcache_tln'
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
        timeline_queue.put(shimcache_list)
    print("Shimcache processing completed!")
    timeline_queue.put("DONE")
    sys.exit()

def timeline_bam(TARGET_PATH,timeline_queue):
    print("Processing bam files...")
    path = TARGET_PATH + r"\Windows\System32\config\SYSTEM"
    command = '.\\bin\\regripper\\rip.exe -r "' + path + '" -p bam_tln | findstr "exe"'
    command_output = os.popen(command).read().split('\n')[:-1]

    for line in command_output:
        bam_list = ["BAM"]
        epoch_time = line.split('|')[0]
        executable_path = line.split('|')[4]

        bam_list.append(int(epoch_time))
        bam_list.append(executable_path)

        timeline_queue.put(bam_list)
    print("Bam processing completed!")
    timeline_queue.put("DONE")
    sys.exit()

def main():
    if len(sys.argv) != 2:
        print('Usage: python main.py <root folder of artefacts> \
        \n\n\t\te.g. python main.py C:\\Users\\Bob\\kape_output\\c')

        print('\nOutput will be saved to the output folder named YYYY-MM-DDTHHMMSS_output.csv \
            \n\n\t\te.g. 2021-10-27T160839_output.csv\n')
        return
    path = sys.argv[1]

    #Initialize all variables for main
    TARGET_PATH = path
    timeline_functions = [timeline_amcache,timeline_bam,timeline_srum,timeline_eventlog,timeline_lnkfiles,
                        timeline_prefetch,timeline_shimcache,timeline_userassist,timeline_jumplist]

    #Variables for process control and results
    EXECUTION_LIST = []
    completed_Process = 0
    timeline_queue = Queue()

    #Start process for each timelining function
    for function in timeline_functions:
        p = Process(target=function,args=(TARGET_PATH,timeline_queue,))
        p.start()
    #Queue.get() auto blocks, join is not needed.
    
    #Set listener to await data from each child timeline processors. Exit when all done.
    while True:
        data = timeline_queue.get()
        if data != "DONE":
            EXECUTION_LIST.append(data)
        else:
            completed_Process += 1
            print("Completed: (" + str(completed_Process) + "/" + str(len(timeline_functions))+ ")")
        
        #Loop control to stop getting data when all processes completes and exit.
        if completed_Process == len(timeline_functions):
            break

    #Start timeline finalization
    print("Begin timelining...")
    # Reference: https://www.geeksforgeeks.org/python-sort-list-according-second-element-sublist/
    # Sort the nested list EXECUTION_LIST by second element. 
    sorted_execution_list = sorted(EXECUTION_LIST, key = lambda x: x[1])
    print("Execution timelined!")

    file_name = datetime.datetime.now().strftime("%Y-%m-%dT%H%M%S") + "_output.csv"

    with open('output\\' + file_name, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'source', 'data']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for item in sorted_execution_list:
            # Reference: https://www.javatpoint.com/python-epoch-to-datetime 
            converted_datetime = datetime.datetime.fromtimestamp(item[1])
            execution_source = item[0]
            execution_data = item[2]
            writer.writerow({'timestamp': converted_datetime,
                            'source': execution_source,
                            'data': execution_data})
        

if __name__ == "__main__":
    main()
