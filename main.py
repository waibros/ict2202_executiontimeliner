import os, json

def parse_prefetch():
    prefetch_list = []
    # command = '.\\bin\\PECmd.exe -q -d "sample\C\Windows\prefetch" --json output --jsonf temp.json'
    # os.system(command)
    with open("output\\temp.json") as jsonfile:
        for line in jsonfile:
            tmp_list = ["Prefetch"]
            
            executable_path = ""
            parsed_json = json.loads(line)
            executable_name = parsed_json["ExecutableName"]
            files_loaded = parsed_json["FilesLoaded"]
            executable_path = ""
            for file in files_loaded.split(","):
                if executable_name in file:
                    executable_path = file
            # tmp_list.append(parsed_json["SourceCreated"]) # first run
            tmp_list.append(parsed_json["SourceModified"]) # last run
            tmp_list.append(executable_path)
            print(tmp_list) 

def main():
    parse_prefetch()

if __name__ == "__main__":
    main()