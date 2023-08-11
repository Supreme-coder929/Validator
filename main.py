import sys 
import hashlib 
import requests
import argparse
import time
import re

parser = argparse.ArgumentParser(description="Tamper Detection")
parser.add_argument("-o", "--original", help="Specifiy the Orginial File in the Local System")
parser.add_argument("-u", "--targeturlf", help="Specifiy the url/file location")
args = parser.parse_args()


ALGORITHM = "md5"
BANNER_LOGO = lambda: '''

    ██╗░░░██╗░█████╗░██╗░░░░░██╗██████╗░░█████╗░████████╗░█████╗░██████╗░
    ██║░░░██║██╔══██╗██║░░░░░██║██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗
    ╚██╗░██╔╝███████║██║░░░░░██║██║░░██║███████║░░░██║░░░██║░░██║██████╔╝
    ░╚████╔╝░██╔══██║██║░░░░░██║██║░░██║██╔══██║░░░██║░░░██║░░██║██╔══██╗
    ░░╚██╔╝░░██║░░██║███████╗██║██████╔╝██║░░██║░░░██║░░░╚█████╔╝██║░░██║
    ░░░╚═╝░░░╚═╝░░╚═╝╚══════╝╚═╝╚═════╝░╚═╝░░╚═╝░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝

'''


class color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'



class Tamper_Detect:
    def __init__(self):
        pass

    def try_request_external_target_file_data(self, url_loc: str) -> str:
        try:
            return requests.get(url_loc).text
        except requests.exceptions.MissingSchema: pass
        except requests.exceptions.ConnectionError: print(color.BOLD + color.RED + "[!] Connection could not established." + color.END)


    def check_file_integrity(self):

        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit()

        unhashed_files: list=[args.original]
        print(BANNER_LOGO())
        print(color.BOLD + "[?] Validating file integrity....." + color.END)
        data_set = {}
        
        if args.targeturlf: unhashed_files.append(args.targeturlf)
        elif not args.targeturlf: sys.exit(color.BOLD + color.RED + "[!] Must supply a target url/file paramter." + color.END)
        else: sys.exit("Must pick a target file")


    
        try:
            for i, file in enumerate(unhashed_files):
                if i == 1:
                    data_set["File 2"] = getattr(hashlib, ALGORITHM)([self.try_request_external_target_file_data(file) if file.startswith("https://") or file.startswith("http://") and self.try_request_external_target_file_data(file) != None else open(file, "r").read()][0].encode()).hexdigest()
                else:
                    data_set[f"File {i+1}"] = getattr(hashlib, ALGORITHM)(open(file, "r").read().encode()).hexdigest()


        except FileNotFoundError:
            sys.exit(color.RED + color.BOLD + "[!] Invalid file location provided." + color.END)

        

        if data_set["File 1"] != data_set["File 2"]:
            print(color.BOLD + color.RED + "[!] Target file INTEGRITY[FALSE]" + color.END)
            print(color.BOLD + color.RED + "[!] {file} is not equal to {second_file}. Therfore it has been tampered/edited with.".format(file=unhashed_files[1], second_file=unhashed_files[0]) + color.END)
        else: print(color.BOLD + color.GREEN + "[!] Target file INTEGRITY[TRUE]" + color.END)

    def start(self):
        self.check_file_integrity()


start_func = Tamper_Detect()
start_func.start()