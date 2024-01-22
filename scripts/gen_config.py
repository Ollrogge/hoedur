import argparse
import os
import subprocess
from glob import glob

def main():
    parser = argparse.ArgumentParser(description="Create Hoedur config from bin / elf file")

    parser.add_argument("path", help="Path to directory containing file")

    args = parser.parse_args()

    file_path = glob(f"{args.path}/*.elf")

    if not file_path:
        bin_file = glob(f"{args.path}/*.bin")

        if not bin_file:
            print("No appropriate file found in dir")
            exit(1)

        file_path = bin_file

    file_path = file_path[0]
    file_dir = os.path.dirname(file_path)

    for f in glob(f"{file_dir}/config.yml"):
        os.remove(f)

    subprocess.check_output(["fuzzware", "genconfig", file_path], stderr=subprocess.STDOUT)

    subprocess.check_output(["hoedur-convert-fuzzware-config", "config.yml", "config.yml"], stderr=subprocess.STDOUT)

    print("[+] config.yml generated")

if __name__ == '__main__':
    main()
