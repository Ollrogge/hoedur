import subprocess
import argparse
import glob
import os

from fuzz_common import *


# TODO: later merge this into fuzz.py

def main():
    parser = argparse.ArgumentParser(description="idk what this is")
    parser.add_argument('config_file', help='Path to reproducer config archive')
    parser.add_argument('inputs', help='Paths of reproducer input files')
    parser.add_argument('archive_dir', help='Path where to create archive')
    args = parser.parse_args()

    _run(args.config_file, args.inputs, args.archive_dir)

def _run(config_file, inputs, archive_dir):
    cmd = ['cargo', 'run' ,'--bin','hoedur-arm', '--']
    cmd += ['--import-config', config_file]
    cmd += ['exploration']
    cmd += ['--archive-dir', archive_dir]
    cmd += ['--inputs', inputs]

    print("Running command: ", cmd)
    run(cmd)

if __name__ == '__main__':
    main()
