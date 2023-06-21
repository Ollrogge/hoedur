import subprocess
import argparse
import glob

from fuzz_common import *


# TODO: later merge this into fuzz.py

def main():
    parser = argparse.ArgumentParser(description="idk what this is")
    parser.add_argument('config_file', help='Path to reproducer config file')
    parser.add_argument('import_corpus', help='Path of reproducer input file')
    parser.add_argument('archive_dir', help='Path where to create archive')
    args = parser.parse_args()

    _run(args.config_file, args.import_corpus, args.archive_dir)

def _run(config_file, import_corpus, archive_dir):

    cmd = ['cargo', 'run' ,'--bin','hoedur-arm', '--']
    cmd += ['--import-config', config_file]
    cmd += ['--archive-dir', archive_dir]
    cmd += ['root-cause']
    cmd += [input_file]

    print("Running command: ", cmd)
    run(cmd)

if __name__ == '__main__':
    main()
