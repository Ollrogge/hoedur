import subprocess
import argparse
import glob
import os

from fuzz_common import *


# TODO: later merge this into fuzz.py

def main():
    parser = argparse.ArgumentParser(description="idk what this is")
    parser.add_argument('crash_corpus', help='Paths to exploration archives')
    parser.add_argument('archive', help='Path where to store result of exploration')
    args = parser.parse_args()

    _run(args.crash_corpus, args.archive)

def _run(crash_corpus, archive):
    cmd = ['cargo', 'run' ,'--bin','hoedur-arm', '--']
    cmd += ['--import-config', crash_corpus]
   # cmd += ['--help']
    cmd += ['--debug', '--trace']
    cmd += ['--trace-type', 'root-cause']
    #cmd += ['--hook', './root-cause-analysis/hooks/test.rs']
    cmd += ['exploration']
    cmd += ['--archive-dir', archive]
    cmd += ['--import-corpus', crash_corpus]

    print("Running command: ", cmd)
    run(cmd)

if __name__ == '__main__':
    main()
