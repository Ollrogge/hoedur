import argparse
import glob
import os

from fuzz_common import *


# TODO: later merge this into fuzz.py

def main():
    parser = argparse.ArgumentParser(description="idk what this is")
    parser.add_argument('exploration_corpus', help='Paths to exploration archive')
    parser.add_argument('out_dir', help='Path where to store tracing info')
    args = parser.parse_args()

    _run(args.exploration_corpus, args.out_dir)

def _run(exploration_corpus, out_dir):
    cmd = ['cargo', 'run' ,'--bin','hoedur-arm', '--']
    cmd += ['--import-config', exploration_corpus]
    cmd += ['--debug', '--trace']
    cmd += ['--trace-type', 'root-cause']
    cmd += ['--trace-file', out_dir + "/root-cause_trace.bin"]
    #cmd += ['--hook', './root-cause-analysis/hooks/test.rs']
    cmd += ['run-corpus']
    cmd += [exploration_corpus]

    print("Running command: ", cmd)
    run(cmd)

if __name__ == '__main__':
    main()

