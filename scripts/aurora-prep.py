import subprocess
import argparse
import glob
import os
import shutil

from fuzz_common import *


# TODO: later merge this into fuzz.py

def main():
    parser = argparse.ArgumentParser(description="Prepare files for aurora")
    parser.add_argument("crash_id", help="Id of crashing input you want to analyze")
    parser.add_argument("corpus_archive", help="Path to corupus archive")
    parser.add_argument("output_dir", help="directory where to store crash archive")
    args = parser.parse_args()

    input_id = int(args.crash_id, 10)

    _run(input_id, args.corpus_archive, args.output_dir)

def _run(input_id, corpus_archive, output_dir):
    print("[+] producing crash archive for input id")
    cmd = ['cargo', 'run' ,'--bin','hoedur-crash-archive', '--']
    cmd += ['--corpus-archive', corpus_archive]
    cmd += ['--input-id', str(input_id)]
    cmd += [output_dir]
    run(cmd)

    print("[+] running exploration mode on crash archive")
    crash_archive= f"{output_dir}/crash-#{input_id}.corpus.tar.zst"
    cmd = ['cargo', 'run' ,'--bin','hoedur-arm', '--']
    cmd += ['--import-config', crash_archive]
    cmd += ["exploration"]
    cmd += ['--archive-dir', output_dir]
    cmd += ['--import-corpus', crash_archive]
    run(cmd)

    print("[+] creating trace information required by aurora")
    crashes_dir = f"{output_dir}/traces/crashes"
    non_crashes_dir = f"{output_dir}/traces/non_crashes"
    try:
        shutil.rmtree(crashes_dir)
        shutil.rmtree(non_crashes_dir)
    except Exception as e:
        print("failed to rm dir: ", e)

    os.mkdir(crashes_dir, mode=0o755)
    os.mkdir(non_crashes_dir, mode=0o775)

    exploration_corpus = f"{output_dir}/exploration.corpus.tar.zst"
    cmd = ['cargo', 'run' ,'--bin','hoedur-arm', '--']
    cmd += ['--import-config', exploration_corpus]
    cmd += ['--debug', '--trace']
    cmd += ['--trace-type', 'root-cause']
    cmd += ['--trace-file', f"{output_dir}/traces/root-cause_trace.bin"]
    cmd += ['run-corpus', exploration_corpus]
    run(cmd)

    print("[+] all done")


if __name__ == '__main__':
    main()

