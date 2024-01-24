#!/usr/bin/env python3

import argparse
import glob
import os
from fuzz_common import *
import concurrent.futures

def main():
    parser = argparse.ArgumentParser(description="Prepare files for aurora")
    parser.add_argument("-crash_id", help="Id of crashing input you want to analyze")
    parser.add_argument("corpus_dir", help="Corpus directory")
    args = parser.parse_args()

    input_id = 0
    if args.crash_id:
        input_id = int(args.crash_id, 10)

    _run(input_id, args.corpus_dir)

def run_trace(args):
    f, crash_archive, output_dir = args
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    #cmd = ['cargo', 'run', '--bin', 'hoedur-arm', '--']
    cmd = ['hoedur-arm']
    cmd += ['--import-config', crash_archive]
    cmd += ['--debug', '--trace']
    cmd += ['--hook', f'{cur_dir}/../emulator/hooks/memcpy.rn']
    cmd += ['--trace-type', 'root-cause']
    cmd += ['--trace-file', f"{output_dir}/exploration/root-cause_trace.bin"]
    cmd += ["run", f]

    run(cmd)

def run_tracing(corpus_dir, input_id, crash_archive):
    if not os.path.exists(f"{corpus_dir}/traces"):
        os.makedirs(f"{corpus_dir}/traces")
    else:
        for f in glob.glob(f"{corpus_dir}/traces/crashes/*-full.bin"):
            os.remove(f)

        for f in glob.glob(f"{corpus_dir}/traces/crashes/*-summary.bin"):
            os.remove(f)

        for f in glob.glob(f"{corpus_dir}/traces/non_crashes/*-full.bin"):
            os.remove(f)

        for f in glob.glob(f"{corpus_dir}/traces/non_crashes/*-summary.bin"):
            os.remove(f)

    filenames = []
    for f in glob.glob(f"{corpus_dir}/exploration/crashes/*#*.bin"):
        filenames.append(f)

    for f in glob.glob(f"{corpus_dir}/exploration/non_crashes/*#*.bin"):
        filenames.append(f)

    if len(filenames) == 0:
        print("[-] No exploration files found")
        exit(1)

    print("[+] concurrently tracing")

    args = [(f, crash_archive, corpus_dir) for f in filenames]

    cpus = os.cpu_count()
    with concurrent.futures.ProcessPoolExecutor(max_workers=cpus-1) as executor:
        executor.map(run_trace, args)

def _run(input_id, corpus_dir):
    crash_archive= f"{corpus_dir}/crash-#{input_id}.corpus.tar.zst"

    run_tracing(corpus_dir, input_id, crash_archive)


if __name__ == '__main__':
    main()

