#!/usr/bin/env python3

import argparse
from fuzz_common import *

def main():
    parser = argparse.ArgumentParser(description="Prepare files for aurora")
    parser.add_argument("-crash_id", help="Id of crashing input you want to analyze")
    parser.add_argument("-crash_file_path", help="Path to the crashing sample")
    parser.add_argument("-duration", help="duration in minutes",default=10)
    parser.add_argument("corpus_archive", help="Path to corupus archive")
    args = parser.parse_args()

    if not args.crash_id and not args.crash_file_path:
        print("need atleast one of input_id or input_file_path")

    input_id = 0
    if args.crash_id:
        input_id = int(args.crash_id, 10)

    _run(input_id, args.crash_file_path, args.corpus_archive, args.duration)

def _run(input_id, crash_file_path, corpus_archive,duration):
    output_dir = os.path.dirname(corpus_archive)
    crash_archive= f"{output_dir}/crash-#{input_id}.corpus.tar.zst"
    run_exploration(input_id, crash_file_path, corpus_archive, output_dir, crash_archive, duration)

def run_exploration(input_id, crash_file_path, corpus_archive, output_dir, crash_archive, duration):
    build("hoedur-crash-archive")
    print("[+] producing crash archive for input id")

    cmd = ['hoedur-crash-archive']
    cmd += ['--corpus-archive', corpus_archive]
    if input_id:
        cmd += ['--input-id', str(input_id)]
    else:
        cmd += ['--input', crash_file_path]

    cmd += [output_dir]
    run(cmd)

    if os.path.exists(f"{output_dir}/crash-#{input_id}.exploration.corpus.tar.zst"):
        os.remove(f"{output_dir}/crash-#{input_id}.exploration.corpus.tar.zst")

    fuzzer = "hoedur-exploration"
    try:
        subprocess.check_call([f"{fuzzer}-arm", '--help'],
                                  stdout=subprocess.DEVNULL)
    except:
        fuzzer = "hoedur"

    cmd = init_hoedur_import_config(fuzzer, crash_archive)
    cmd += ["exploration"]
    cmd += ['--import-corpus', crash_archive]
    cmd += ['--archive-dir', output_dir]
    cmd += ['--duration', duration]

    print("Cmd: ", cmd)
    run(cmd)

if __name__ == '__main__':
    main()

