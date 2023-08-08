import subprocess
import argparse
import glob
import os
import shutil

from fuzz_common import *
import concurrent.futures


# TODO: later merge this into fuzz.py

def main():
    parser = argparse.ArgumentParser(description="Prepare files for aurora")
    parser.add_argument("-crash_id", help="Id of crashing input you want to analyze")
    parser.add_argument("-input_file_path", help="Path to the crashing sample")
    parser.add_argument("corpus_archive", help="Path to corupus archive")
    parser.add_argument("output_dir", help="directory where to store crash archive")
    args = parser.parse_args()

    if not args.crash_id and not args.input_file_path:
        print("need atleast one of input_id or input_file_path")

    input_id = 0
    if args.crash_id:
        input_id = int(args.crash_id, 10)

    _run(input_id, args.input_file_path, args.corpus_archive, args.output_dir)

def run_trace(args):
    f, crash_archive, output_dir = args
    cmd = ['cargo', 'run', '--bin', 'hoedur-arm', '--']
    cmd += ['--import-config', crash_archive]
    cmd += ['--debug', '--trace']
    cmd += ['--trace-type', 'root-cause']
    cmd += ['--trace-file', f"{output_dir}/traces/root-cause_trace.bin"]
    cmd += ["run", f]

    run(cmd)

def _run(input_id, input_file_path, corpus_archive, output_dir):
    crash_archive= f"{output_dir}/crash-#{input_id}.corpus.tar.zst"
    print("[+] producing crash archive for input id")
    cmd = ['cargo', 'run' ,'--bin','hoedur-crash-archive', '--']
    cmd += ['--corpus-archive', corpus_archive]
    if input_id:
        cmd += ['--input-id', str(input_id)]
    else:
        cmd += ['--input', input_file_path]


    cmd += [output_dir]
    run(cmd)

    print("[+] running exploration mode on crash archive")
    cmd = ['cargo', 'run' ,'--bin','hoedur-arm', '--']
    cmd += ['--import-config', crash_archive]
    cmd += ["exploration"]
    cmd += ['--archive-dir', output_dir]
    cmd += ['--import-corpus', crash_archive]
    run(cmd)

    #exit(1)
    # remove useless exploration corpus which was created to make fuzzer happy
    if os.path.exists(f"{output_dir}/crash-#{input_id}.exploration.corpus.tar.zst"):
        os.remove(f"{output_dir}/crash-#{input_id}.exploration.corpus.tar.zst")

    filenames = []
    for f in os.listdir(f"{output_dir}/traces/crashes"):
        filenames.append(f"{output_dir}/traces/crashes/{f}")

    for f in os.listdir(f"{output_dir}/traces/non_crashes"):
        filenames.append(f"{output_dir}/traces/non_crashes/{f}")

    print("[+] concurrently running tracing")

    args = [(f, crash_archive, output_dir) for f in filenames]

    '''
    print(args[0])
    run_trace(args[0])
    exit(0)
    '''

    with concurrent.futures.ProcessPoolExecutor(max_workers=8) as executor:
        executor.map(run_trace, args)


    '''
    print("[+] creating trace information required by aurora")
    crashes_dir = f"{output_dir}/traces/crashes"
    non_crashes_dir = f"{output_dir}/traces/non_crashes"
    # try to remove previous trace directories
    try:
        shutil.rmtree(crashes_dir)
        shutil.rmtree(non_crashes_dir)
    except Exception as e:
        print("failed to rm dir: ", e)

    os.mkdir(crashes_dir, mode=0o755)
    os.mkdir(non_crashes_dir, mode=0o775)

    exploration_corpus = f"{output_dir}/crash-#{input_id}.exploration.corpus.tar.zst"
    cmd = ['cargo', 'run' ,'--bin','hoedur-arm', '--']
    cmd += ['--import-config', exploration_corpus]
    cmd += ['--debug', '--trace']
    cmd += ['--trace-type', 'root-cause']
    # todo: useless file for aurora trace, just passed because was easier for implementation
    cmd += ['--trace-file', f"{output_dir}/traces/root-cause_trace.bin"]
    cmd += ['run-corpus', exploration_corpus]
    run(cmd)
    '''

    print("[+] all done")


if __name__ == '__main__':
    main()

