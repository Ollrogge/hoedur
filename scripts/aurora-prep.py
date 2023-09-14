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
    parser.add_argument("-crash_file_path", help="Path to the crashing sample")
    parser.add_argument("corpus_archive", help="Path to corupus archive")
    parser.add_argument("output_dir", help="directory where to store crash archive")
    args = parser.parse_args()

    if not args.crash_id and not args.crash_file_path:
        print("need atleast one of input_id or input_file_path")

    input_id = 0
    if args.crash_id:
        input_id = int(args.crash_id, 10)

    _run(input_id, args.crash_file_path, args.corpus_archive, args.output_dir)

def run_exploration(input_id, crash_file_path, corpus_archive, output_dir, crash_archive):
    print("[+] producing crash archive for input id")
    cmd = ['cargo', 'run' ,'--bin','hoedur-crash-archive', '--']
    cmd += ['--corpus-archive', corpus_archive]
    if input_id:
        cmd += ['--input-id', str(input_id)]
    else:
        cmd += ['--input', crash_file_path]


    cmd += [output_dir]
    run(cmd)

    print("[+] running exploration mode on crash archive")
    cmd = ['cargo', 'run' ,'--bin','hoedur-arm', '--']
    cmd += ['--import-config', crash_archive]
    cmd += ["exploration"]
    cmd += ['--archive-dir', output_dir]
    cmd += ['--import-corpus', crash_archive]
    cmd += ['--duration', '3']
    run(cmd)

def run_trace(args):
    f, crash_archive, output_dir = args
    cmd = ['cargo', 'run', '--bin', 'hoedur-arm', '--']
    cmd += ['--import-config', crash_archive]
    cmd += ['--debug', '--trace']
    cmd += ['--trace-type', 'root-cause']
    cmd += ['--trace-file', f"{output_dir}/traces/root-cause_trace.bin"]
    cmd += ["run", f]

    run(cmd)

def run_traces(output_dir, input_id, crash_archive, single = False):
    if os.path.exists(f"{output_dir}/crash-#{input_id}.exploration.corpus.tar.zst"):
        os.remove(f"{output_dir}/crash-#{input_id}.exploration.corpus.tar.zst")

    elf = glob.glob(f"{output_dir}/*.elf")
    if len(elf) == 0:
        print("[-] Missing elf file required by aurora")
    else:
        os.system(f"cp {output_dir}/{elf} {output_dir}/traces/tmp_trace")

    filenames = []
    for f in glob.glob(f"{output_dir}/traces/crashes/*#*.bin"):
        filenames.append(f)

    for f in glob.glob(f"{output_dir}/traces/non_crashes/*#*.bin"):
        filenames.append(f)

    print("[+] concurrently running tracing")

    args = [(f, crash_archive, output_dir) for f in filenames]

    if single:
        for i in range(1):
            run_trace(args[i])
    else:
        with concurrent.futures.ProcessPoolExecutor(max_workers=8) as executor:
            executor.map(run_trace, args)

def _run(input_id, crash_file_path, corpus_archive, output_dir):
    crash_archive= f"{output_dir}/crash-#{input_id}.corpus.tar.zst"

    run_exploration(input_id, crash_file_path, corpus_archive, output_dir, crash_archive)

    run_traces(output_dir, input_id, crash_archive, False)
    print("[+] all done")
    ''''
    print("[+] producing crash archive for input id")
    cmd = ['cargo', 'run' ,'--bin','hoedur-crash-archive', '--']
    cmd += ['--corpus-archive', corpus_archive]
    if input_id:
        cmd += ['--input-id', str(input_id)]
    else:
        cmd += ['--input', crash_file_path]


    cmd += [output_dir]
    run(cmd)

    print("[+] running exploration mode on crash archive")
    cmd = ['cargo', 'run' ,'--bin','hoedur-arm', '--']
    cmd += ['--import-config', crash_archive]
    cmd += ["exploration"]
    cmd += ['--archive-dir', output_dir]
    cmd += ['--import-corpus', crash_archive]
    cmd += ['--duration', '10']
    run(cmd)


    #exit(1)
    # remove useless exploration corpus which was created to make fuzzer happy
    if os.path.exists(f"{output_dir}/crash-#{input_id}.exploration.corpus.tar.zst"):
        os.remove(f"{output_dir}/crash-#{input_id}.exploration.corpus.tar.zst")

    elf = glob.glob(f"{output_dir}/*.elf")
    if len(elf) == 0:
        print("[-] Missing elf file required by aurora")
    else:
        os.system(f"cp {output_dir}/{elf} {output_dir}/traces/tmp_trace")

    filenames = []
    for f in glob.glob(f"{output_dir}/traces/crashes/*#*.bin"):
        filenames.append(f)

    for f in glob.glob(f"{output_dir}/traces/non_crashes/*#*.bin"):
        filenames.append(f)

    print("[+] concurrently running tracing")

    args = [(f, crash_archive, output_dir) for f in filenames]
    print(args[0])
    for i in range(1):
        run_trace(args[i])
    exit(0)
    with concurrent.futures.ProcessPoolExecutor(max_workers=8) as executor:
        executor.map(run_trace, args)
    '''


if __name__ == '__main__':
    main()

