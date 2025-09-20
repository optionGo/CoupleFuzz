import argparse
from genericpath import exists
import os
import shutil
from socket import timeout
import subprocess
import json
import time
from time import sleep
import sys


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-f", dest="input",
                   help="Input", required=False)
    p.add_argument("-o", dest="fuzzer", help="Fuzzer output Directory", required=False)
    p.add_argument("cmd", nargs="+",
                   help="Command to execute: use @@ to denote a file")
    p.add_argument("-t", dest="timeout",
                   help="Timeout for structure inference", type=int, required=True)
    p.add_argument("--opt_list", , dest="option_list_path" ,required=True, help="option_list path") # option_list 
    p.add_argument("--constraint", dest="constraint_path" ,required=True, help="constraint relationship path") # constraint
    return p.parse_args()


def gen_cmd(cmd, timeout, input):
    
    input = '"' + input + '"'
    shell = []
    if timeout:
        shell += ["timeout", "-k", str(5), str(timeout)]
    
    li = [input if i == "@@" else i for i in cmd]
    shell += li
    return shell



def set_isi_path(input):
    new_path = os.path.join(os.path.dirname(input), input + ".isi")
    os.rename(input, new_path)
    return new_path

def generate_conflict_options(cmds, option_name_list, equivalence_sets, isi_path):
    cur_cmd_option = cmds[1].split(' ')
    cur_cmd_option_names = [e for e in cur_cmd_option if e in option_name_list]
    
    conflict_options = []
    
    for opt_name in option_name_list:
        if opt_name in cur_cmd_option_names:
            continue
        
        temp_options = cur_cmd_option_names + [opt_name]
        temp_set = set(temp_options)
        is_conflict = False
        
        for equivalence_set in equivalence_sets:
            if len(equivalence_set) != 2:
                continue
            
            set1 = set(equivalence_set[0])
            set2 = set(equivalence_set[1])
            
            if set1 & set2:
                continue
            
            union_set = set1.union(set2)
            has_no_extra = temp_set.issubset(union_set)
            contains_set1 = set1.issubset(temp_set)
            contains_set2 = set2.issubset(temp_set)
            
            if has_no_extra and contains_set1 and contains_set2:
                is_conflict = True
                break 
        
        if is_conflict:
            conflict_options.append(opt_name)
    new_conflict_path = isi_path + ".conflict_option.json"
    print(conflict_options)
    with open(new_conflict_path, 'w',encoding='utf-8') as f:
        json.dump(conflict_options, f)

def taint_infer(input, cmd, timeout, option_name_list, equivalence_sets):
    isi_path = set_isi_path(input)
    shell = gen_cmd(cmd, timeout, isi_path)
    # print(cmd)
    print("### Infer " + input + " ###")
    print(" ".join(shell))
    
    generate_conflict_options(cmd, option_name_list, equivalence_sets, isi_path)
    start_time = time.time()
    proc = os.system(" ".join(shell))
    # stdout, stderr = proc.communicate()
    old_variable_path = os.path.join(os.getcwd(), "variable_usage_counter.json")
    old_bb_path = os.path.join(os.getcwd(), "bb_taint_seg_logger.json")
    new_variable_path = isi_path + ".variable_usage_counter.json"
    new_bb_path = isi_path + ".bb_taint_seg_logger.json"
    
    target_dir = os.path.dirname(isi_path)
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    
    if os.path.exists(old_variable_path):
        shutil.move(old_variable_path, new_variable_path)
    if os.path.exists(old_bb_path):
        shutil.move(old_bb_path, new_bb_path)
    
    end_time = time.time()
    # msg = "Infer file: " + input + " \n" + "Infer time: " + str(end_time - start_time) + "\n" + "Return code: " + str(proc.returncode) + "\n"
    # if os.path.exists(isi_path):
    #     os.remove(isi_path)
  
def parse_cmd(cmd, seed):
    cmd_copy = cmd.copy()
    for i in range(len(cmd_copy)):
        if cmd_copy[i] == "%%":
            cmd_copy[i] = seed.split("*")[-1] if "*" in seed else " "
    return cmd_copy

def handle_fuzzer_out(output, cmd, timeout, option_name_list, equivalence_sets):
    fuzzer_queue = os.path.join(output, "queue")
    infer_dir = os.path.join(output, "infer")
    if not os.path.exists(infer_dir):
        os.mkdir(infer_dir)

    processed = []
    while True:
        seeds = os.listdir(fuzzer_queue)
        for seed in seeds:
            if seed == ".state":
                continue
            if processed.count(seed):
                continue
            processed.append(seed)

            seed_path = os.path.join(fuzzer_queue, seed)
            shutil.copy(seed_path, infer_dir)

            input_path = os.path.join(infer_dir, seed)
            cmd = parse_cmd(cmd, seed) # ['$bin', '-e i -l -s -t -w -V -X -Y', '@@']
            print(cmd)
            taint_infer(input_path, cmd, timeout, option_name_list, equivalence_sets)

            
        print("###Wait 30s for new files###")
        sleep(2)

def main():
    args = parse_args()
    if not args.fuzzer and not args.input:
        print("set -f or -o")
        exit()
    cmd = args.cmd
    timeout = args.timeout
     
    with open(args.option_list_path, encoding='utf-8') as f:
        option_list = json.load(f)  
    option_name_list = [option['option_name'] for option in option_list]

    with open(args.constraint_path, encoding='utf-8') as f:
        constraint = json.load(f)  
    equivalence_sets = constraint['equivalence_sets']
    
    if args.fuzzer:
        handle_fuzzer_out(args.fuzzer, cmd, timeout, option_name_list, equivalence_sets)

    if args.input:
        taint_infer(args.input, cmd, timeout)

if __name__ == "__main__":
    main()
