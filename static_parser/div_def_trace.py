import difflib
import json
import os
import sys
import html
import pprint
import pygraphviz as pgv
import scubatrace
import subprocess
import pprint
import pygraphviz as pgv
import re
import textwrap
import logging
import argparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

ROOT_DIR = '/home/download'


def map_lines(pre_file, joern_file):
    with open(pre_file, 'r', encoding='utf-8') as f:
        pre_lines = f.readlines()
    with open(joern_file, 'r', encoding='utf-8') as f:
        post_lines = f.readlines()

    # SequenceMatcher
    sm = difflib.SequenceMatcher(None, pre_lines, post_lines)
    mapping = []

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            
            for pre_idx, post_idx in zip(range(i1, i2), range(j1, j2)):
                mapping.append({'pre': pre_idx + 1, 'joern': post_idx + 1})
        elif tag == 'replace':

            mapping.append({'pre': list(range(i1 + 1, i2 + 1)),
                            'joern': list(range(j1 + 1, j2 + 1))})
        elif tag == 'delete':

            mapping.append({'pre': list(range(i1 + 1, i2 + 1)), 'joern': []})
        elif tag == 'insert':
      
            mapping.append({'pre': [], 'joern': list(range(j1 + 1, j2 + 1))})

    return mapping

def var_line_column_loc(option_func, joern_pass, joern_file):
    global_div_usage_num = 0
    local_div_usage_num = 0
    var_coordinate = {}
    
    if "'?'" in joern_pass:
        joern_pass.pop("'?'")
    if "end_line" in joern_pass:
        joern_pass.pop("end_line")
    if "parse_func" in joern_pass:
        joern_pass.pop("parse_func")
    
    with open(joern_file, 'r', encoding='utf-8') as f:
        joern_lines = f.readlines()
    for option, args_meta in joern_pass.items():
        var_coordinate[option] = {}
        for arg_meta in args_meta:
            function_name = arg_meta[0]
            var_name = arg_meta[1]
            unknown_bool = arg_meta[2]
            line_num = arg_meta[3]
            global_flag = arg_meta[4]
            if function_name != option_func:
                continue
            if line_num > 0:
                line_content = joern_lines[line_num - 1]
            else:
                line_num = arg_meta[5]["assignment"]["line"]
                line_content = joern_lines[arg_meta[5]["assignment"]["line"] - 1]
 
            unified_var_name = html.unescape(var_name)
            col_index = line_content.find(unified_var_name)
            col_num = col_index + 1
            var_coordinate[option][unified_var_name] = (line_num, col_num)
            # if option == "'i'":
            #     print(unified_var_name, line_content)
    return var_coordinate

def recover_original_line(joern_var_coordinate, mapping):
    var_coordinate = {}
    for option, var_info in joern_var_coordinate.items():
        var_coordinate[option] = {}
        for var_name, (line_num, col_num) in var_info.items():
            for tuple in mapping:
                if tuple["joern"] == line_num:
                    var_coordinate[option][var_name] = (tuple["pre"], col_num)  # 记录原始行号和列号
    return var_coordinate

def def_trace(filename, var_coordinate, svfg_dot_pth):
    dot_data = open(svfg_dot_pth).read()
    graph = pgv.AGraph(string=dot_data)

    div_def_dic = {}
    pprint.pprint(var_coordinate, indent=2)
    
    for option, var_info in var_coordinate.items():
        print(option)
        div_def_dic[option] = {}
        for var_name, (line_num, col_num) in var_info.items():
            div_def_dic[option][var_name] = {}

            line_node_list = []
            for node in graph.nodes():
                label = node.attr.get("label", "")
           
                if not (f"ln: {line_num}" in label and f"fl: {filename}" in label):
                    continue
                line_node_list.append(node)
       
            if line_node_list == []:
                continue
            best_match_node = None
            best_match_distance = 10000
      
            for node in line_node_list:
                label = node.attr.get("label", "")

                if "BranchStmt" in label:
                    continue
                if "cl: " in label:
                    column_num = int(label.split("cl: ")[1].split(" ")[0])
                    distance = abs(column_num - col_num)
                else:
                    distance = 1000
                if distance < best_match_distance:
                    best_match_node = node
                    best_match_distance = distance
    
            start = best_match_node
            heads = set()
            stack = [start]
          
            visited = set([start])
            initial_node = None
            while stack:
                cur = stack.pop()
                preds = graph.predecessors(cur)
                if not preds or graph.in_degree(cur) == 0:
                    heads.add(cur)
                    continue
                for p in preds:
                    if p in visited:
                        continue
                    visited.add(p)
                    stack.append(p)
                    if "AddrStmt" in p.attr.get("label", ""):
                        initial_node = p
            if initial_node:
                div_def_dic[option][var_name] = {
                    "def_instruction": {
                        "label": initial_node.attr.get("label", ""),
                        "id": initial_node,
                    },
                    "option_var_instruction": {
                        "label": start.attr.get("label", ""),
                        "id": start,
                    }
                }
    return div_def_dic

def split_path(path: str) -> tuple[str, str]:
    p = path if path == "/" else path.rstrip("/")
    dir_path = os.path.dirname(p) or "."
    file_name = os.path.basename(p)
    return dir_path, file_name

def find_nodes_by_function_and_line(graph, function_name, line_num, var_name=None):

    matching_nodes = []

    for node in graph.nodes():
        node_attr = node.attr
        label = node_attr.get('label', '')

    
        if function_name in label and f"line: {line_num}" in label and "file: tiffcrop.c" in label:
       
            if var_name is None or var_name in label:
                matching_nodes.append({
                    'node_id': node.get_name(),
                    'label': label,
                    'function': function_name,
                    'line': line_num,
                    'var_name': var_name
                })

    return matching_nodes


def process_div_def_trace(cve_id: str):
    cve_repo_dir = os.path.join(ROOT_DIR, cve_id)
    source_code_dir = os.path.join(cve_repo_dir, 'source-code')
    config_file_path = os.path.join(cve_repo_dir, 'config.json')

    with open(config_file_path, 'r', encoding='utf-8') as f:
        config_dict = json.load(f)

    file_name = os.path.basename(config_dict['file_path'])

    pre_file = os.path.join(source_code_dir, config_dict['file_path'])
    if not os.path.exists(pre_file):
        logging.error(f'❌ Missing required previous C source file: {pre_file}')
        raise FileNotFoundError(pre_file)

    joern_file = os.path.join(cve_repo_dir, file_name)
    if not os.path.exists(joern_file):
        logging.error(f'❌ Missing required Joern C source file: {joern_file}')
        raise FileNotFoundError(joern_file)

    mapping = map_lines(pre_file, joern_file)

    pass_file_path = os.path.join(cve_repo_dir, 'pass.json')
    if not os.path.exists(pass_file_path):
        logging.error(f'❌ Missing required pass json file: {pass_file_path}')
        raise FileNotFoundError(pass_file_path)

    with open(pass_file_path, "r", encoding="utf-8") as f:
        joern_pass = json.load(f)

    bc_file_path = os.path.join(cve_repo_dir, f'{config_dict["component_name"]}.bc')
    if not os.path.exists(bc_file_path):
        logging.error(f'❌ Missing required BC file: {bc_file_path}')
        raise FileNotFoundError(bc_file_path)


    svfg_dot_path = os.path.join(cve_repo_dir, 'svfg.dot')
    if not os.path.exists(svfg_dot_path):
        logging.error(f'❌ Missing required SVFG dot graph file: {svfg_dot_path}')
        raise FileNotFoundError(svfg_dot_path)
    
    div_def_trace_path = os.path.join(cve_repo_dir, 'div_def_trace.json')

    option_func = config_dict["option_func"]
    joern_var_coordinate = var_line_column_loc(option_func, joern_pass, joern_file)

    var_coordinate = recover_original_line(joern_var_coordinate, mapping)

  
    located_nodes = def_trace(file_name, var_coordinate, svfg_dot_path)
   
    with open(div_def_trace_path, "w", encoding="utf-8") as f:
        json.dump(located_nodes, f, indent=4, ensure_ascii=False)

    with open(div_def_trace_path, "r", encoding="utf-8") as f:
        div_def_trace = json.load(f)

    div_def_dict = {}
    
    
    root_dir, filename = split_path(pre_file)
    file_pth = os.path.join(root_dir, filename)
    project = scubatrace.Project.create(root_dir, language=scubatrace.language.C)
    file = project.files[filename]

    with open(file_pth, "r", encoding="utf-8") as f:
        file_content = f.readlines()

    for option, var_info in div_def_trace.items():
        if not var_info or var_info == []:
            continue
        div_def_dict[option] = {}
        if option == {}:
            continue
        for var_name, node_info in var_info.items():
            div_def_dict[option][var_name] = {}
            if node_info == {}:
                continue
            if "def_instruction" not in node_info:
                continue
            
            if "ln: " not in node_info["def_instruction"]["label"]:
                print("error!!!", option, var_name)
                continue
            
            def_line = int(node_info["def_instruction"]["label"].split("ln: ")[1].split(" ")[0])
            line_content = file_content[def_line - 1]
            # variable = file.statements_by_line(def_line)[0]
            
            div_def_dict[option][var_name] = {
                "line": def_line,
                "column": int(node_info["def_instruction"]["label"].split("ln: ")[1].split(" ")[0]),
                "line_content": line_content
            }
            
            if "struct" in line_content:
                div_def_dict[option][var_name]["type"] = "struct"
            elif "[" in line_content and "]" in line_content:
                div_def_dict[option][var_name]["type"] = "array"
            elif "*" in line_content and "/*" not in line_content:
                div_def_dict[option][var_name]["type"] = "pointer"
            else:
                div_def_dict[option][var_name]["type"] = "basic"

    def_json_path = os.path.join(cve_repo_dir, "def.json")
    with open(def_json_path, "w", encoding="utf-8") as f:
        json.dump(div_def_dict, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process DIV definition trace for a given CVE ID.")
    parser.add_argument("--cve", required=True, help="CVE ID to process (e.g., libtiff-736)")
    args = parser.parse_args()
    cve_id = args.cve
    process_div_def_trace(cve_id)
    