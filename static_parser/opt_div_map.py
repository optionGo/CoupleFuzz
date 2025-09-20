import scubatrace
import json
import os


def arg_switch_map(arg_node, tNode):
    arg_code = arg_node.children[0]
    empty_node = arg_node.children[1] # 空节点
    args_dict = {}
    now_arg = None
    for child_num, child in enumerate(empty_node.children):
        if child.jt_content == "case" and empty_node.children[child_num + 1].lit_var != "":
            now_arg = empty_node.children[child_num + 1].lit_var
        if now_arg not in args_dict:
            args_dict[now_arg] = []
        args_dict[now_arg].append(child)
    for arg, children in args_dict.items():
        for child in children:
            if child.num == tNode.num:
                return arg
    return None

def arg_if_map(arg_node, tNode):
    return arg_node.cst_right

def arg_elif_map(arg_node, tNode):
    return arg_node.cst_right 

def arg_else_map(arg_node, tNode, topNode):
    arg_list = []
    cur_node = arg_node
    while cur_node is not None and cur_node.parent and cur_node.cst_right_type != 'switch':
        par_node = cur_node.parent[0]
        if par_node == topNode:
            break
        if par_node is not None and par_node.type_str == 'CONTROL_STRUCTURE':
            if any(kw in par_node.cst_right for kw in ("else", "switch")):
                cur_node = par_node
                continue
            if any(
                substr in par_node.cst_right for substr in
                ["optarg", "argv", "opt_arg", "argument", "param", "p[1]",
                 "clp-&gt;vstr", "clp-&gt;val.i", "clp-&gt;val.s",
                 "clp-&gt;val.u"]) and par_node.cst_right_type == 'if':
                arg_list.append(f'! {par_node.cst_right}')
        cur_node = par_node
    if arg_list:
        return ' && '.join(arg_list)
    else:
        return None