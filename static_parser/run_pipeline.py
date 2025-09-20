import os
import json
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

ROOT_DIR = '/home/download'


def get_member(div_type: str, div_name: str):
    if div_type == 'struct':
        if '->' in div_name:
            return div_name.split('->')[-1]
        else:
            return div_name.split('.')[-1]
    else:
        return ""


def get_local_or_global(pass_dict: dict, option_name: str, div_name: str):
    div_list = pass_dict[option_name]
    for div_dict in div_list:
        if div_dict[1] == div_name:
            return "local" if div_dict[2] == 0 else "global"
    return None


def retrieve_result_file(cve_id: str):
    cve_repo_dir = os.path.join(ROOT_DIR, cve_id)
    def_json_path = os.path.join(cve_repo_dir, 'def.json')
    if not os.path.exists(def_json_path):
        logging.error(f'❌ Missing required def json file: {def_json_path}')
        raise FileNotFoundError(def_json_path)

    pass_json_path = os.path.join(cve_repo_dir, 'pass.json')
    if not os.path.exists(pass_json_path):
        logging.error(f'❌ Missing required pass json file: {pass_json_path}')
        raise FileNotFoundError(pass_json_path)

    config_json_path = os.path.join(cve_repo_dir, 'config.json')
    if not os.path.exists(config_json_path):
        logging.error(f'❌ Missing required pass json file: {config_json_path}')
        raise FileNotFoundError(config_json_path)

    with open(config_json_path, 'r', encoding='utf-8') as f:
        config_dict = json.load(f)

    with open(def_json_path, 'r', encoding='utf-8') as f:
        def_dict = json.load(f)

    with open(pass_json_path, 'r', encoding='utf-8') as f:
        pass_dict = json.load(f)

    file_name = os.path.basename(config_dict['file_path'])

    div_list = []
    option_list = []
    div_2_option = dict()  # div_id ---> list of option name
    div_name_map = dict()  # div_name ---> div dict
    option_name_map = dict()  # option_name ---> option dict

    div_id = 0

    for option_name, div_info_dict in def_dict.items():
        option_dict = {
            "option_name": option_name,
            "need_value": False,
            "data_type": 0,
            "candidates_list": [],
            "str_template": ""
        }

        option_list.append(option_dict)
        option_name_map[option_name] = option_dict

        for div_name, div_info in div_info_dict.items():
            if div_info == {}:
                continue
            line_number = div_info['line']
            column_number = div_info['column']
            div_type = div_info['type']
            div_dict = None

            if div_name in div_name_map:
                div_dict = div_name_map[div_name]
            else:
                div_id += 1
                div_dict = {
                    "id": div_id,
                    "div_name": div_name,
                    "file": file_name,
                    "line": line_number,
                    "column": column_number,
                    "type": get_local_or_global(pass_dict, option_name, div_name),
                    "data_type": div_type,
                    "member": get_member(div_type, div_name)
                }
                div_list.append(div_dict)
                div_name_map[div_name] = div_dict

            assert div_dict is not None

            option_control = div_2_option.get(div_dict["id"], [])
            option_control.append(option_name)
            div_2_option[div_dict["id"]] = option_control

    div_2_option_json_path = os.path.join(cve_repo_dir, 'div_2_option.json')
    div_list_json_path = os.path.join(cve_repo_dir, 'div_list.json')
    option_list_json_path = os.path.join(cve_repo_dir, 'option_list.json')

    with open(div_2_option_json_path, 'w', encoding='utf-8') as f:
        f.write(json.dumps(div_2_option, indent=4, ensure_ascii=False))

    with open(div_list_json_path, 'w', encoding='utf-8') as f:
        f.write(json.dumps(div_list, indent=4, ensure_ascii=False))

    with open(option_list_json_path, 'w', encoding='utf-8') as f:
        f.write(json.dumps(option_list, indent=4, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Process project option for a given CVE ID.")
    parser.add_argument("--cve", required=True, help="CVE ID to process (e.g., libtiff-736)")
    args = parser.parse_args()
    cve_id = args.cve
    retrieve_result_file(cve_id)
