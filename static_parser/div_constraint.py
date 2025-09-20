import json
import argparse
PROJECT_ROOT_DIR = '/home/download'
def generate_equivalence_sets(equivalent_combinations):
    """
    Generate a large set containing all equivalence relations as tuples of option lists
    
    Parameters:
    equivalent_combinations: List of equivalent combination pairs
    
    Returns:
    Set of tuples (option_list1, option_list2) where both lists correspond to the same variable set
    and have no overlapping options
    """
    # Create a set to store all equivalence relations (automatically deduplicates)
    equivalence_set = set()
    
    # Add all equivalent combination pairs to the set
    for combo1, combo2, var_set in equivalent_combinations:
        # Ensure combo1 and combo2 are lists (not tuples) for consistency
        option_list1 = list(combo1)
        option_list2 = list(combo2)
        
        # Create a normalized tuple (sorted to ensure consistent ordering)
        # This ensures that (A, B) and (B, A) are treated as the same equivalence relation
        normalized_pair = tuple(sorted([tuple(sorted(option_list1)), tuple(sorted(option_list2))]))
        equivalence_set.add(normalized_pair)
    
    return equivalence_set

def constraint_generation(div_2_option, ignore_vars=None):
    """
    Find completely equivalent option combinations and generate equivalence sets
    
    Parameters:
    div_2_option: Dictionary with variable IDs as keys and corresponding option lists as values
    ignore_vars: List of variable IDs to ignore, these variables will be excluded from calculation
    
    Returns:
    Dictionary containing two keys:
    - 'equivalence_sets': Set of tuples (option_list1, option_list2) representing equivalence relations
    - 'pairs': Original list of equivalent combination pairs
    """
    from itertools import combinations
    from collections import defaultdict
    
    # Handle ignored variables
    if ignore_vars is None:
        ignore_vars = []
    else:
        ignore_vars = [str(var) for var in ignore_vars]  # Ensure string format
    
    print(f"Ignored variable IDs: {ignore_vars}")
    
    # Build mapping from option to variable IDs (excluding ignored variables)
    option_to_vars = {}
    for var_id, options in div_2_option.items():
        if var_id in ignore_vars:
            print(f"Ignoring variable {var_id}")
            continue
        for option in options:
            if option not in option_to_vars:
                option_to_vars[option] = set()
            option_to_vars[option].add(var_id)
    
    # Get all options
    all_options = list(option_to_vars.keys())
    print(f"Total {len(all_options)} different options")
    
    # Use dictionary to store mapping from variable sets to option combinations
    vars_to_combos = defaultdict(list)
    
    # Limit combination size to avoid exponential explosion, only process small combinations
    max_combo_size = min(4, len(all_options))
    
    # Generate all possible option combinations and calculate corresponding variable sets
    for r in range(1, max_combo_size + 1):
        print(f"Processing combinations of size {r}...")
        count = 0
        for combo in combinations(all_options, r):
            # Calculate variable ID set corresponding to this combination
            var_set = frozenset()
            for option in combo:
                var_set = var_set.union(option_to_vars[option])
            
            # Skip if variable set is empty
            if not var_set:
                continue
            
            # Add combination to corresponding variable set
            vars_to_combos[var_set].append(tuple(sorted(combo)))
            count += 1
        
        print(f"  Processed {count} combinations")
    
    print(f"Found {len(vars_to_combos)} different variable sets")
    
    # Find equivalent combinations
    equivalent_combinations = []
    
    for var_set, combos in vars_to_combos.items():
        if len(combos) > 1:  # Multiple combinations correspond to the same variable set
            # Check if these combinations have no overlapping options
            for i in range(len(combos)):
                for j in range(i + 1, len(combos)):
                    combo1 = set(combos[i])
                    combo2 = set(combos[j])
                    
                    # Check if two combinations have overlapping options
                    if not combo1.intersection(combo2):
                        equivalent_combinations.append((
                            combos[i],
                            combos[j],
                            var_set
                        ))
    
    # Generate equivalence sets
    equivalence_sets = generate_equivalence_sets(equivalent_combinations)
    
    return {
        'equivalence_sets': equivalence_sets,
        'pairs': equivalent_combinations
    }

def convert_non_serializable(obj):
    if isinstance(obj, (set, frozenset)):
        return list(obj)
    elif isinstance(obj, dict):
        return {k: convert_non_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_non_serializable(item) for item in obj]
    else:
        return obj

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process project option for a given CVE ID.")
    parser.add_argument("--cve", required=True, help="CVE ID to process (e.g., libtiff-736)")
    args = parser.parse_args()
    cve_id = args.cve
    with open(f"{PROJECT_ROOT_DIR}/{cve_id}/div_2_option.json", "r") as f:
        div_2_option = json.load(f)
    # Don't ignore any variables
    result = constraint_generation(div_2_option)
    result = convert_non_serializable(result)
    with open(f"{PROJECT_ROOT_DIR}/{cve_id}/constraint.json", "w") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)
    
    # Test ignore variables functionality
    # print(f"\nAfter ignoring variable '1':")
    # result_ignore = constraint_generation(div_2_option, ignore_vars=["1"])
    # print(f"Found {len(result_ignore['pairs'])} equivalent combination pairs, generated {len(result_ignore['equivalence_sets'])} equivalence relations")
    