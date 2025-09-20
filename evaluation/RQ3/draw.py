import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import re
import sys
import argparse
from datetime import datetime, timedelta
import random
import time
import json
import os

plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'sans-serif']
plt.rcParams['axes.unicode_minus'] = False

def parse_distance_data(filename):
    data = []
    
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    min_distance = float('inf')
    cur = {}
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
            
        parts = line.split(', ')
        if len(parts) < 4:
            continue
            
        filename_part = parts[0].strip('"')
        distance = float(parts[1])
        total_distance = int(parts[2])
        total_count = int(parts[3])
        
        match = re.search(r'id:\d+,(\d+),', filename_part)
        if match:
            timestamp = int(match.group(1))  
        else:
            if 'orig:' in filename_part:
                timestamp = 0 
            else:
                continue 
        
        id_match = re.search(r'id:(\d+),', filename_part)
        if id_match:
            id = id_match.group(1)
        else:
            id = 'init'
        
        op_match = re.search(r'op:(\w+),', filename_part)
        if op_match:
            op = op_match.group(1)
        else:
            op = 'init'
        
        src_match = re.search(r'src:(\d+),', filename_part)
        if src_match:
            src = src_match.group(1)
        else:
            src = 'init'
        
        if distance < 100 or total_distance < total_count:
            continue
        
        if (min_distance > distance):
            cur = line
        
        min_distance = min(min_distance, distance)

        data.append({
            'id': id,
            'timestamp': timestamp,
            'distance': distance,
            'total_distance': total_distance,
            'total_count': total_count,
            'filename': filename_part,
            'opt': True if 'og' in op else False,
            'src': src
        })
    return data

def find_global_min_distance_by_time(data, time_interval=600000, max_hours=24):
    if not data:
        return [], [], []

    data.sort(key=lambda x: x['timestamp'])
    
    start_time = data[0]['timestamp']
    max_time_ms = max_hours * 60 * 60 * 1000  
    end_time = min(data[-1]['timestamp'], start_time + max_time_ms)
    
    data = [d for d in data if d['timestamp'] <= end_time]

    time_points = []
    global_min_distances = []
    global_min_data = []

    current_min_distance = float('inf')
    
    for data_point in data:
        timestamp = data_point['timestamp']
        distance = data_point['distance']
        
        if distance < current_min_distance:
            current_min_distance = distance
            time_points.append(timestamp)
            global_min_distances.append(current_min_distance)
            global_min_data.append(data_point)
    
    return time_points, global_min_distances, global_min_data

def optimize_plot_data(time_points, min_distances, max_points=200):
    if len(time_points) <= max_points:
        return time_points, min_distances
    
    step = len(time_points) // max_points
    
    optimized_times = time_points[::step]
    optimized_distances = min_distances[::step]

    if optimized_times[-1] != time_points[-1]:
        optimized_times.append(time_points[-1])
        optimized_distances.append(min_distances[-1])
    
    return optimized_times, optimized_distances

def extend_curve_to_length(times, distances, target_length_hours):
    if not times or not distances:
        return times, distances
    
    if times[-1] >= target_length_hours:
        return times, distances

    last_time = times[-1]
    last_distance = distances[-1]
    
    extended_times = times.copy()
    extended_distances = distances.copy()
    
    extended_times.append(target_length_hours)
    extended_distances.append(last_distance)
    
    return extended_times, extended_distances

def create_step_plot_data(times, distances):
    if not times or not distances or len(times) < 2:
        return times, distances
    
    step_times = []
    step_distances = []
    
    for i in range(len(times)):
        step_times.append(times[i])
        step_distances.append(distances[i])
        
        if i < len(times) - 1:
            step_times.append(times[i + 1])
            step_distances.append(distances[i])
            
            step_times.append(times[i + 1])
            step_distances.append(distances[i + 1])
    
    return step_times, step_distances

def create_custom_color_step_plot(times, distances, opt_flags, horizontal_color='black'):
    if not times or not distances or len(times) < 2:
        return
    
    for i in range(len(times) - 1):
        plt.plot([times[i], times[i + 1]], [distances[i], distances[i]], 
                color=horizontal_color, linewidth=6, alpha=0.8)
        
        if 0 <  i < len(opt_flags) and isinstance(opt_flags[i], dict) and 'opt' in opt_flags[i]:
            print(times[i], times[i + 1], distances[i], opt_flags[i]['opt'])
            if opt_flags[i]['opt']:
                vertical_color = '#4472C4'  
            else:
                vertical_color = '#C00000'
        
            plt.plot([times[i], times[i]], [distances[i - 1], distances[i]], 
                    color=vertical_color, linewidth=6, alpha=0.8)
    

def plot_quad_distance_evolution(time_points, global_min_distances, global_min_data,
                                time_points_opt_only, min_distances_opt_only, time_points_file_only, min_distances_file_only, 
                                output_file='distance_evolution_quad.png', title='Global Minimum Distance Evolution Over Time'):
    plt.rcParams['font.family'] = 'Times New Roman'
    plt.rcParams['font.serif'] = ['Times New Roman']
    
    import matplotlib.font_manager as fm
    try:
        fm._rebuild()
    except AttributeError:
        fm.fontManager.__init__()
    time_points_opt_only, min_distances_opt_only = optimize_plot_data(time_points_opt_only, min_distances_opt_only)
    time_points_file_only, min_distances_file_only = optimize_plot_data(time_points_file_only, min_distances_file_only)
    
    all_time_points = []
    if time_points: all_time_points.extend(time_points)
    if time_points_opt_only: all_time_points.extend(time_points_opt_only)
    if time_points_file_only: all_time_points.extend(time_points_file_only)
    
    if all_time_points:
        start_time = min(all_time_points)
        end_time = max(all_time_points)
        
        relative_times = [(t - start_time) / (1000.0 * 60 * 60) for t in time_points] if time_points else []
        relative_times_opt_only = [(t - start_time) / (1000.0 * 60 * 60) for t in time_points_opt_only] if time_points_opt_only else []
        relative_times_file_only = [(t - start_time) / (1000.0 * 60 * 60) for t in time_points_file_only] if time_points_file_only else []
        
        max_time_hours = (end_time - start_time) / (1000.0 * 60 * 60)
 
        if relative_times and global_min_distances:
            relative_times, global_min_distances = extend_curve_to_length(relative_times, global_min_distances, max_time_hours)
            if global_min_data:
                last_opt = global_min_data[-1]['opt'] if global_min_data else True
                extended_opt_flags = global_min_data + [{'opt': last_opt}]
            else:
                extended_opt_flags = [{'opt': True}] * len(relative_times)
        else:
            extended_opt_flags = []
            
        relative_times_opt_only, min_distances_opt_only = extend_curve_to_length(relative_times_opt_only, min_distances_opt_only, max_time_hours)
        relative_times_file_only, min_distances_file_only = extend_curve_to_length(relative_times_file_only, min_distances_file_only, max_time_hours)
        
        plt.figure(figsize=(14, 10))
        if relative_times and global_min_distances and extended_opt_flags:
            create_custom_color_step_plot(relative_times, global_min_distances, extended_opt_flags, horizontal_color='black')
        
        step_times_opt_only, step_distances_opt_only = create_step_plot_data(relative_times_opt_only, min_distances_opt_only)
        step_times_file_only, step_distances_file_only = create_step_plot_data(relative_times_file_only, min_distances_file_only)
        
        if step_times_opt_only and step_distances_opt_only:
            plt.plot(step_times_opt_only, step_distances_opt_only, '#4472C4', linewidth=4, alpha=0.8, linestyle='--', label='OI Queue(NFI)')
        
        if step_times_file_only and step_distances_file_only:
            plt.plot(step_times_file_only, step_distances_file_only, '#C00000', linewidth=4, alpha=0.8, linestyle='--', label='FI Queue(NOI)')
        
        
        font_size = 32
        from matplotlib.lines import Line2D
        legend_elements = [
            Line2D([0], [0], color='black', linewidth=2, label='(Minimum Distance)'),
            Line2D([0], [0], color='#4472C4', linewidth=2, label='OI(w/ FI)'),
            Line2D([0], [0], color='#C00000', linewidth=2, label='FI(w/ OI)'),
            Line2D([0], [0], color='#4472C4', linewidth=2, linestyle='--', label='OI(w/o FI)'),
            Line2D([0], [0], color='#C00000', linewidth=2, linestyle='--', label='FI(w/o OI)')
        ]
        
        plt.xlabel('Time (hours)', fontsize=font_size, fontfamily='Times New Roman', fontweight='bold')
        plt.ylabel('Minimum Distance of OI Queue & FI Queue', fontsize=font_size + 2, fontfamily='Times New Roman', fontweight='bold')
        plt.title(f'{title}\n', fontsize=font_size + 2, fontweight='bold', fontfamily='Times New Roman')
        plt.grid(True, alpha=0.3)
        
        plt.legend(handles=legend_elements, loc='upper right', 
                   prop={'family': 'Times New Roman', 'size': 22, 'weight': 'bold'}, 
                   frameon=True, fancybox=True, shadow=True, framealpha=0.9, 
                   markerscale=5.0, handlelength=5.0, handletextpad=0.1,
                   borderpad=0.5, columnspacing=0.8, labelspacing=0.3)  # Add custom legend
        
        # Set x-axis format
        plt.gca().xaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'{x:.1f}h'))
        
        plt.xticks(fontfamily='Times New Roman', fontsize=font_size, fontweight='bold')
        plt.yticks(fontfamily='Times New Roman', fontsize=font_size, fontweight='bold')
        
        plt.tight_layout()
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.show()
        
        print(f"Main data points: {len(relative_times)}")
        print(f"OI Queue(NFI) data points: {len(relative_times_opt_only)}")
        print(f"FI Queue(NOI) data points: {len(relative_times_file_only)}")
        
        # Calculate time range
        all_relative_times = []
        if relative_times: all_relative_times.extend(relative_times)
        if relative_times_opt_only: all_relative_times.extend(relative_times_opt_only)
        if relative_times_file_only: all_relative_times.extend(relative_times_file_only)
        
        if all_relative_times:
            print(f"Time range: {min(all_relative_times):.1f}h - {max(all_relative_times):.1f}h")

def trace_orig_descendants(data):
    orig_items = [d for d in data if d['timestamp'] == 0 and 'orig:' in d['filename']]
    
    
    traced_items = []
    
    for orig_item in orig_items:
        descendants = trace_single_orig(orig_item, data, traced_items)
        traced_items.extend(descendants)
    
    traced_items.extend(orig_items)
    seen_filenames = set()
    unique_traced_items = []
    for item in traced_items:
        if item['filename'] not in seen_filenames:
            seen_filenames.add(item['filename'])
            unique_traced_items.append(item)
    
    return unique_traced_items

def trace_single_orig(orig_item, data, already_traced):
    descendants = [orig_item]  
    orig_id = orig_item['id']
    
    direct_children = [d for d in data if d['src'] == orig_id and d['opt'] == False]
    
    for child in direct_children:
        if child not in already_traced: 
            descendants.append(child)
            child_descendants = trace_single_orig(child, data, already_traced + descendants)
            descendants.extend(child_descendants)
    
    return descendants

def find_only_opt_data(data):
    
    orig_items = [d['id'] for d in data if d['timestamp'] == 0 and 'orig:' in d['filename']]
    result = []
    
    for d in data:
        if d['src'] in orig_items and d['opt'] == True:
            result.append(d.copy())
    result.extend([d for d in data if d['timestamp'] == 0 and 'orig:' in d['filename']])
    return result

def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-j', '--json',  required=False, 
                       help='input json data file')
    parser.add_argument('-o', '--output', default='distance_evolution_quad.png', 
                       help='output image file path')
    parser.add_argument('-t', '--time-interval', type=int, default=600000,
                       help='time sampling interval, unit: milliseconds (default: 600000)')
    parser.add_argument('-m', '--max-hours', type=int, default=24,
                       help='maximum time range, unit: hours (default: 24)')
    parser.add_argument('--title', default='Global Minimum Distance Evolution Over Time',
                       help='chart title (default: Global Minimum Distance Evolution Over Time)')
    
    args = parser.parse_args()
    
    input_file = args.input_file
    output_file = args.output
    time_interval = args.time_interval
    max_hours = args.max_hours
    json_file = args.json
    title = args.title
    
    if json_file:
        with open(json_file, 'r') as f:
            data = json.load(f)
        global_min_data = data['GLOBAL_MIN_DISTANCES'].get('global_min_data', [])
        time_points = [d['timestamp'] for d in global_min_data]
        global_min_distances = [d['distance'] for d in global_min_data]
        time_points_opt_only = data['OI_QUEUE_ONLY']['time_points']
        min_distances_opt_only = data['OI_QUEUE_ONLY']['min_distances']
        time_points_file_only = data['FI_QUEUE_ONLY']['time_points']
        min_distances_file_only = data['FI_QUEUE_ONLY']['min_distances']
    
    if time_points or time_points_opt_only or time_points_file_only:
        plot_quad_distance_evolution(time_points, global_min_distances, global_min_data,
                                   time_points_opt_only, min_distances_opt_only, time_points_file_only, min_distances_file_only,
                                   output_file, title)
        
    else:
        print("No valid time point data found")

if __name__ == "__main__":
    main()