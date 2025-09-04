import json
import os
import re
import matplotlib.pyplot as plt

l = [2**i for i in range(13)]
sr = [256, 512, 1024]

dir = "./target/criterion/kzg-elgamal/"
folders = [name for name in os.listdir(dir) if os.path.isdir(os.path.join(dir, name))]

prove_pattern = re.compile(r"^proof-prove-l(\d+)-sr(\d+)-m(\d+)$")
verify_pattern = re.compile(r"^proof-verify-l(\d+)-sr(\d+)-m(\d+)$")
range_pattern = re.compile(r"^range-proof-l(\d+)-sr(\d+)-m(\d+)$")

def append_bench_data(folder_map):
    folder_name = folder_map['name']
    estimates_path = os.path.join(dir, folder_name, "base", "estimates.json")
    if os.path.exists(estimates_path):
        with open(estimates_path, "r") as f:
            try:
                estimates = json.load(f)
                # Only keep the 'point_estimate' in the 'median'
                folder_map['bench'] = estimates.get('median', {}).get('point_estimate') / 1000000
            except Exception as e:
                print(f"Failed to load {estimates_path}: {e}")

prove_folders = []
verify_folders = []
range_folders = []

for folder in folders:
    m = prove_pattern.match(folder)
    if m:
        A, B, C = map(int, m.groups())
        entry = {'name': folder, 'l': A, 'sr': B, 'm': C}
        append_bench_data(entry)
        prove_folders.append(entry)
        continue
    m = verify_pattern.match(folder)
    if m:
        A, B, C = map(int, m.groups())
        entry = {'name': folder, 'l': A, 'sr': B, 'm': C}
        append_bench_data(entry)
        verify_folders.append(entry)
        continue
    m = range_pattern.match(folder)
    if m:
        A, B, C = map(int, m.groups())
        entry = {'name': folder, 'l': A, 'sr': B, 'm': C}
        append_bench_data(entry)
        range_folders.append(entry)

# print("Prove folders:", prove_folders)
# print("Verify folders:", verify_folders)
# print("Range folders:", range_folders)

# sr_value in [256, 512, 1024]
def filter_by_sr(entries, sr_value):
    sr_common = [2, 3, 5, 9, 17, 33, 65, 129]
    sr_values = [sr_value] * (12 - len(sr_common))
    sr_values.extend(sr_common)
    return [entry for entry in entries if entry['sr'] in sr_values]

plt.figure(figsize=(8, 6))
sr_values = [256, 512, 1024]

for sr in sr_values:
    sr_entries = filter_by_sr(prove_folders, sr)
    sr_entries_sorted = sorted(sr_entries, key=lambda x: x['l'])
    x = [entry['l'] for entry in sr_entries_sorted]
    y = [entry['bench'] for entry in sr_entries_sorted]
    plt.plot(x, y, marker='o', label=f'prove-sr={sr}')

for sr in sr_values:
    sr_entries = filter_by_sr(verify_folders, sr)
    sr_entries_sorted = sorted(sr_entries, key=lambda x: x['l'])
    x = [entry['l'] for entry in sr_entries_sorted]
    y = [entry['bench'] for entry in sr_entries_sorted]
    plt.plot(x, y, marker='p', label=f'verify-sr={sr}')

for sr in sr_values:
    sr_entries = filter_by_sr(range_folders, sr)
    sr_entries_sorted = sorted(sr_entries, key=lambda x: x['l'])
    x = [entry['l'] for entry in sr_entries_sorted]
    y = [entry['bench'] for entry in sr_entries_sorted]
    print(f"Rangeproof sr={sr}: {y}")
    plt.plot(x, y, marker='s', label=f'rangeproof-sr={sr}')
    

plt.xlabel('l')
plt.ylabel('Time (ms)')
plt.title('Proof Benchmarks for sr=256, 512, 1024')
plt.legend()
plt.xscale('log', base=2)
plt.yscale('log', base=10)
plt.grid(True, which='both', ls='--')
plt.tight_layout()
plt.show()
