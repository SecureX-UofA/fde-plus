import json
import os
import re
import matplotlib.pyplot as plt

l = [2**i for i in range(13)]
sr = [256, 512, 1024]

dir = "./target/criterion/kzg-elgamal/"
folders = [name for name in os.listdir(dir) if os.path.isdir(os.path.join(dir, name))]

suffix = "l(\d+)-m(\d+)-rsr(\d+)-sr(\d+)"
enc_patter = re.compile(r"^proof-encryption-" + suffix + "$")
prove_pattern = re.compile(r"^proof-prove-" + suffix + "$")
verify_pattern = re.compile(r"^proof-verify-" + suffix + "$")
range_pattern = re.compile(r"^range-proof-" + suffix + "$")

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

enc_by_sr = {}
prove_by_sr = {}
verify_by_sr = {}
range_by_sr = {}

for folder in folders:
    m = enc_patter.match(folder)
    if m:
        A, B, C, D = map(int, m.groups())
        entry = {'name': folder, 'l': A, 'm': B, 'rsr': C, 'sr': D}
        append_bench_data(entry)
        sr_val = entry['sr']
        if sr_val not in enc_by_sr:
            enc_by_sr[sr_val] = []
        enc_by_sr[sr_val].append(entry)
        continue
    m = prove_pattern.match(folder)
    if m:
        A, B, C, D = map(int, m.groups())
        entry = {'name': folder, 'l': A, 'm': B, 'rsr': C, 'sr': D}
        append_bench_data(entry)
        sr_val = entry['sr']
        if sr_val not in prove_by_sr:
            prove_by_sr[sr_val] = []
        prove_by_sr[sr_val].append(entry)
        continue
    m = verify_pattern.match(folder)
    if m:
        A, B, C, D = map(int, m.groups())
        entry = {'name': folder, 'l': A, 'm': B, 'rsr': C, 'sr': D}
        append_bench_data(entry)
        sr_val = entry['sr']
        if sr_val not in verify_by_sr:
            verify_by_sr[sr_val] = []
        verify_by_sr[sr_val].append(entry)
        continue
    m = range_pattern.match(folder)
    if m:
        A, B, C, D = map(int, m.groups())
        entry = {'name': folder, 'l': A, 'm': B, 'rsr': C, 'sr': D}
        append_bench_data(entry)
        sr_val = entry['sr']
        if sr_val not in range_by_sr:
            range_by_sr[sr_val] = []
        range_by_sr[sr_val].append(entry)
        continue

plt.figure(figsize=(8, 6))
sr_values = [256, 512, 1024]

# for sr in sr_values:
#     entries = enc_by_sr.get(sr, [])
#     entries_sorted = sorted(entries, key=lambda x: x['l'])
#     x = [entry['l'] for entry in entries_sorted]
#     y = [entry['bench'] for entry in entries_sorted]
#     plt.plot(x, y, marker='o', label=f'enc-sr={sr}')

# for sr in sr_values:
#     entries = prove_by_sr.get(sr, [])
#     entries_sorted = sorted(entries, key=lambda x: x['l'])
#     x = [entry['l'] for entry in entries_sorted]
#     y = [entry['bench'] for entry in entries_sorted]
#     plt.plot(x, y, marker='p', label=f'Prover (R={sr})')

# for sr in sr_values:
#     entries = range_by_sr.get(sr, [])
#     entries_sorted = sorted(entries, key=lambda x: x['l'])
#     x = [entry['l'] for entry in entries_sorted]
#     y = [entry['bench'] for entry in entries_sorted]
#     plt.plot(x, y, marker='^', label=f'Rangeproof (R={sr})')

for sr in sr_values:
    entries = verify_by_sr.get(sr, [])
    entries_sorted = sorted(entries, key=lambda x: x['l'])
    x = [entry['l'] for entry in entries_sorted]
    y = [entry['bench'] for entry in entries_sorted]
    plt.plot(x, y, marker='s', label=f'Verifier (R={sr})')

for sr in sr_values:
    prv_entries = prove_by_sr.get(sr, [])
    prv_entries_sorted = sorted(prv_entries, key=lambda x: x['l'])
    rp_entries = range_by_sr.get(sr, [])
    rp_entries_sorted = sorted(rp_entries, key=lambda x: x['l'])
    x = [entry['l'] for entry in prv_entries_sorted]
    y = [e1['bench'] + e2['bench'] for e1, e2 in zip(prv_entries_sorted, rp_entries_sorted)]
    plt.plot(x, y, marker='^', label=f'Prover (R={sr})')

plt.xlabel('Data size (#BLS12-381 field element)')
plt.ylabel('Time (ms)')
plt.title('Proof Benchmarks for sr=256, 512, 1024')
plt.legend()
plt.xscale('log', base=2)
plt.yscale('log', base=10)
plt.grid(True, which='both', ls='--')
plt.tight_layout()
plt.show()
