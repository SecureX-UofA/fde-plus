import matplotlib.pyplot as plt

x_entries = [1, 8, 16, 32]
prove_entries = [
    [53850, 7424, 5780, 4314],
    [97974, 13397, 9956, 8051],
    [186305, 25589, 18902, 15127],
]
verify_entries = [
    [59, 10, 9.22, 10.69],
    [105.94, 20.65, 13.73, 14.9],
    [222.21, 34.84, 27.21, 19.53]
]

plt.figure(figsize=(8, 6))
sr_values = [256, 512, 1024]

i = 0
for sr in sr_values:
    plt.plot(x_entries, prove_entries[i], marker='s', label=f'Prover (R={sr})')
    i += 1

i = 0
for sr in sr_values:
    y = []
    plt.plot(x_entries, verify_entries[i], marker='^', label=f'Verifier (R={sr})')
    i += 1

plt.xlabel('# CPU Cores')
plt.ylabel('Time (ms)')
plt.title('SNARK Benchmarks for sr=256, 512, 1024')
plt.legend()
# plt.xscale('log', base=2)
plt.xticks(x_entries)
plt.yscale('log', base=10)
plt.grid(True, which='both', ls='--')
plt.tight_layout()
plt.show()

# N = 256
# 1
# Compile: 2.165887439s (field bits=377)
# Setup:   17m7.449841329s
# 15:34:28 DBG constraint system solver done nbConstraints=1029847 took=632.689593
# 15:35:21 DBG prover done acceleration=none backend=groth16 curve=bw6_761 nbConstraints=1029847 took=53165.670532
# Prove:   53.850134413s
# 15:35:21 DBG verifier done backend=groth16 curve=bw6_761 took=59.369012
# Verify:  59.392339ms
# Constraints: 1029847
# OK: proof verified on BW6-761 with native BLS12-377 G1 arithmetic + MiMC(PRF) + range checks (< r_377).
# 8
# Compile: 2.474734554s (field bits=377)
# Setup:   2m16.621588115s
# 15:15:22 DBG constraint system solver done nbConstraints=1029847 took=173.313512
# 15:15:29 DBG prover done acceleration=none backend=groth16 curve=bw6_761 nbConstraints=1029847 took=7201.306717
# Prove:   7.424444814s
# 15:15:29 DBG verifier done backend=groth16 curve=bw6_761 took=10.028143
# Verify:  10.05207ms
# Constraints: 1029847
# OK: proof verified on BW6-761 with native BLS12-377 G1 arithmetic + MiMC(PRF) + range checks (< r_377).
# 16
# Compile: 2.775575752s (field bits=377)
# Setup:   1m38.494440924s
# 15:09:08 DBG constraint system solver done nbConstraints=1029847 took=179.674168
# 15:09:13 DBG prover done acceleration=none backend=groth16 curve=bw6_761 nbConstraints=1029847 took=5548.093415
# Prove:   5.780403218s
# 15:09:13 DBG verifier done backend=groth16 curve=bw6_761 took=9.193913
# Verify:  9.218438ms
# Constraints: 1029847
# OK: proof verified on BW6-761 with native BLS12-377 G1 arithmetic + MiMC(PRF) + range checks (< r_377).
# 32
# Compile: 2.806377957s (field bits=377)
# Setup:   1m18.753606837s
# 15:12:24 DBG constraint system solver done nbConstraints=1029847 took=166.628614
# 15:12:28 DBG prover done acceleration=none backend=groth16 curve=bw6_761 nbConstraints=1029847 took=4096.03573
# Prove:   4.314181248s
# 15:12:28 DBG verifier done backend=groth16 curve=bw6_761 took=10.654237
# Verify:  10.692461ms
# Constraints: 1029847
# OK: proof verified on BW6-761 with native BLS12-377 G1 arithmetic + MiMC(PRF) + range checks (< r_377).
# 512
# 1
# Compile: 4.514216394s (field bits=377)
# Setup:   34m11.240104983s
# 16:25:30 DBG constraint system solver done nbConstraints=2057687 took=1330.750231
# 16:27:07 DBG prover done acceleration=none backend=groth16 curve=bw6_761 nbConstraints=2057687 took=96541.395974
# Prove:   1m37.973837411s
# 16:27:07 DBG verifier done backend=groth16 curve=bw6_761 took=105.911956
# Verify:  105.937143ms
# Constraints: 2057687
# OK: proof verified on BW6-761 with native BLS12-377 G1 arithmetic + MiMC(PRF) + range checks (< r_377).
# 8
# Compile: 4.341735991s (field bits=377)
# Setup:   4m32.698567052s
# 16:33:24 DBG constraint system solver done nbConstraints=2057687 took=343.724902
# 16:33:37 DBG prover done acceleration=none backend=groth16 curve=bw6_761 nbConstraints=2057687 took=12954.639159
# Prove:   13.397166145s
# 16:33:37 DBG verifier done backend=groth16 curve=bw6_761 took=20.61682
# Verify:  20.648826ms
# Constraints: 2057687
# OK: proof verified on BW6-761 with native BLS12-377 G1 arithmetic + MiMC(PRF) + range checks (< r_377).
# 16
# Running with GOMAXPROCS=16 (NumCPU=32)
# 15:06:52 INF compiling circuit
# 15:06:52 INF parsed circuit inputs nbPublic=2564 nbSecret=513
# 15:06:57 INF building constraint builder nbConstraints=2057687
# Compile: 4.745172806s (field bits=377)
# Setup:   3m16.173061241s
# 15:10:13 DBG constraint system solver done nbConstraints=2057687 took=334.229476
# 15:10:23 DBG prover done acceleration=none backend=groth16 curve=bw6_761 nbConstraints=2057687 took=9522.747694
# Prove:   9.95626965s
# 15:10:23 DBG verifier done backend=groth16 curve=bw6_761 took=13.69848
# Verify:  13.726571ms
# Constraints: 2057687
# OK: proof verified on BW6-761 with native BLS12-377 G1 arithmetic + MiMC(PRF) + range checks (< r_377).
# 32
# Compile: 4.803264164s (field bits=377)
# Setup:   2m33.735314571s
# 15:13:49 DBG constraint system solver done nbConstraints=2057687 took=518.883512
# 15:13:57 DBG prover done acceleration=none backend=groth16 curve=bw6_761 nbConstraints=2057687 took=7432.701345
# Prove:   8.050962112s
# 15:13:57 DBG verifier done backend=groth16 curve=bw6_761 took=14.860675
# Verify:  14.907403ms
# Constraints: 2057687
# OK: proof verified on BW6-761 with native BLS12-377 G1 arithmetic + MiMC(PRF) + range checks (< r_377).
# 1024
# 1
# Compile: 9.804315136s (field bits=377)
# Setup:   1h8m11.03910762s
# 20:46:30 DBG constraint system solver done nbConstraints=4113367 took=3000.082784
# 20:49:34 DBG prover done acceleration=none backend=groth16 curve=bw6_761 nbConstraints=4113367 took=183102.705084
# Prove:   3m6.305215081s
# 20:49:34 DBG verifier done backend=groth16 curve=bw6_761 took=222.186477
# Verify:  222.213971ms
# Constraints: 4113367
# OK: proof verified on BW6-761 with native BLS12-377 G1 arithmetic + MiMC(PRF) + range checks (< r_377).
# 8
# Compile: 8.159906025s (field bits=377)
# Setup:   9m5.595974197s
# 21:18:23 DBG constraint system solver done nbConstraints=4113367 took=776.015507
# 21:18:47 DBG prover done acceleration=none backend=groth16 curve=bw6_761 nbConstraints=4113367 took=24615.455677
# Prove:   25.589297893s
# 21:18:47 DBG verifier done backend=groth16 curve=bw6_761 took=34.811057
# Verify:  34.843066ms
# Constraints: 4113367
# OK: proof verified on BW6-761 with native BLS12-377 G1 arithmetic + MiMC(PRF) + range checks (< r_377).
# 16
# Compile: 9.037782615s (field bits=377)
# Setup:   6m32.021484537s
# 15:22:22 DBG constraint system solver done nbConstraints=4113367 took=713.027942
# 15:22:40 DBG prover done acceleration=none backend=groth16 curve=bw6_761 nbConstraints=4113367 took=17991.02137
# Prove:   18.902309669s
# 15:22:40 DBG verifier done backend=groth16 curve=bw6_761 took=27.145153
# Verify:  27.206221ms
# Constraints: 4113367
# OK: proof verified on BW6-761 with native BLS12-377 G1 arithmetic + MiMC(PRF) + range checks (< r_377).
# 32
# Compile: 8.679149133s (field bits=377)
# Setup:   5m3.87681747s
# 15:31:22 DBG constraint system solver done nbConstraints=4113367 took=593.880974
# 15:31:37 DBG prover done acceleration=none backend=groth16 curve=bw6_761 nbConstraints=4113367 took=14326.373853
# Prove:   15.126562357s
# 15:31:37 DBG verifier done backend=groth16 curve=bw6_761 took=19.495225
# Verify:  19.531147ms
# Constraints: 4113367
# OK: proof verified on BW6-761 with native BLS12-377 G1 arithmetic + MiMC(PRF) + range checks (< r_377).