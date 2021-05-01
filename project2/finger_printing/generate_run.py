import itertools
values = ['-T restaurant', '-T bar', '-T dojo']
f = open('run_commands.txt', 'w+')
for i in range(1, 4):
    for s in itertools.combinations(values, i):
        joined = ' '.join(s)
        v = f" python3 client.py grid @ {joined} -t\n"
        f.write(v)
f.close()
