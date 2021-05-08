import itertools
values = ['-T restaurant', '-T bar', '-T dojo', '-T cloth', '-T parks']
f = open('run_commands.txt', 'w+')
for i in range(1, 5):
    for s in itertools.combinations(values, i):
        joined = ' '.join(s)
        v = f" python3 client.py grid @ {joined} -t\n"
        f.write(v)
f.close()
#-S restaurant' -S 'bar' -S 'dojo' -S 'cloth' -S 'parks'
