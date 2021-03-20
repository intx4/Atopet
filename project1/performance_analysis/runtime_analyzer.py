import pandas as pd
import os
import numpy as np
import matplotlib.pyplot as plt

dir = os.getcwd()
paths = ['num_party_change', 'scalar_additions', 'scalar_multiplications', 'secrets_additions', 'secrets_multiplications']
target = 'runtime.csv'

for path in paths:
    file = pd.read_csv(dir+'/'+path+'/'+target, names=['num_parties', 'time'])
    means = file.groupby(['num_parties'], as_index=False).agg({'time': ['mean', 'sem']})
    means.columns = list(map(''.join, means.columns.values))

    x = np.array([], dtype=int)
    y = np.array([], dtype=float)
    e = np.array([], dtype=float)

    x = np.append(x, means['num_parties'])
    y = np.append(y, means['timemean'])
    e = np.append(e, means['timesem'])

    plt.errorbar(x, y, fmt='o')
    plt.savefig('plot_'+path+'_.png')
    plt.close()