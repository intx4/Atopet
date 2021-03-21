import pandas as pd
import os
import numpy as np
import matplotlib.pyplot as plt

dir = os.getcwd()
paths = ['num_party_change', 'scalar_additions', 'scalar_multiplications', 'secrets_additions', 'secrets_multiplications']
vars = ['parties', 'scalar_adds', 'scalar_muls', 'secrets_adds', 'secrets_mul']
target = 'runtime.csv'

for path, var in zip(paths, vars):
    file = pd.read_csv(dir+'/'+path+'/'+target, names=['num_parties', 'time'])
    means = file.groupby(['num_parties'], as_index=False).agg({'time': ['mean', 'sem', 'var']}).reset_index()
    means.columns = list(map(''.join, means.columns.values))

    x = np.array([], dtype=int)
    m = np.array([], dtype=float)
    v = np.array([], dtype=float)
    e = np.array([], dtype=float)

    x = np.append(x, means['num_parties'])
    m = np.append(m, means['timemean'])
    e = np.append(e, means['timesem'])
    v = np.append(v, means['timevar'])

    fig, axs = plt.subplots(2)
    axs[0].set_title('Mean with std. error')
    axs[0].set(ylabel='avg runtime')
    axs[0].errorbar(x, m, yerr=e, fmt='--o', color='red', ecolor='lightgray', elinewidth=3)
    axs[1].set(xlabel=var, ylabel='variance')
    axs[1].plot(x, v, 'o', color='g')
    axs[1].set_title('Variance')
    for ax in fig.get_axes():
        ax.label_outer()
    plt.savefig('runtime_'+path+'_.png')
