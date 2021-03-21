import pandas as pd
import os
import numpy as np
import matplotlib.pyplot as plt

dir = os.getcwd()
paths = ['num_party_change', 'scalar_additions', 'scalar_multiplications', 'secrets_additions', 'secrets_multiplications']
vars = ['parties', 'scalar_adds', 'scalar_muls', 'secrets_adds', 'secrets_mul']
target = 'dataflow.csv'

for path, var in zip(paths, vars):
    file = pd.read_csv(dir+'/'+path+'/'+target, names=['num_parties', 'B_in', 'B_out'])
    gr = file.groupby(['num_parties'], as_index=False)

    mean_in = gr.mean()['B_in']
    var_in = gr.var()['B_in']
    sem_in = gr.sem()['B_in']

    mean_out = gr.mean()['B_out']
    var_out = gr.var()['B_out']
    sem_out = gr.sem()['B_out']

    x = np.array([], dtype=int)
    m_in = np.array([], dtype=float)
    v_in = np.array([], dtype=float)
    e_in = np.array([], dtype=float)

    for row in file.itertuples(index=False):
        n = row[0]
        if n not in x:
            x = np.append(x, n)

    m_in = np.append(m_in, mean_in)
    e_in = np.append(e_in, sem_in)
    v_in = np.append(v_in, var_in)

    m_out = np.array([], dtype=float)
    v_out = np.array([], dtype=float)
    e_out = np.array([], dtype=float)

    m_out = np.append(m_out, mean_out)
    e_out = np.append(e_out, sem_out)
    v_out = np.append(v_out, var_out)

    fig,((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2)

    ax1.set(ylabel='avg dataflow')
    ax1.errorbar(x, m_in, yerr=e_in, fmt='--o', color='blue', ecolor='lightgray', elinewidth=3)
    ax2.errorbar(x, m_out, yerr=e_out, fmt='--o', color='orange', ecolor='lightgray', elinewidth=3)
    ax3.set(xlabel=var, ylabel='variance')
    ax3.plot(x, v_in, 'o', color='green')
    ax4.set(xlabel=var)
    ax4.plot(x, v_out, 'o', color='red')
    for ax in fig.get_axes():
        ax.label_outer()
    plt.savefig('dataflow_'+path+'_.png')