import pandas as pd
import os
import numpy as np
import matplotlib.pyplot as plt

dir = os.getcwd()
paths = ['keygen', 'issuance', 'showing']
target = '_data.csv'

for path in paths:
    if path == 'issuance':
        file = pd.read_csv(dir + '/' + path + target, names=['num_subscriptions', 'request_bytes', 'signature_bytes'])
        gr = file.groupby(['num_subscriptions'], as_index=False)

        mean_r = gr.mean()['request_bytes']
        var_r = gr.var()['request_bytes']
        sem_r = gr.sem()['request_bytes']

        mean_s = gr.mean()['signature_bytes']
        var_s = gr.var()['signature_bytes']
        sem_s = gr.sem()['signature_bytes']

        x = np.array([], dtype=int)
        m_r = np.array([], dtype=float)
        v_r = np.array([], dtype=float)
        e_r = np.array([], dtype=float)

        m_r = np.append(m_r, mean_r)
        e_r = np.append(e_r, sem_r)
        v_r = np.append(v_r, var_r)
        
        for row in file.itertuples(index=False):
            n = row[0]
            if n not in x:
                x = np.append(x, n)
        m_s = np.array([], dtype=float)
        v_s = np.array([], dtype=float)
        e_s = np.array([], dtype=float)
        
        m_s = np.append(m_s, mean_s)
        e_s = np.append(e_s, sem_s)
        v_s = np.append(v_s, var_s)
        
        fig, ((ax1,ax2),(ax3, ax4)) = plt.subplots(2,2, constrained_layout=True)
        ax1.set(ylabel='avg dataflow in bytes')
        ax1.set(title='Client - Issuance step')
        ax1.errorbar(x, m_r, yerr=e_r, fmt='--o', color='blue', ecolor='lightgray', elinewidth=3)
        ax2.set(ylabel='avg dataflow in bytes')
        ax2.set(title='Server - Issuance step')
        ax2.errorbar(x, m_s, yerr=e_s, fmt='--o', color='red', ecolor='lightgray', elinewidth=3)
        ax3.set(xlabel='num_subs', ylabel='variance')
        ax3.plot(x, v_r, 'o', color='green')
        ax4.set(xlabel='num_subs', ylabel='variance')
        ax4.plot(x, v_s, 'o', color='pink')
        plt.savefig('dataflow_' + path + '.png')
    else:
        file = pd.read_csv(dir + '/' + path + target, names=['num_subscriptions', 'sent_bytes'])
        gr = file.groupby(['num_subscriptions'], as_index=False)
    
        mean = gr.mean()['sent_bytes']
        var = gr.var()['sent_bytes']
        sem = gr.sem()['sent_bytes']

        x = np.array([], dtype=int)
        m = np.array([], dtype=float)
        v = np.array([], dtype=float)
        e = np.array([], dtype=float)

        for row in file.itertuples(index=False):
            n = row[0]
            if n not in x:
                x = np.append(x, n)

        m = np.append(m, mean)
        e = np.append(e, sem)
        v = np.append(v, var)

        fig, (ax1, ax2) = plt.subplots(2, constrained_layout=True)
        ax1.set(ylabel='avg dataflow in bytes')
        ax1.set(title='Communication cost '+ path)
        ax1.errorbar(x, m, yerr=e, fmt='--o', color='blue', ecolor='lightgray', elinewidth=3)
        ax2.set(xlabel='x', ylabel='variance')
        ax2.plot(x, v, 'o', color='green')
        plt.savefig('dataflow_' + path + '.png')