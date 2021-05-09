import pandas as pd
import os
import numpy as np
import matplotlib.pyplot as plt

dir = os.getcwd()
paths = ['keygen', 'issuance', 'showing', 'verification']
target = '_runtime.csv'

for path in paths:
	file = pd.read_csv(dir + '/' + path + target, names=['num_subscriptions', 'runtime'])
	gr = file.groupby(['num_subscriptions'], as_index=False)
	
	mean = gr.mean()['runtime']
	var = gr.var()['runtime']
	sem = gr.sem()['runtime']
	
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
	
	fig, ax1 = plt.subplots(1, constrained_layout=True)
	ax1.set(ylabel='avg runtime in seconds')
	ax1.set(title='Computational cost '+ path)
	ax1.errorbar(x, m, yerr=e, fmt='--o', color='blue', ecolor='lightgray', elinewidth=3)
	plt.savefig('runtime_' + path + '.png')