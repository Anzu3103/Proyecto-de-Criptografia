# ============================= Criptografía ============================= # 
# Integrantes:
# 		Martínez Ostoa Néstor Iván 
# 		Meza Ortega Fernando
# 		Suxo Pacheco Elsa Guadalupe
# ======================================================================== #

import numpy as np
import pandas as pd
import os

# ======================================================================
#						Test vector generation
# ======================================================================
def generate_csv(tv_file_name, destination_path, verbose=False):
	lines = open(tv_file_name).readlines()
	msgs = []
	lengths = []
	for line in lines:
		if line[:3] == 'Msg': 
			cleaned_line = clean_str(line)
			msgs.append(cleaned_line)
			lengths.append(len(cleaned_line))
	df = pd.DataFrame({
		'length': lengths,
		'message': msgs
	})
	if verbose: print(df.head())
	df.to_csv(destination_path + 'signing_test_vectors.csv', index=False)

def clean_str(str_):
	return str_.split('=')[1].strip()

generate_csv('ECDSA_SigGen.txt', destination_path='./', verbose=True)


# ======================================================================
#						Algorithm evaluation
# ======================================================================
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, dsa, rsa, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

global sign_rsa
global sign_dsa
global sign_ec_1
global sign_ec_2

sign_rsa = []
sign_dsa = []
sign_ec_1 = []
sign_ec_2 = []


test_vectors_df = pd.read_csv('./signing_test_vectors.csv')
test_vectors_df.head()


def get_times(test_vector_messages, algorithm, hash_algorithm, args):
	times = []
	#Listas para guardar resultado de la firma de cada algoritmo
	#con su respectivo msj, llave e info
	
	#-----------------PRIVATE and PUBLIC KEY generation--------------------
	if algorithm == ec or algorithm == dsa:
		private_key = algorithm.generate_private_key(args['pk'])
	elif algorithm == rsa:
		private_key = algorithm.generate_private_key(
			args['public_exponent'], args['key_size']
		)
	public_key = private_key.public_key()

	#-----------------------------------------------------------
	
	for msg in test_vector_messages:
		data = str.encode(msg)
		#-----------------------------SIGNATURE---------------------------------
		start = time.time()
		if algorithm == ec:
			signature = private_key.sign(data, ec.ECDSA(hash_algorithm()))
		elif algorithm == dsa:
			signature = private_key.sign(data, hash_algorithm())
		elif algorithm == rsa:
			signature = private_key.sign(data, args['padding'],hash_algorithm())
		end = time.time()
		#-----------------------------------------------------------------------
		
		aux = [signature, data, public_key, hash_algorithm, args]
		if algorithm == ec:
			if isinstance(args['pk'],ec.SECP521R1):
				sign_ec_1.append(list(aux))
			elif isinstance(args['pk'],ec.SECT571K1):
				sign_ec_2.append(list(aux))
		elif algorithm == dsa:
			sign_dsa.append(list(aux))
		elif algorithm == rsa:
			sign_rsa.append(list(aux))
		
		times.append(end-start)

	return times

def get_all_times(test_vectors_messages, algo, hash_algo, args, num_iter=10, verbose=False):
	algo_name = str(algo).split('.')[4].upper()[:4]
	if verbose: print(f'------------------------\nProcessing {algo_name}')
	all_times = []
	if verbose: print(f'\t\tIteration #: ', end='')
	for i in range(num_iter):
		if verbose: print(f'{i+1}  ', end='\n' if i == num_iter-1 else '')
		times = get_times(test_vectors_messages, algo, hash_algo, args)
		all_times.append(times)

	return np.array(all_times)

def get_times_matrix_for_hash(test_vector, hash_algorithm, num_iter=10, verbose=False):
	times_matrix = []

	algorithms = [rsa, dsa, ec, ec] # we repeat 'ec' since we need to use two curves

	ec_521_args = {'pk': ec.SECP521R1()}
	ec_571_args = {'pk': ec.SECT571K1()}
	dsa_args = {'pk': 1024}
	rsa_args = {
		'public_exponent':65537,
		'key_size':1024,
		'padding': padding.PSS(mgf=padding.MGF1(hash_algorithm()), salt_length=padding.PSS.MAX_LENGTH)
	}
	algo_args = [rsa_args, dsa_args, ec_521_args, ec_571_args]
	
	for idx, algo in enumerate(algorithms):
		all_times = get_all_times(
			test_vectors_messages=test_vector, algo=algo, hash_algo=hash_algorithm,
			args=algo_args[idx], num_iter=num_iter, verbose=verbose
		)

		times_matrix.append(np.mean(all_times, axis=0))

	return times_matrix


import time
num_iter = 10
print("\n\t\t- - Operation: Signing - - ")

sha512_times_matrix = get_times_matrix_for_hash(test_vectors_df['message'], hashes.SHA512, num_iter, verbose=True)
sha256_times_matrix = get_times_matrix_for_hash(test_vectors_df['message'], hashes.SHA256, num_iter)

print(f'Number of time vectors: {len(sha512_times_matrix)}')
for idx, time in enumerate(sha512_times_matrix):
	print(f'Time vector #{idx +1} of length: {len(sha512_times_matrix[idx])}')

# ======================================================================
#						Graphs - Signing
# ======================================================================
import plotly.graph_objects as go

def get_color_for_idx(idx):
	colors = ["#118ab2", "#ffd166", "#06d6a0", "#ef476f"]
	return colors[idx]

def graph_times(times_matrix, hash_algorithm, dark=False, sign=True):
	fig = go.Figure()
	for idx, time in enumerate(times_matrix):
		if idx == 0: 
			algo_label = 'RSA'
			test_vector_label = 'PSS padding'
		elif idx == 1:
			algo_label = 'DSA'
			test_vector_label = '1024'
		elif idx == 2:
			algo_label = 'ECDSA'
			test_vector_label = 'SECT521R1'
		elif idx == 3:
			algo_label = 'ECDSA'
			test_vector_label = 'SECT571K1'

		fig.add_trace(go.Scatter(
			x=np.arange(len(time)),
			y=time,
			name=algo_label + ' - ' + test_vector_label,
			line=dict(color=get_color_for_idx(idx)),
			mode='lines'
		))
		fig.update_layout(
			title=dict(
					text=f'<b>Comparison of DSA vs. ECDSA vs. RSA for signature</b><br>for messages of length 256 using {hash_algorithm}' 
					if sign else
					f'<b>Comparison of DSA vs. ECDSA vs. RSA for verify</b><br>for messages of length 256 using {hash_algorithm}'

			), 
			template='plotly_dark' if dark else 'plotly_white',
			xaxis_title='Number of messages',
			yaxis_title='Time in seconds'
		)
	fig.show()

dark_mode = False

graph_times(sha512_times_matrix, hash_algorithm='SHA512', dark=dark_mode, sign=True)
graph_times(sha256_times_matrix, hash_algorithm='SHA256', dark=dark_mode, sign=True)

def get_info_from_time_matrix(time_matrix, hash, sign = True):
	if sign:
		print(f'\n-------- Signing - Info for hash: {hash}--------')
	else:
		print(f'\n-------- Verifying - Info for hash: {hash}--------')

	for time in time_matrix:
		print(np.mean(time))

get_info_from_time_matrix(sha512_times_matrix, hash='SHA512')
get_info_from_time_matrix(sha256_times_matrix, hash='SHA256')


# ======================================================================
#						Verificación
# ======================================================================

import time

def Verificacion_RSA_PSS(signature,message, pubkey, hash_algorithm, args):
	start = time.time()
	pubkey.verify(signature, message, args['padding'],hash_algorithm())
	end = time.time()

	return (end-start)

def Verificacion_DSA(signature,message, pubkey, hash_algorithm):
	start = time.time()
	pubkey.verify(signature, message, hash_algorithm())
	end = time.time()
	return (end-start)

def Verificacion_ECDSA(signature,message, pubkey, hash_algorithm):
	start = time.time()
	pubkey.verify(signature, message, ec.ECDSA(hash_algorithm()))
	end = time.time()
	return (end-start)

def get_times_for_hash_ver(sign_sha, num_iter = 10, verbose = False):
	total = []
	for idx, algorithm in enumerate(sign_sha):
		time_ver = []
		if verbose and idx==0: print(f'------------------------\nProcessing RSA')
		elif verbose and idx==1: print(f'------------------------\nProcessing DSA')
		elif verbose and (idx==2 or idx==3): print(f'------------------------\nProcessing EC')

		for data in algorithm:
			if idx == 0: #RSA
				temp = Verificacion_RSA_PSS(data[0],data[1],data[2],data[3],data[4])
			elif idx == 1: #DSA
				temp = Verificacion_DSA(data[0],data[1],data[2],data[3])
			elif idx == 2: #EC 1
				temp = Verificacion_ECDSA(data[0],data[1],data[2],data[3])
			elif idx == 3: #EC 2
				temp = Verificacion_ECDSA(data[0],data[1],data[2],data[3])
			time_ver.append(temp)	
				
		aux = np.array(list(time_ver))
		aux = np.array_split(aux,num_iter)
		aux = np.mean(aux, axis = 0)
		total.append(np.copy(aux))

	return list(total)

# --------------------- Ajuste de valores ----------------------------

sign_sha512 = []
sign_sha256 = []


sign_sha512.append(sign_rsa[:(len(sign_rsa)//2)])
sign_sha256.append(sign_rsa[(len(sign_rsa)//2):])

sign_sha512.append(sign_dsa[:(len(sign_dsa)//2)])
sign_sha256.append(sign_dsa[(len(sign_dsa)//2):])

sign_sha512.append(sign_ec_1[:(len(sign_ec_1)//2)])
sign_sha256.append(sign_ec_1[(len(sign_ec_1)//2):])

sign_sha512.append(sign_ec_2[:(len(sign_ec_2)//2)])
sign_sha256.append(sign_ec_2[(len(sign_ec_2)//2):])

ver_sha512 = []	
ver_sha256 = []	

print("\n\t\t- - Operation: Verifying - - ")

ver_sha512 = get_times_for_hash_ver(sign_sha512, num_iter=10, verbose=True)
ver_sha256 = get_times_for_hash_ver(sign_sha256, num_iter=10)

# ======================================================================
#						Graphs - Verifying
# ======================================================================
dark_mode = False
graph_times(ver_sha512, hash_algorithm='SHA512', dark=dark_mode, sign=False)
graph_times(ver_sha256, hash_algorithm='SHA256', dark=dark_mode, sign=False)

get_info_from_time_matrix(ver_sha512, hash='SHA512', sign=False)
get_info_from_time_matrix(ver_sha256, hash='SHA256', sign=False)
