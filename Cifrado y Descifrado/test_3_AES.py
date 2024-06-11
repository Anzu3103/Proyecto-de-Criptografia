# ============================= Criptografía ============================= # 
# Integrantes:
# 		Martínez Ostoa Néstor Iván 
# 		Meza Ortega Fernando
# 		Suxo Pacheco Elsa Guadalupe
# ======================================================================== #

import secrets
import time
import statistics
import numpy as np
import plotly.graph_objects as go

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as padding_asim
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


# ========================================================================
# 		Algoritmos de cifrado simétrico y asimétrico (AES)
# ========================================================================

def Cifrado_AES_256(mensaje, cifradorAES):
	return cifradorAES.update(mensaje)

def Descifrado_AES_256(mensaje, descifradorAES):
	return descifradorAES.update(mensaje)


def context_generation():
	"""
	Se utilizará las mismas llaves tanto pára AES y el mismo Vector
	de inicializacion para AES-CBC porque nos interesa probar la eficiencia del cifrado
	y descifrado y la generación de llaves se excluye en este proyecto. 
	"""
	llave_AES = secrets.token_bytes(32)
	vi = secrets.token_bytes(16)

	#Para no estar creando el contexto cada vez que se quiere cifrar
	cifradorECB = Cipher(algorithms.AES(llave_AES), modes.ECB()).encryptor()
	cifradorCBC = Cipher(algorithms.AES(llave_AES), modes.CBC(vi)).encryptor()
	descifradorECB = Cipher(algorithms.AES(llave_AES), modes.ECB()).decryptor()
	descifradorCBC = Cipher(algorithms.AES(llave_AES), modes.CBC(vi)).decryptor()


	return cifradorECB, cifradorCBC, descifradorECB, descifradorCBC

# ----------------------- Creacion de contexto ------------------------- #

cifradorECB, cifradorCBC, descifradorECB, descifradorCBC = context_generation()

# ------------------- Creación de vectores de prueba ------------------- #
arr_msg = []
for i in range(0, 16385, 256): # Creando msj de n bytes
	msgs = []
	for j in range(300): #Cambiar msj de n bytes j veces
		message = secrets.token_bytes(i)
		msgs.append(message)
	arr_msg.append(list(msgs))

# ------------- Toma de tiempo para Cifrado AES - ECB ----------------- #

arr_enc_ecb = [] #msjs cifrados
av_enc_ecb = []

print("Cifrando msjs con AES - 256 ECB ...")

for msg_type in arr_msg: 
	cipher = []
	times = []
	for message in msg_type:
		start = time.time()
		ciphertext = Cifrado_AES_256(message, cifradorECB)
		end = time.time()
		cipher.append(ciphertext) #guardando texto cifrado
		times.append(end-start)
	average = statistics.mean(list(times))
	av_enc_ecb.append(average)		
	arr_enc_ecb.append(list(cipher))

# ------------ Toma de tiempo para Descifrado AES - ECB --------------- #
av_dec_ecb = []
arr_dec_ecb = [] #msjs descifrados

print("Descifrando msjs con AES - 256 ECB ...\n")

for msg_type in arr_enc_ecb:
	plain = []
	times = [] 
	for i in range(len(msg_type)):
		ciphertext_raw = msg_type[i]
		start = time.time()
		plaintext = Descifrado_AES_256(ciphertext_raw, descifradorECB)
		end = time.time()
		plain.append(plaintext) #guardando texto en claro
		times.append(end-start)
	average = statistics.mean(list(times))
	av_dec_ecb.append(average)		
	arr_dec_ecb.append(list(plain))

# ------------- Toma de tiempo para Cifrado AES - CBC ----------------- #
arr_enc_cbc = [] #msjs cifrados
av_enc_cbc = []

print("Cifrando msjs con AES - 256 CBC ...")

for msg_type in arr_msg: 
	cipher = []
	times = []
	for message in msg_type:
		start = time.time()
		ciphertext = Cifrado_AES_256(message, cifradorCBC)
		end = time.time()
		cipher.append(ciphertext) #guardando texto cifrado
		times.append(end-start)
	average = statistics.mean(list(times))
	av_enc_cbc.append(average)		
	arr_enc_cbc.append(list(cipher))

# ------------ Toma de tiempo para Descifrado AES - CBC --------------- #
av_dec_cbc = []
arr_dec_cbc = [] #msjs descifrados

print("Descifrando msjs con AES - 256 CBC ...\n")

for msg_type in arr_enc_cbc:
	plain = []
	times = [] 
	for i in range(len(msg_type)):
		ciphertext_raw = msg_type[i]
		start = time.time()
		plaintext = Descifrado_AES_256(ciphertext_raw, descifradorCBC)
		end = time.time()
		plain.append(plaintext) #guardando texto en claro
		times.append(end-start)
	average = statistics.mean(list(times))
	av_dec_cbc.append(average)		
	arr_dec_cbc.append(list(plain))

encrypt_times_matrix = np.array([av_enc_ecb,av_enc_cbc])
decrypt_times_matrix = np.array([av_dec_ecb,av_dec_cbc])


# ======================================================================
#						Graficas
# ======================================================================

def get_color_for_idx(idx):
	colors = ["#06d6a0", "#ef476f"]
	return colors[idx]

def graph_times(times_matrix, dark=False, enc=True):
	fig = go.Figure()
	for idx, time in enumerate(times_matrix):
		if idx == 0:
			algo_label = 'AES 256'
			test_vector_label = 'ECB'
		elif idx == 1:
			algo_label = 'AES 256'
			test_vector_label = 'CBC'

		fig.add_trace(go.Scatter(
			x=np.arange(len(time)),
			y=time,
			name=algo_label + ' - ' + test_vector_label,
			line=dict(color=get_color_for_idx(idx)),
			mode='lines'
		))
		fig.update_layout(
			title=dict(
					text=f'<b>Comparison of AES ECB vs. AES CBC for encryption</b><br>for messages of length 0 - 16384 bytes' 
					if enc else
					f'<b>Comparison of AES ECB vs. AES CBC for decryption</b><br>for messages of length 0 - 16384 bytes'

			), 
			template='plotly_dark' if dark else 'plotly_white',
			xaxis_title='Length of messages',
			yaxis_title='Time in seconds'
		)
	fig.show()

dark_mode = False

graph_times(encrypt_times_matrix, dark=dark_mode, enc=True)
graph_times(decrypt_times_matrix, dark=dark_mode, enc=False)

def get_info_from_time_matrix(time_matrix, enc = True):
	if enc:
		print(f'\n-------- Encryption --------')
	else:
		print(f'\n-------- Decryption --------')

	for time in time_matrix:
		print(np.mean(time))

get_info_from_time_matrix(encrypt_times_matrix)
get_info_from_time_matrix(decrypt_times_matrix, enc=False)
