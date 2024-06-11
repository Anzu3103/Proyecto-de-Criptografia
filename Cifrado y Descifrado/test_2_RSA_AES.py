# ============================= Criptografía ============================= # 
# Integrantes:
# 		Martínez Ostoa Néstor Iván 
# 		Meza Ortega Fernando
# 		Suxo Pacheco Elsa Guadalupe
# ======================================================================== #

import time
import secrets
import statistics
import numpy as np
import plotly.graph_objects as go


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as padding_asim
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


# ======================================================================
#						Lectura de vectores de prueba
# ======================================================================
mensajes=[]
try:
	f=open("Test_vectors.txt","r")
	linea=f.readline() #Se lee la primera linea con datos
	while linea != "": #buscando linea
		linea=linea.replace('\n','') #Quita el salto de linea 
		mensajes.append(bytes.fromhex(linea))
		linea=f.readline()#Se lee la sig.linea que contiene los datos
	f.close()
except IOError:
	print ("Error al leer el archivo. Posible archivo inexistente.")
except :
	print ("Error inesperado al leer el archivo.")

print("Vectores de prueba cargados")

# ========================================================================
# 		Generación de llave pública y privada para RSA y secreto para AES
# ========================================================================
def Generar_llavePub(exp, modulus):
	size = 1024
	public_exponent=int(format(exp), 16)
	rsa_modulus = int(modulus, 16)
	pubkey = rsa.RSAPublicNumbers(public_exponent, rsa_modulus).public_key(default_backend())
	return pubkey

def Generar_llavePriv(llave_pub,d,p,q,dp,dq,iq):
	d_int = int(d, 16)
	p_int = int(p, 16)
	q_int = int(q, 16)
	dp_int = int(dp, 16)
	dq_int = int(dq, 16)
	iq_int = int(iq, 16)
	pub_num = llave_pub.public_numbers()
	numbers = rsa.RSAPrivateNumbers(p_int, q_int, d_int, dp_int, dq_int, iq_int, pub_num)
	privkey = numbers.private_key(default_backend())
	#privkey = default_backend().load_rsa_private_numbers(numbers)
	return privkey

def Generar_secreto():
	global llave
	global vi
	llave = b"00000000000000000000000000000000"
	vi = b"0000000000000000"
	return

def Generacion_llaves():
	global llave_pub
	global llave_priv

	exp="010001"
	mod="0x9195E9854FA04A1433D4E22048951426A0ACFC6FE446730579D742CAEA5FDF6590FAEC7F71F3EBF0C6408564987D07E19EC07BC0F601B5E6ADB28D9AA6148FCC51CFF393178983790CC616C0EF34AB50DC8444F44E24117B46A47FA3630BF7E696865BFC245F7C3A314CD48C583D7B2223AF06881158557E37B3CC370AE6C8D5"
	llave_pub = Generar_llavePub(exp, mod)

	d="0x05B2DDE134ACB6E448E31C618720796EC9A5FBD0FAC3DC876A5832BFC94CD76C725B0AC6DCFF09F7F2CAB3C356F4B89F96F1E73B8BBAFABE7CD8C5BCE2A360BD8A3CE2767A2F83A6B143C2446D5A0388748F91813BB5E7A6CEA402368842DBC50C11EFE6B26CB08B53B83BC7FB17D5A62C39A6CCC718165D59375BE387642601"
	p="0xCCF876B8B473F7E05C9551EE3F7ECA0C57CB542E0849B663026CB8A2896E75B80CC6D2415425DD5987ECB47AE7DCD091BA3F609B0FE02E969C4E7DC29E36437D"
	q="0xB5D49FA4F78255C12DD125EF76EB039DA81CECF80C314E1E067706E200101117EF3D03479EEC26DBFA7355CD2913F3AD7F465D6F1424D8A8506A1E8852606A39"
	dp="0x03C4C9C209A75C3666DD63FD42739D596EBFD1536B59979DE86C815493BC5133CA2059BB53C5C27523F7A935DD4F851238DF7372466F73CBD721E6540EBEA6AD"
	dq="0x603745CEEE65DA68E18CB5AD345901CDD02296465F754BA7D9B5EC3F74D70BA485A4DC726EA6F99D17B72624ECE2B0E412E0321AD026FB3A7D6ADA033ACBE809"
	iq="0x036F02D351D7831238E5361BAC0D60888D0F2AB38B0DED7A14A90E2CF1D4D3BD72395F9667ED279889987808288FFF2739927A2868F01A3036BD85D44DDA9FD5"
	llave_priv = Generar_llavePriv(llave_pub,d,p,q,dp,dq,iq)

	Generar_secreto()

# ========================================================================
# 		Algoritmos de cifrado simétrico y asimétrico (RSA-OAEP, AES)
# ========================================================================
def Cifrado_RSA_OAEP(message):
	ciphertext_raw = llave_pub.encrypt(
	 message, padding_asim.OAEP(
			mgf=padding_asim.MGF1(algorithm=hashes.SHA256()),
			 algorithm=hashes.SHA256(),
			label=""
			)
		)
	return ciphertext_raw

def Descifrado_RSA_OAEP(ciphertext_raw):
	plaintext = llave_priv.decrypt(
		ciphertext_raw,
		padding_asim.OAEP(
			mgf=padding_asim.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	return plaintext

def Cifrado_AES_256(mensaje, cifradorAES):
	return cifradorAES.update(mensaje)

def Descifrado_AES_256(mensaje, descifradorAES):
	return descifradorAES.update(mensaje)



def context_generation():
	"""
	Se utilizará las mismas llaves tanto pára RSA como para AES y el mismo Vector
	de inicializacion para AES-CBC porque nos interesa probar la eficiencia del cifrado
	y descifrado y la generación de llaves se excluye en este proyecto. 
	"""
	Generacion_llaves()

	#Para no estar creando el contexto cada vez que se quiere cifrar
	cifradorECB = Cipher(algorithms.AES(llave), modes.ECB()).encryptor()
	cifradorCBC = Cipher(algorithms.AES(llave), modes.CBC(vi)).encryptor()
	descifradorECB = Cipher(algorithms.AES(llave), modes.ECB()).decryptor()
	descifradorCBC = Cipher(algorithms.AES(llave), modes.CBC(vi)).decryptor()


	return cifradorECB, cifradorCBC, descifradorECB, descifradorCBC



# ========================================================================
# 							Programa principal
# ========================================================================
#Test propuesto: ir aumentando el tam del msj en bits

# ----------------------- Creacion de contexto ------------------------- #

cifradorECB, cifradorCBC, descifradorECB, descifradorCBC = context_generation()

# ------------- Toma de tiempo para Cifrado RSA - OAEP ----------------- #
num_iter = 300
arr_enc_rsa = [] #msjs cifrados
av_enc_rsa = []

print("Cifrando msjs con RSA-OAEP ...")

for msg in mensajes: 
	cipher = []
	times = []
	for i in range(num_iter):
		start = time.time()
		ciphertext = Cifrado_RSA_OAEP(msg)
		end = time.time()
		cipher.append(ciphertext) #guardando texto cifrado
		times.append(end-start)
	average = statistics.mean(list(times))
	av_enc_rsa.append(average)		
	arr_enc_rsa.append(list(cipher))



# ------------ Toma de tiempo para Descifrado RSA - OAEP --------------- #
av_dec_rsa = []
arr_dec_rsa = [] #msjs descifrados
print("Descifrando msjs con RSA-OAEP ...\n")

for msg_type in arr_enc_rsa:
	plain = []
	times = [] 
	for i in range(len(msg_type)):
		ciphertext_raw = msg_type[i]
		start = time.time()
		plaintext = Descifrado_RSA_OAEP(ciphertext_raw)
		end = time.time()
		plain.append(plaintext) #guardando texto en claro
		times.append(end-start)
	average = statistics.mean(list(times))
	av_dec_rsa.append(average)		
	arr_dec_rsa.append(list(plain))

# ------------- Toma de tiempo para Cifrado AES-256 ECB ----------------- #
arr_enc_ecb = [] #msjs cifrados
av_enc_ecb = []
print("Cifrando msjs con AES - 256 ECB ...")


for msg in mensajes:
	cipher = []
	times = []
	for i in range(num_iter):
		numBytes = len(msg)
		start = time.time()
		ciphertext = Cifrado_AES_256(msg, cifradorECB)
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
		numBytes = len(ciphertext_raw)
		start = time.time()
		plaintext = Descifrado_AES_256(ciphertext_raw, descifradorECB)
		end = time.time()
		plain.append(plaintext) #guardando texto en claro
		times.append(end-start)
	average = statistics.mean(list(times))
	av_dec_ecb.append(average)		
	arr_dec_ecb.append(list(plain))

# ------------- Toma de tiempo para Cifrado AES-256 CBC ----------------- #
arr_enc_cbc = [] #msjs cifrados
av_enc_cbc = []
print("Cifrando msjs con AES - 256 CBC ...")


for msg in mensajes:
	cipher = []
	times = []
	for i in range(num_iter):
		numBytes = len(msg)
		start = time.time()
		ciphertext = Cifrado_AES_256(msg, cifradorCBC)
		end = time.time()
		cipher.append(ciphertext) #guardando texto cifrado
		times.append(end-start)
	average = statistics.mean(list(times))
	av_enc_cbc.append(average)		
	arr_enc_cbc.append(list(cipher))

# ------------ Toma de tiempo para Descifrado AES-256 CBC --------------- #
av_dec_cbc = []
arr_dec_cbc = [] #msjs descifrados
print("Descifrando msjs con AES - 256 CBC ...\n")

for msg_type in arr_enc_cbc:
	plain = []
	times = [] 
	for i in range(len(msg_type)):
		ciphertext_raw = msg_type[i]
		numBytes = len(ciphertext_raw)
		start = time.time()
		plaintext = Descifrado_AES_256(ciphertext_raw, descifradorECB)
		end = time.time()
		plain.append(plaintext) #guardando texto en claro
		times.append(end-start)
	average = statistics.mean(list(times))
	av_dec_cbc.append(average)		
	arr_dec_cbc.append(list(plain))

encrypt_times_matrix = np.array([av_enc_rsa,av_enc_ecb,av_enc_cbc])
decrypt_times_matrix = np.array([av_dec_rsa,av_dec_ecb,av_dec_cbc])


# ======================================================================
#						Graficas
# ======================================================================

def get_color_for_idx(idx):
	colors = ["#118ab2", "#06d6a0", "#ef476f"]
	return colors[idx]

def graph_times(times_matrix, dark=False, enc=True):
	fig = go.Figure()
	for idx, time in enumerate(times_matrix):
		if idx == 0: 
			algo_label = 'RSA 1024'
			test_vector_label = 'OAEP'
		elif idx == 1:
			algo_label = 'AES 256'
			test_vector_label = 'ECB'
		elif idx == 2:
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
					text=f'<b>Comparison of RSA OAEP vs. AES ECB vs. AES CBC for encryption</b><br>for messages of length 128 bits' 
					if enc else
					f'<b>Comparison of RSA OAEP vs. AES ECB vs. AES CBC for decryption</b><br>for messages of length 128 bits'

			), 
			template='plotly_dark' if dark else 'plotly_white',
			xaxis_title='Number of message',
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