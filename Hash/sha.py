# ============================= Criptografía ============================= # 
# Integrantes:
#       Martínez Ostoa Néstor Iván 
#       Meza Ortega Fernando
#       Suxo Pacheco Elsa Guadalupe
# ======================================================================== #

import os
import pandas as pd
import numpy as np
from cryptography.hazmat.primitives import hashes
import time
import plotly.graph_objects as go
from plotly.subplots import make_subplots

def get_dir_contents(path):
    contents = os.listdir(path)
    contents = [f for f in contents if f[0] != '.']
    return sorted(contents)


class TestVector:
    def __init__(self, file_name, lengths, messages, mds):
        self.file_name = file_name
        self.lengths = lengths
        self.messages = messages
        self.mds = mds

    def __init__(self, path, file_name):
        self.file_name = file_name
        (self.lengths, self.messages, self.mds) = self.build_tv(path, file_name)

    def build_tv(self, path, file_name, length_key='Len', msg_key='Msg'):
        lines = open(path + file_name).readlines()
        lengths = []
        messages = []
        mds = []
        for line in lines:
            if line[:len(length_key)] == length_key: lengths.append(int(self.clean_str(line)))
            if line[:len(msg_key)] == msg_key: messages.append(self.clean_str(line))
            if line[:2] == 'MD': mds.append(self.clean_str(line))
        temp_df = pd.DataFrame({
            'length': lengths,
            'message': messages,
            'md': mds
        })
        temp_df = temp_df.sort_values(by='length')
        return (temp_df['length'], temp_df['message'], temp_df['md'])

    def to_df(self):
        return pd.DataFrame({
            'length': self.lengths,
            'message': self.messages,
            'md': self.mds
        })

    def clean_str(self, str_):
        return str_.split('=')[1].strip()

    def __str__(self):
        return f"{self.file_name} - {self.lengths.shape[0]} elements"

    def print_extended(self):
        return f"""-------------------------------------------------
        File name: {self.file_name}
        Num elements:
            Lengths: {self.lengths.shape}
            Messages: {self.messages.shape}
            MDs: {self.mds.shape}
        Example: 
            Len: {self.lengths[0]} bits
            Msg: {len(self.messages[0])} chars
            MD: {len(self.mds[0])*4} bits
        """

def get_time_vector(test_vectors, algorithm):
    times = []
    for msg in test_vectors:
        start = time.time()
        #-Algorithm evaluation-----------
        h = hashes.Hash(algorithm)
        h.update(str.encode(msg))
        h.finalize().hex()
        #---------------------------------
        end = time.time()
        times.append(end-start)
    return times

def get_avg_time_vector(test_vectors, algorithm, num_iter=4):
    times_matrix = []
    for _ in range(num_iter):
        times_matrix.append(get_time_vector(test_vectors, algorithm))
    return np.mean(np.array(times_matrix), axis=0)


def get_algos_time_matrix(algorithms, test_vectors, num_iter=4):
    test_vectors_time_matrix = []
    for tv in test_vectors:
        time_matrix = []
        for algo in algorithms:
            tm = get_avg_time_vector(tv.messages, algo, num_iter)
            time_matrix.append(tm)
        test_vectors_time_matrix.append(time_matrix)
    return test_vectors_time_matrix

def get_element_from_idx(iterable, idx):
    if idx >= 0: return iterable[idx]
    if type(iterable) == dict: return iterable[len(iterable.keys()) + idx]
    return iterable[len(iterable) + idx]

def get_color_for_algo_label(algo_label):
    if algo_label == algorithms_labels[0]: return "#ef476f"
    if algo_label == algorithms_labels[1]: return "#ffd166"
    if algo_label == algorithms_labels[2]: return "#06d6a0"
    if algo_label == algorithms_labels[3]: return "#118ab2"

def graph_all_tv(test_vectors_matrix, dark=False):
    fig = make_subplots(
        rows=4, cols=4, subplot_titles=list(tv_dict.values()),
        row_heights=[0.25]*4
    )
    idx = 0
    for row in range(4):
        for col in range(4):
            times = test_vectors_matrix[idx]
            for time_idx, time in enumerate(times):
                algo_label = algorithms_labels[time_idx]
                fig.add_trace(go.Scatter(
                    x=test_vectors[idx].lengths,
                    y=time,
                    line=dict(color=get_color_for_algo_label(algo_label)),
                    name=algo_label,
                    showlegend=True if row == 0 and col == 0 else False
                ), row+1, col+1)
            idx += 1
    fig.update_layout(
        title=dict(
            text='Test vectors evaluations with SHA-2,3 and md size 384 and 512'
        ),
        height=700,
        template='plotly_dark' if dark else 'plotly_white'
    )
    fig.show()

def get_tv_info(test_vector_idx, test_vectors):
    df = test_vectors[test_vector_idx].to_df()
    min_ = min(df['length'])
    max_ = max(df['length'])
    print(f'Shape: {df.shape}\nMin: {min_}\tMax: {max_}')
    print(f'Size of last msg: {len(df.iloc[-1].message)}')
    return df

def graph_tv(test_vectors, vector_lengths, tv_idx, dark=False):
    times = get_element_from_idx(test_vectors, tv_idx)
    test_vector_label = get_element_from_idx(tv_dict, tv_idx)
    fig = go.Figure()
    for idx, time in enumerate(times):
        algo_label = algorithms_labels[idx]
        fig.add_trace(go.Scatter(
            x=vector_lengths,
            y=time,
            name=algo_label,
            line=dict(color=get_color_for_algo_label(algo_label)),
            mode='lines'
        ))
        fig.update_layout(
            title=dict(
                text=f'<b>{test_vector_label}</b>'
            ), 
            template='plotly_dark' if dark else 'plotly_white',
            xaxis_title='Message size',
            yaxis_title='Time in seconds'
        )
    fig.show()

def get_info_from_time_matrix(time_matrix, test_vectors_to_use):

    print(f'\n-------- Hash - Info: --------')
    for k in test_vectors_to_use.keys():
        times = get_element_from_idx(time_matrix, k)
        for _, time in enumerate(times):
            print(np.mean(time))


A = [1, 3, 2, 10, 4]
B = sorted(A)
A == B


TEST_VECTORS_PATH = 'test-vectors/'
test_vectors = []
for file_name in get_dir_contents(TEST_VECTORS_PATH):
    tv = TestVector(TEST_VECTORS_PATH, file_name)
    test_vectors.append(tv)
    print(tv)


# Verificamos que los vectores de prueba estén ordenados por tamaño del mensaje

for tv in test_vectors:
    print(tv, end='  ')
    lengths = list(tv.to_df()['length'])
    s = True
    for i in range(1, len(lengths)):
        if lengths[i-1] > lengths[i]:
            S = False
            break
    print(f'Sorted? {s}')


# # 2. SHA algorithms evaluation



algorithms = [hashes.SHA384(), hashes.SHA512(), hashes.SHA3_384(), hashes.SHA3_512()]
test_vectors_time_matrix = get_algos_time_matrix(algorithms, test_vectors, num_iter=10)


# # 3. SHA-2,3 evaluation graphs

tv_dict = {
    0:'SHA2_384LongMsg_Bit.rsp',
    1:'SHA2_384LongMsg_Byte.rsp',
    2:'SHA2_384ShortMsg_Bit.rsp',
    3:'SHA2_384ShortMsg_Byte.rsp',
    4:'SHA2_512LongMsg_Bit.rsp',
    5:'SHA2_512LongMsg_Byte.rsp',
    6:'SHA2_512ShortMsg_Bit.rsp',
    7:'SHA2_512ShortMsg_Byte.rsp',
    8:'SHA3_384LongMsg_Bit.rsp',
    9:'SHA3_384LongMsg_Byte.rsp',
    10:'SHA3_384ShortMsg_Bit.rsp',
    11:'SHA3_384ShortMsg_Byte.rsp',
    12:'SHA3_512LongMsg_Bit.rsp',
    13:'SHA3_512LongMsg_Byte.rsp',
    14:'SHA3_512ShortMsg_Bit.rsp',
    15:'SHA3_512ShortMsg_Byte.rsp'
}

algorithms_labels = [
    'SHA-2 384', 'SHA-2 512', 'SHA-3 384', 'SHA-3 512'
]



graph_all_tv(test_vectors_time_matrix, dark=False)

get_tv_info(3, test_vectors).head()

test_vectors_to_use = {
    13: test_vectors[13], # SHA3_512LongMsg_Byte.rsp
    2: test_vectors[2], # SHA2_384ShortMsg_Bit.rsp
    15: test_vectors[15] # SHA3_512ShortMsg_Byte.rsp
}
for k in test_vectors_to_use.keys():
    graph_tv(test_vectors_time_matrix, test_vectors[k].lengths, k, dark=False)

get_info_from_time_matrix(test_vectors_time_matrix, test_vectors_to_use)