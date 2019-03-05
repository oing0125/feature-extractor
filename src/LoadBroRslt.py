import csv
import pandas as pd

path = '/home/sdsra/Downloads/CTU-13-Dataset/benign/2013-12-17_capture1'

conn_log_datas = pd.read_csv(path + '/conn.log', delimiter='\x09')
ssl_log_datas = pd.read_csv(path + '/ssl.log', delimiter='\x09')
x509_log_datas = pd.read_csv(path + '/x509.log', delimiter='\x09')

for idx, ssl_log in ssl_log_datas.iterrows():
    uid = ssl_log['uid']

    # 1. find 4 tuples
    conn_log = conn_log_datas[conn_log_datas['uid'] == uid].squeeze()
    src_ip = conn_log['id.orig_h']
    dst_ip = conn_log['id.resp_h']
    src_port = conn_log['id.orig_p']
    dst_port = conn_log['id.resp_p']

    # 2. find ssl certs(one or more)
    cert_chain = ssl_log['cert_chain_fuids']
    if cert_chain == '-':
        continue
    first_cert_key = cert_chain.split(',')[0]
    x509_logs = x509_log_datas[x509_log_datas['id'] == first_cert_key]
    print(x509_logs)
    break



print('================================ end ==============================')