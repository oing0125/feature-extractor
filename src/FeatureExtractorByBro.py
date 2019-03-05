from Connection4tuple import Connection4tuple
import csv
import pandas as pd
import numpy as np

class FeatureExtractor:

    # key : 4 tuple(src_ip, dst_ip, src_port, dst_port)
    connections = {}

    def __init__(self, path):
        if type(path) is str:
            self.path = path
        else:
            print('error : type of path should be string')
            raise RuntimeError()
        self.init_datas()

    def init_datas(self):
        self.conn_log_datas = pd.read_csv(self.path + '/conn.log', delimiter='\x09')
        self.ssl_log_datas = pd.read_csv(self.path + '/ssl.log', delimiter='\x09')
        self.x509_log_datas = pd.read_csv(self.path + '/x509.log', delimiter='\x09')

    def convert_csv_from_bro_log(self):
        file_types = ['conn', 'ssl', 'x509']
        for file_type in file_types:
            with open('{}/{}.csv'.format(self.path, file_type)) as fw:
                with open('{}/{}.log'.format(self.path, file_type)) as fr:
                    # TODO write code for converting
                    print('aaa')

    def extract_features(self):
        for idx, ssl_log in self.ssl_log_datas.iterrows():
            uid = ssl_log['uid']

            # 1. find 4 tuples
            conn_log = self.conn_log_datas[self.conn_log_datas['uid'] == uid].squeeze()
            src_ip = conn_log['id.orig_h']
            dst_ip = conn_log['id.resp_h']
            src_port = conn_log['id.orig_p']
            dst_port = conn_log['id.resp_p']
            if type(src_ip) is not str or type(dst_ip) is not str or type(src_port) is not np.int64 or type(dst_port) is not np.int64:
                print('[warning] keys of tuples has some strange value. skip the data')
                continue

            # 2. find ssl certs(one or more)
            cert_chain = ssl_log['cert_chain_fuids']
            if cert_chain == '-':
                continue
            first_cert_key = cert_chain.split(',')[0] if ',' in str(cert_chain) else cert_chain
            x509_logs = self.x509_log_datas[self.x509_log_datas['id'] == first_cert_key]

            # 3. save in connections
            connection4tuple = None
            tuple_key = (src_ip, dst_ip, src_port, dst_port)
            if tuple_key in self.connections:
                connection4tuple = self.connections[tuple_key]
            else:
                connection4tuple = Connection4tuple(tuple_key)
            connection4tuple.add_ssl_log(ssl_log)
            connection4tuple.add_conn_log(conn_log)
            connection4tuple.add_x509_log(x509_logs)
            self.connections[tuple_key] = connection4tuple

if __name__ == '__main__':
    print('=============================== start =============================')
    path = '/home/sdsra/Downloads/CTU-13-Dataset/benign/2013-12-17_capture1'
    fe = FeatureExtractor(path)
    fe.extract_features()
    print('================================ end ==============================')

