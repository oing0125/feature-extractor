from Connection4tuple import Connection4tuple
import csv
import pandas as pd
import numpy as np

class FeatureExtractor:

    # key : 4 tuple(src_ip, dst_ip, src_port, dst_port)
    connections = {}
    conn_dict = dict()
    ssl_dict = dict()

    def __init__(self, path):
        if type(path) is str:
            self.path = path
        else:
            print('error : type of path should be string')
            raise RuntimeError()
        self.init_datas()

    def init_datas(self):
        self.convert_csv_from_bro_log()
        self.conn_log_datas = pd.read_csv(self.path + '/conn.csv', delimiter='\x09')
        self.ssl_log_datas = pd.read_csv(self.path + '/ssl.csv', delimiter='\x09')
        self.x509_log_datas = pd.read_csv(self.path + '/x509.csv', delimiter='\x09')

    def convert_csv_from_bro_log(self):
        file_types = ['conn', 'ssl', 'x509']
        for file_type in file_types:
            row_no = 0
            fields_row_no = 7
            datas_start = 9
            end_line_start_with = '#close'
            with open('{}/{}.csv'.format(self.path, file_type), 'w') as fw:
                with open('{}/{}.log'.format(self.path, file_type), 'r') as fr:
                    while True:
                        row_no += 1
                        line = fr.readline()
                        if not line:
                            break
                        if row_no < datas_start:
                            if row_no == fields_row_no:
                                fw.write(line.replace('#fields\x09', ''))
                            continue
                        if line.startswith(end_line_start_with):
                            break;
                        fw.write(line)

    def extract_features(self):
        # TODO
        # 1. load ssl, insert data
        for idx, ssl_log in self.ssl_log_datas.iterrows():
            uid = ssl_log['uid']
            self.ssl_dict[uid] = ssl_log

            # 1) find 4 tuples
            conn_log = self.conn_log_datas[self.conn_log_datas['uid'] == uid].squeeze()
            self.conn_dict[uid] = conn_log
            src_ip = conn_log['id.orig_h']
            dst_ip = conn_log['id.resp_h']
            src_port = conn_log['id.orig_p']
            dst_port = conn_log['id.resp_p']
            if type(src_ip) is not str or type(dst_ip) is not str or type(src_port) is not np.int64 or type(dst_port) is not np.int64:
                print('[warning] keys of tuples has some strange value. skip the data')
                continue
            tuple_key = (src_ip, dst_ip, src_port, dst_port)

            # 2) find ssl certs(one or more)
            cert_chain = ssl_log['cert_chain_fuids']
            if cert_chain == '-':
                continue
            cert_keys = cert_chain.split(',') if ',' in str(cert_chain) else [cert_chain]
            x509_logs = []
            for cert_key in cert_keys:
                x509_logs.append(self.x509_log_datas[self.x509_log_datas['id'] == cert_key])

            # 3) save in connections
            connection4tuple = None
            if tuple_key in self.connections:
                connection4tuple = self.connections[tuple_key]
            else:
                connection4tuple = Connection4tuple(tuple_key)
                connection4tuple.add_ssl_flow(conn_log)
            # connection4tuple.add_conn_log(conn_log)
            # connection4tuple.add_ssl_log(ssl_log)
            # connection4tuple.add_x509_log(ssl_log, x509_logs)
            self.connections[tuple_key] = connection4tuple

        # 2. load conn, if not exist, insert
        for idx, conn_log in self.conn_log_datas.iterrows():
            uid = conn_log['uid']
            if uid in self.conn_dict:
                pass
            self.conn_dict[uid] = conn_log
            src_ip = conn_log['id.orig_h']
            dst_ip = conn_log['id.resp_h']
            src_port = conn_log['id.orig_p']
            dst_port = conn_log['id.resp_p']
            tuple_key = (src_ip, dst_ip, src_port, dst_port)
            if tuple_key not in self.connections:
                connection4tuple = Connection4tuple(tuple_key)
                connection4tuple.add_not_ssl_flow(conn_log)

        # 3. calculate statictical feature
        # for connection4tupl_key in self.connections:
        #     self.connections[connection4tupl_key].calculate_statistical_feature()


if __name__ == '__main__':
    print('=============================== start =============================')
    path = '/home/sdsra/Downloads/CTU-13-Dataset/benign/2017_04_30-normal'
    fe = FeatureExtractor(path)
    # fe.extract_features()
    print('================================ end ==============================')

