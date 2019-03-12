from Connection4tuple import Connection4tuple
from CertificateFeature import CertificationFeatures
import csv
import pandas as pd
import numpy as np

class FeatureExtractor:

    # key : 4 tuple(src_ip, dst_ip, src_port, dst_port)
    connections = {}
    # neeed to insert not_ssl conn log
    conn_dict = dict()
    ssl_dict = dict()
    x509_dict = dict()
    certificate_dict = dict()

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
                            break
                        fw.write(line)

    def extract_features(self):
        # TODO

        # 0. load x509, create x509_dict
        for idx, x509_log in self.x509_log_datas.iterrows():
            x509_uid = x509_log['id']
            if x509_uid not in self.x509_dict:
                self.x509_dict[x509_uid] = x509_log

        # 1. load ssl, insert data
        for idx, ssl_log in self.ssl_log_datas.iterrows():
            uid = ssl_log['uid']
            self.ssl_dict[uid] = ssl_log

            # 1) find 4 tuples
            conn_log = self.conn_log_datas[self.conn_log_datas['uid'] == uid].squeeze()
            self.conn_dict[uid] = conn_log
            src_ip = conn_log['id.orig_h']
            dst_ip = conn_log['id.resp_h']
            dst_port = conn_log['id.resp_p']
            proto = conn_log['proto']
            if type(src_ip) is not str or type(dst_ip) is not str or type(proto) is not np.int64 or type(dst_port) is not np.int64:
                print('[warning] keys of tuples has some strange value. skip the data')
                continue
            tuple_key = (src_ip, dst_ip, dst_port, proto)


            # 3) save in connections
            connection4tuple = None
            if tuple_key in self.connections:
                connection4tuple = self.connections[tuple_key]
            else:
                connection4tuple = Connection4tuple(tuple_key)
            connection4tuple.add_ssl_flow(conn_log)

            # TODO
            # write ssl information
            server_name = ssl_log['server_name']
            cert_chain = ssl_log['cert_chain_fuids']
            if cert_chain == '-':
                # print('[Warning]no cert chain.... what can u do?')
                continue
            cert_keys = cert_chain.split(',') if ',' in str(cert_chain) else [cert_chain]
            uid_x509 = cert_keys[0]
            x509_log = self.x509_log_datas[self.x509_log_datas['id'] == uid_x509].squeeze()
            if uid_x509 in self.x509_dict:
                cert_serial = x509_log['certificate.serial']
                certificate_feature = None
                if cert_serial in self.certificate_dict:
                    certificate_feature = self.certificate_dict[cert_serial]
                else:
                    certificate_feature = CertificationFeatures()
                certificate_feature.add_server_name(server_name)
                certificate_feature.add_x509_info(x509_log)

            connection4tuple.add_ssl_log(ssl_log, x509_log)
            list_of_x509_uid = ssl_log['cert_chain_fuids'].split(',')
            x509_log_list = []
            is_found = True
            for x509_uid in list_of_x509_uid:
                if x509_uid in self.x509_dict:
                    x509_log_list.append(self.x509_dict[x509_uid])
                else:
                    is_found = False
            connection4tuple.check_certificate_path(x509_log_list, is_found)
            if len(x509_log_list) > 0 :
                connection4tuple.check_root_certificate(x509_log_list)

            self.connections[tuple_key] = connection4tuple

        # 2. load conn, if not exist, insert
        for idx, conn_log in self.conn_log_datas.iterrows():
            uid = conn_log['uid']
            if uid in self.conn_dict:
                pass
            self.conn_dict[uid] = conn_log
            src_ip = conn_log['id.orig_h']
            dst_ip = conn_log['id.resp_h']
            dst_port = conn_log['id.resp_p']
            proto = conn_log['proto']
            tuple_key = (src_ip, dst_ip, dst_port, proto)
            connection4tuple = None
            if tuple_key in self.connections:
                connection4tuple = self.connections[tuple_key]
            else:
                connection4tuple = Connection4tuple(tuple_key)
            connection4tuple.add_not_ssl_flow(conn_log)
            self.connections[tuple_key] = connection4tuple

        # 3. calculate statictical feature
        # for connection4tupl_key in self.connections:
        #     self.connections[connection4tupl_key].calculate_statistical_feature()


if __name__ == '__main__':
    print('=============================== start =============================')
    path = '/home/sdsra/Downloads/CTU-13-Dataset/benign/2017_04_30-normal'
    fe = FeatureExtractor(path)
    # fe.extract_features()
    print('================================ end ==============================')

