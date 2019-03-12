'''
FeatureExtractor
2019-03-11
* Functions
- parsing bro log
- extract flow information
- extract statistical features
'''
import os
import pandas as pd
from Flows import Flows

class FeatureExtractor:


    def __init__(self, path):
        self.path = path
        self.delimiter_csv = '\x09'
        self.file_types = ['conn', 'ssl', 'x509', 'dns']

        # key
        # flows : (src_ip, dst_ip, dst_port, proto)
        # conn_logs : uid
        # ssl_logs : uid
        # x509_log : id
        # dns_log : uid
        self.flows = dict()
        self.conn_logs = dict()
        self.ssl_logs = dict()
        self.x509_logs = dict()
        self.dns_logs = dict()
        self.exist_file_type = []
        self.convert_csv_from_bro_log()

    '''
        convert bro file to csv file
    '''
    def convert_csv_from_bro_log(self):
        for file_type in self.file_types:
            csv_file = '{}/{}.csv'.format(self.path, file_type)
            bro_file = '{}/{}.log'.format(self.path, file_type)
            if os.path.exists(bro_file):
                self.exist_file_type.append(file_type)
                with open(csv_file, 'w') as fw:
                    with open(bro_file, 'r') as fr:
                        while True:
                            line = fr.readline()
                            if not line or line.startswith('#close'):
                                break
                            if line.startswith("#fields"):
                                fw.write(line.replace('#fields\x09', ''))
                                continue
                            elif line.startswith("#"):
                                continue
                            fw.write(line)

    '''
        1. extract data from csv file, 
    '''
    def prepare_data(self):
        # parse data and store in each {file_type}_log
        self.parsing_conn_file()
        self.parsing_ssl_file()
        self.parsing_dns_file()
        self.parsing_x509_file()

        # create flows group by (src_ip, dst_ip, dst_port, protocol)
        self.create_flows()

    def parsing_conn_file(self):
        self.conn_log_datas = pd.read_csv(self.path + '/conn.csv', delimiter=self.delimiter_csv)
        for idx, conn_log in self.conn_log_datas.iterrows():
            uid = conn_log['uid']
            if uid in self.conn_logs:
                print(['[WARNING] there is duplicated uid key in conn log'])
            else:
                self.conn_logs[uid] = conn_log

    def parsing_ssl_file(self):
        self.ssl_log_datas = pd.read_csv(self.path + '/ssl.csv', delimiter=self.delimiter_csv)
        for idx, ssl_log in self.ssl_log_datas.iterrows():
            uid = ssl_log['uid']
            if uid in self.ssl_logs:
                self.ssl_logs[uid].append(ssl_log)
            else:
                self.ssl_logs[uid] = [ssl_log]

    def parsing_x509_file(self):
        self.x509_log_datas = pd.read_csv(self.path + '/x509.csv', delimiter=self.delimiter_csv)
        for idx, x509_log in self.x509_log_datas.iterrows():
            id = x509_log['id']
            if id in self.x509_logs:
                self.x509_logs[id].append(x509_log)
            else:
                self.x509_logs[id] = [x509_log]

    def parsing_dns_file(self):
        self.dns_log_datas = pd.read_csv(self.path + '/dns.csv', delimiter=self.delimiter_csv)
        for idx, dns_log in self.dns_log_datas.iterrows():
            uid = dns_log['uid']
            if uid in self.dns_logs:
                self.dns_logs[uid].append(dns_log)
            else:
                self.dns_logs[uid] = [dns_log]

    def create_flows(self):
        for uid in self.conn_logs:
            conn_log = self.conn_logs[uid]
            src_ip = conn_log['id.orig_h']
            dst_ip = conn_log['id.resp_h']
            dst_port = conn_log['id.resp_p']
            protocol = conn_log['proto']
            key = (src_ip, dst_ip, dst_port, protocol)
            if key not in self.flows:
                self.flows[key] = Flows(key)
            self.flows[key].add_conn_log(conn_log)

            if uid in self.ssl_logs:
                ssl_log_list = self.ssl_logs[uid]
                for ssl_log in ssl_log_list:
                    self.flows[key].add_ssl_log(ssl_log)
                    cert_chain_fuids = ssl_log['cert_chain_fuids']
                    if cert_chain_fuids != '-':
                        for id in cert_chain_fuids.split(','):
                            self.flows[key].add_x509_log(ssl_log, self.x509_logs[id])

        print('create flows')

    def get_features_list(self):
        features_list = []
        for key in self.flows:
            flow = self.flows[key]
            try:
                flow_info = {
                    'src_ip': key[0]
                    , 'dst_ip': key[1]
                    , 'dst_port': key[2]
                    , 'proto': key[3]
                    , 'nubmer_of_conn': flow.number_of_connections()
                    , 'mean_of_duration': flow.mean_of_duration()
                    , 'stdev_of_duration': flow.stdev_of_duration()
                    , 'stdev_of_range_of_duration': flow.stdev_of_range_of_duration()
                    , 'payload_bytes_from_orig': flow.payload_bytes_from_orig()
                    , 'payload_bytes_from_resp': flow.payload_bytes_from_resp()
                    , 'ratio_of_resp_bytes': flow.ratio_of_resp_bytes()
                    , 'ip_bytes_from_orig': flow.ip_bytes_from_orig()
                    , 'ip_bytes_from_resp': flow.ip_bytes_from_resp()
                    , 'ratio_of_resp_ip_bytes': flow.ratio_of_resp_ip_bytes()
                    , 'ratio_of_established_states': flow.ratio_of_established_states()
                    , 'number_of_resp_pkts': flow.number_of_resp_pkts()
                    , 'number_of_orig_pkts': flow.number_of_orig_pkts()
                    , 'mean_of_periodicity': flow.mean_of_periodicity()
                    , 'stdev_of_periodicity': flow.stdev_of_periodicity()
                    , 'ratio_of_non_ssl_to_ssl': flow.ratio_of_non_ssl_to_ssl()
                    , 'ratio_of_tls': flow.ratio_of_tls()
                    , 'ratio_of_sni': flow.ratio_of_sni()
                    , 'code_of_sni_as_ip': flow.code_of_sni_as_ip()
                    , 'mean_of_certificate': flow.mean_of_certificate()
                    , 'ratio_of_not_verified_cert': flow.ratio_of_not_verified_cert()
                }
                features_list.append(flow_info)
            except Exception as e:
                raise e

        return features_list

import pandas as pd
if __name__ == '__main__':
    print('=============================== start =============================')
    path = '/home/sdsra/Downloads/CTU-13-Dataset/malware/42'
    fe = FeatureExtractor(path)
    fe.prepare_data()
    list = fe.get_features_list()
    datas = pd.DataFrame.from_records(list)
    print(datas.describe())
    print(datas.info())
    print('================================ end ==============================')