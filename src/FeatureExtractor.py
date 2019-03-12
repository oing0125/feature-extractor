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

    def parsing_file(self, path):
        self.conn_log_datas = pd.read_csv(self.path + '/conn.csv', delimiter=self.delimiter_csv)
        for idx, conn_log in self.conn_log_datas.iterrows():
            uid = conn_log['uid']
            if uid in self.conn_logs:
                self.conn_logs['uid'].append(conn_log)
            else:
                self.conn_logs['uid'] = [conn_log]

    def parsing_ssl_file(self, path):
        self.ssl_log_datas = pd.read_csv(self.path + '/ssl.csv', delimiter=self.delimiter_csv)
        for idx, ssl_log in self.ssl_log_datas.iterrows():
            uid = ssl_log['uid']
            if uid in self.ssl_logs:
                self.ssl_logs['uid'].append(ssl_log)
            else:
                self.ssl_logs['uid'] = [ssl_log]

    def parsing_x509_file(self, path):
        self.x509_log_datas = pd.read_csv(self.path + '/x509.csv', delimiter=self.delimiter_csv)
        for idx, x509_log in self.x509_log_datas.iterrows():
            uid = x509_log['uid']
            if uid in self.x509_logs:
                self.x509_logs['id'].append(x509_log)
            else:
                self.x509_logs['id'] = [x509_log]

    def parsing_dns_file(self, path):
        self.dns_log_datas = pd.read_csv(self.path + '/dns.csv', delimiter=self.delimiter_csv)
        for idx, dns_log in self.dns_log_datas.iterrows():
            uid = dns_log['uid']
            if uid in self.dns_logs:
                self.dns_logs['uid'].append(dns_log)
            else:
                self.dns_logs['uid'] = [dns_log]

    def create_flows(self):
        # TODO 0311 iterate conn_logs and create flow info
        print('create flows')


if __name__ == '__main__':
    print('=============================== start =============================')
    path = '/home/sdsra/Downloads/CTU-13-Dataset/benign/2017_04_30-normal'
    fe = FeatureExtractor(path)
    fe.prepare_data()
    print('================================ end ==============================')