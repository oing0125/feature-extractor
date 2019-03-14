'''
Flows
2019-03-11
* Functions
- group by flow tuple : (src_ip, dst_ip, dst_port, protocol)
'''
import statistics
import socket

class Flows:

    def __init__(self, key):
        self.key = key
        self.src_ip = key[0]
        self.dst_ip = key[1]
        self.dst_port = key[2]
        self.protocol = key[3]

        # bro's log
        self.conn_log_list = []
        self.ssl_log_list = []
        self.x509_log_list = []

        # connection information
        self.ts_list = []
        self.duration_list = []
        self.conn_state_list = []
        self.orig_bytes_list = []
        self.resp_bytes_list = []
        self.orig_ip_bytes_list = []
        self.resp_ip_bytes_list = []
        self.orig_pkts_list = []
        self.resp_pkts_list = []

        # ssl information
        self.number_of_ssl = 0
        self.number_of_tls_version = 0
        self.number_of_ssl_version = 0
        self.number_of_ssl_having_SNI = 0
        self.sni_as_ip = 1
        self.number_of_cert_list = []
        self.validation_status_list = []

        # x509 information
        self.is_not_valid_cert_period = 0
        self.is_sni_in_san_dns = 0
        self.is_cn_in_san_dns = 0
        self.pub_key_length_list = []
        self.cert_validatity_period_list = []
        self.age_of_cert_list = []
        self.cert_serial_list = []

    def add_conn_log(self, conn_log):
        self.conn_log_list.append(conn_log)
        self.ts_list.append(conn_log['ts'])
        self.duration_list.append(float(conn_log['duration'] if conn_log['duration'] != '-' else 0))
        self.conn_state_list.append(conn_log['conn_state'])
        if conn_log['orig_bytes'] != '-':
            self.orig_bytes_list.append(float(conn_log['orig_bytes']))
        if conn_log['resp_bytes'] != '-':
            self.resp_bytes_list.append(float(conn_log['resp_bytes']))
        if conn_log['orig_ip_bytes'] != '-':
            self.orig_ip_bytes_list.append(float(conn_log['orig_ip_bytes']))
        if conn_log['resp_ip_bytes'] != '-':
            self.resp_ip_bytes_list.append(float(conn_log['resp_ip_bytes']))
        if conn_log['orig_pkts'] != '-':
            self.orig_pkts_list.append(float(conn_log['orig_pkts']))
        if conn_log['resp_bytes'] != '-':
            self.resp_pkts_list.append(float(conn_log['resp_pkts']))

    def add_ssl_log(self, ssl_log):
        self.ssl_log_list.append(ssl_log)
        self.number_of_ssl += 1
        version = ssl_log['version']
        servername = ssl_log['server_name']
        validation_status = ssl_log['validation_status']
        if version.startswith('TLS'):
            self.number_of_tls_version += 1
        elif version.startswith('SSL'):
            self.number_of_ssl_version += 1

        if servername is not '-':
            self.number_of_ssl_having_SNI += 1

        try:
            socket.inet_aton(servername)
            dst_ip = ssl_log['id.resp_h']
            if self.sni_as_ip != -1 and servername == dst_ip:
                self.sni_as_ip = 0
            elif servername != dst_ip:
                self.sni_as_ip = -1
        except socket.error:
            pass

        cert_chain_fuids = ssl_log['cert_chain_fuids']
        if cert_chain_fuids != '-':
            self.number_of_cert_list.append(len(cert_chain_fuids.split(',')))
        else:
            self.number_of_cert_list.append(0)

        self.validation_status_list.append(validation_status)

    def add_x509_log(self, ssl_log, x509_log):
        self.x509_log_list.append(x509_log)
        ts = x509_log['ts']
        ssl_server_name = ssl_log['server_name']
        pub_key_length = x509_log['certificate.key_length']
        not_valid_before = x509_log['certificate.not_valid_before']
        not_valid_after = x509_log['certificate.not_valid_after']
        cert_serial = x509_log['certificate.serial']
        san_dns = x509_log['san.dns']
        san_dns_list = san_dns.split(',')
        subject_str = x509_log['certificate.subject']
        subject_list = subject_str.split(',')
        cn_list = list(map(lambda x :x.split('=')[1], filter(lambda x: x.split('=')[0] == 'CN', subject_list)))

        self.pub_key_length_list.append(pub_key_length)
        self.cert_validatity_period_list.append(not_valid_after - not_valid_before)
        if not (not_valid_before <= ts <= not_valid_after):
            self.is_not_valid_cert_period = 1
        age_of_cert = float((ts - not_valid_before) / (not_valid_after - not_valid_before))
        self.age_of_cert_list.append(age_of_cert)
        if cert_serial not in self.cert_serial_list:
            self.cert_serial_list.append(cert_serial)
        self.is_sni_in_san_dns = 1 if ssl_server_name in san_dns_list else self.is_sni_in_san_dns
        for cn in cn_list:
            if cn in san_dns_list:
                self.is_cn_in_san_dns = 1

    def get_key(self):
        return self.key

    """
        conn_log
    """
    # 1. number of connections
    def number_of_connections(self):
        return len(self.conn_log_list)

    # 2. mean of duration
    def mean_of_duration(self):
        return statistics.mean(self.duration_list)

    # 3. stdev of duration
    def stdev_of_duration(self):
        if len(self.duration_list) > 1:
            return statistics.stdev(self.duration_list)
        else:
            return 0

    # 4. stdev range of duration
    def stdev_of_range_of_duration(self):
        size = len(self.duration_list)
        mean = self.mean_of_duration()
        stdev = self.stdev_of_duration()
        upper_limit = mean + stdev
        lower_limit = mean - stdev
        out_of_upper_limit_list = len(list(filter(lambda x: x>upper_limit, self.duration_list)))
        out_of_lower_limit_list = len(list(filter(lambda x: x<lower_limit, self.duration_list)))
        return float((out_of_lower_limit_list + out_of_upper_limit_list) / size)

    # 5. payload bytes from orig
    def payload_bytes_from_orig(self):
        return sum(self.orig_bytes_list)

    # 6. payload bytes from resp
    def payload_bytes_from_resp(self):
        return sum(self.resp_bytes_list)

    # 7. ratio of responder bytes
    def ratio_of_resp_bytes(self):
        if (self.payload_bytes_from_orig()+self.payload_bytes_from_resp()) == 0:
            return -1
        return float(self.payload_bytes_from_resp() / (self.payload_bytes_from_orig()+self.payload_bytes_from_resp()))

    # 8. Number of IP level bytes that the originator sent
    def ip_bytes_from_orig(self):
        return sum(self.orig_ip_bytes_list)

    # 9. Number of IP level bytes that the responder sent
    def ip_bytes_from_resp(self):
        return sum(self.resp_ip_bytes_list)

    # 10. ratio of responder bytes
    def ratio_of_resp_ip_bytes(self):
        if (self.ip_bytes_from_orig()+self.ip_bytes_from_resp()) == 0:
            return -1
        return float(self.ip_bytes_from_resp() / (self.ip_bytes_from_orig()+self.ip_bytes_from_resp()))

    # 11. ratio of established states of connection
    def ratio_of_established_states(self):
        established_stats = ['SF', 'S1', 'S2', 'S3', 'RSTO', 'RSTR']
        size = len(self.conn_state_list)
        num_of_established = len(list(filter(lambda x: x in established_stats, self.conn_state_list)))
        return float(num_of_established / size)

    # 12. the nubmer of inbound packet
    def number_of_resp_pkts(self):
        return sum(self.resp_pkts_list)

    # 13. the nubmer of outbound packet
    def number_of_orig_pkts(self):
        return sum(self.orig_pkts_list)

    def __get_periodicity_list(self):
        sorted_ts_list = sorted(self.ts_list)
        periodicity_list = []
        if len(sorted_ts_list) < 3:
            return None
        t1 = sorted_ts_list[0]
        t2 = sorted_ts_list[1]
        t3 = 0
        for ts in range(2, len(sorted_ts_list)):
            t3 = ts
            t2_t1 = t2 - t1
            t3_t2 = t3 - t2
            periodicity_list.append(abs(t3_t2 - t2_t1))
            t1 = t2
            t2 = t3
        return periodicity_list

    # 14. mean of periodicity
    def mean_of_periodicity(self):
        periodicity_list = self.__get_periodicity_list()
        if periodicity_list is None:
            return -1
        else:
            return statistics.mean(periodicity_list)

    # 15. stdev of periodicity
    def stdev_of_periodicity(self):
        periodicity_list = self.__get_periodicity_list()
        if periodicity_list is None:
            return -1
        elif len(periodicity_list) > 1:
            return statistics.stdev(periodicity_list)
        else:
            return 0


    """
        ssl_log
    """
    # 16. ratio of non-ssl to ssl
    def ratio_of_non_ssl_to_ssl(self):
        if self.number_of_ssl == 0:
            return -1
        return float(len(self.conn_log_list) / self.number_of_ssl)

    # 17. ratio of tls to tls+ssl about ssl version
    def ratio_of_tls(self):
        if self.number_of_ssl == 0:
            return -1
        return float(self.number_of_tls_version / self.number_of_ssl)

    # 18. ratio of sni to all ssl
    def ratio_of_sni(self):
        if self.number_of_ssl == 0:
            return -1
        return float(self.number_of_ssl_having_SNI / self.number_of_ssl)

    # 19. SNI as IP
    # SNI as IP
    # -1 : one of ssl has sni as ip but not same as dst ip
    # 0 : any ssl as sni as ip and same as dst ip
    # 1 : none of ssl has sni as ip
    def code_of_sni_as_ip(self):
        return self.sni_as_ip

    # 20. mean of the number of certificate in each ssl log
    def mean_of_certificate(self):
        if len(self.number_of_cert_list) == 0:
            return -1
        return statistics.mean(self.number_of_cert_list)

    # 21. ratio of ssl not verified
    def ratio_of_not_verified_cert(self):
        if self.number_of_ssl == 0:
            return -1
        not_verified_length = len(list(filter(lambda x: x != 'ok', self.validation_status_list)))
        return float(not_verified_length / self.number_of_ssl)

    """
        x509_log
    """
    # 22. mean of public_key_length
    def mean_of_pub_key_length(self):
        if len(self.pub_key_length_list) == 0:
            return -1
        return statistics.mean(self.pub_key_length_list)

    # 23. mean of cert validatity period
    def mean_of_cert_validatity_period(self):
        if len(self.cert_validatity_period_list) == 0:
            return -1
        return statistics.mean(self.cert_validatity_period_list)

    # 24. stdev of cert validatity period
    def stdev_of_cert_validatity_period(self):
        if len(self.cert_validatity_period_list) > 2:
            return statistics.stdev(self.cert_validatity_period_list)
        return -1

    # 25. validity of certificate period
    def validity_of_cert_period(self):
        return self.is_not_valid_cert_period

    # 26. mean of age of cert
    def mean_of_age_of_cert(self):
        if len(self.age_of_cert_list) == 0:
            return -1
        return statistics.mean(self.age_of_cert_list)

    # 27. amount of cert
    def number_of_cert(self):
        return len(self.cert_serial_list)

    # 28. sni in san dns
    def sni_in_san_dns(self):
        return self.is_sni_in_san_dns

    # 29. cn in san dns
    def cn_in_san_dns(self):
        return self.is_cn_in_san_dns

if __name__ == '__main__':
    for i in range(2,3):
        print(i)