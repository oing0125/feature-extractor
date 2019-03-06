import statistics

class Connection4tuple():

    def __init__(self, tuple_index):

        # 1. basic information
        self.tuple_index = tuple_index
        self.label = ''
        self.ssl_log_list = []
        self.x509_log_list = []
        self.ssl_flow_list = []
        self.not_ssl_flow_list = []

        # flow information
        self.total_duration = 0
        self.orig_packets = 0
        self.resp_packets = 0
        self.total_size_of_flows_ip_orig = 0
        self.total_size_of_flows_ip_resp = 0
        self.total_size_of_flows_resp = 0
        self.total_size_of_flows_orig = 0
        self.duration_list = []
        self.uid_flow_dict = dict()
        self.state_of_connection_dict = dict()

        # x509 information
        self.the_number_of_not_valid_cert = 0
        self.certificate_valid_length = 0
        self.certificate_valid_length_pow = 0
        self.the_number_of_certificate_valid = 0
        self.the_number_of_san_domains = 0
        self.the_number_of_san_domains_index = 0
        self.certificate_key_length_dict = dict()
        self.certificate_serial_dict = dict()
        self.cert_percent_validity = list()
        self.san_x509_list = list()
        self.subject_x509_list = list()
        self.issuer_x509_list = list()
        self.cert_exponent_x509_list = list()
        self.is_CN_in_SAN_list = list()
        self.is_SNI_in_san_dns = list()

# ==========================================================

        # # 3. statistical feature
        # # 3.1) duration
        # self.mean_of_duration = 0
        # self.sd_range_of_duration = 0
        # self.flow_which_has_duration_number = 0
        # self.datsets_names_list = []
        #
        # # 3.2) Connection Features
        # self.number_of_ssl_flows = 0
        # self.number_of_not_ssl_flows = 0
        # self.number_of_ssl_logs = 0
        #
        # # 3.3) flow_log features
        # self.the_number_of_inbound_packets = 0
        # self.inbound_packets = 0
        # self.inbound_ip_packets = 0
        # self.the_number_of_outbound_packets = 0
        # self.outbound_packets = 0
        # self.outbound_ip_packets = 0
        #
        # # 3.4) ssl_log
        # self.version_of_ssl_dict = dict()
        # self.version_of_ssl_cipher_dict = dict()
        # self.certificate_path = dict()
        # self.ssl_uids_list = []
        # self.ssl_with_SNI = 0
        # self.self_signed_cert = 0
        # self.SNI_equal_DstIP = 0
        # self.SNI_list = []
        # self.subject_ssl_list = []
        # self.issuer_ssl_list = []
        # self.top_level_domain_error = 0
        # self.certificate_path_error = 0
        # self.missing_cert_in_cert_path = 0
        # self.ssl_with_certificate = 0
        # self.ssl_without_certificate = 0
        #
        # # 3.5) X509 features
        # self.certificate_key_type_dict = dict()
        # self.certificate_key_length_dict = dict()
        # self.certificate_serial_dict = dict()
        # self.certificate_valid_length = 0
        # self.certificate_valid_length_pow = 0
        # self.certificate_valid_number = 0
        # self.not_valid_certificate_number = 0
        # self.number_san_domains = 0
        # self.number_san_domains_index = 0
        # self.cert_percent_validity = []
        # self.is_CN_in_SAN_list = []
        # self.is_SNI_in_san_dns = []
        # self.subject_x509_list = []
        # self.issuer_x509_list = []
        # self.san_x509_list = []
        # self.certificate_exponent = 0
        # self.temp_list = []
        # self.founded_root_certificate = 0
        # self.not_founded_root_certificate = 0
        #
        # # 3.6) Compare SSL and x509 features
        # self.subject_diff = 0
        # self.issuer_diff = 0
        # self.SNI_is_in_CN = 0

        # Function
        # Read top level domain file.
        # self.top_level_domain = []
        # self.read_top_level_domain_file()

    def add_ssl_flow(self, flow_log):
        self.ssl_flow_list.append(flow_log)
        self.add_flow.append(flow_log)

    def add_not_ssl_flow(self, flow_log):
        self.not_ssl_flow_list.append(flow_log)
        self.add_flow(flow_log)

    def add_flow(self, flow_log):
        uid = flow_log['uid']
        state = flow_log['conn_state']
        duration = flow_log['duration']
        orig_bytes = flow_log['orig_bytes']
        resp_bytes = flow_log['resp_bytes']
        orig_pkts = flow_log['orig_pkts']
        resp_pkts = flow_log['resp_pkts']
        orig_ip_bytes = flow_log['orig_ip_bytes']
        resp_ip_bytes = flow_log['resp_ip_bytes']
        if uid in self.uid_conn_dict:
            self.uid_conn_dict[uid] += 1
        else:
            self.uid_conn_dict[uid] = 1
        if state in self.state_of_connection_dict:
            self.state_of_connection_dict[state] += 1
        else:
            self.state_of_connection_dict[state] = 1
        if orig_bytes != '-':
            self.total_size_of_flows_orig += int(orig_bytes)
        if resp_bytes != '-':
            self.total_size_of_flows_resp += int(resp_bytes)
        self.duration_list.append(float(duration))
        self.total_duration += float(duration)
        self.total_size_of_flows_ip_orig += int(orig_ip_bytes)
        self.total_size_of_flows_ip_resp += int(resp_ip_bytes)
        self.resp_packets += int(resp_pkts)
        self.orig_packets += int(orig_pkts)

    def add_ssl_log(self, ssl_log, x509_log):
        self.add_x509_log(x509_log)
        self.is_SNI_in_cert(ssl_log, x509_log)
        self.compare_ssl_and_x509(ssl_log, x509_log)

    def add_x509_log(self, x509_log):
        ts = x509_log['ts']
        not_valid_before = x509_log['certificate.not_valid_before']
        not_valid_after = x509_log['certificate.not_valid_after']
        CN_part = x509_log['certificate.subject']
        cert_serial = x509_log['certificate.serial']
        cert_key_length = x509_log['certificate.key_length']
        cert_issuer = x509_log['certificate.issuer']
        cert_exponent = x509_log['certificate.exponent']

        self.x509_log_list.append(x509_log)
        self.subject_x509_list.append(CN_part)

        # is SNI in san dns
        if x509_log['san.dns'] != '-':
            SAN_dns_list = x509_log['san.dns']
            SAN_dns_list = list(lambda x: x.replace('*', ''), SAN_dns_list)
            hit_2 = 0
            for san_dns in SAN_dns_list:
                if san_dns in CN_part:
                    hit_2 = 1
                    break
            self.is_CN_in_SAN_list.append(hit_2)


        if not_valid_after != '-' and not_valid_before != '-':
            if ts > not_valid_after or ts < not_valid_before:
                self.the_number_of_not_valid_cert += 1
            norm_after = not_valid_after - not_valid_before
            current_time_norm = ts - not_valid_before
            self.cert_percent_validity.append(current_time_norm / norm_after)

        if cert_serial not in self.certificate_serial_dict:
            self.certificate_serial_dict[cert_serial] = 1

            if cert_key_length != '-':
                if cert_key_length in self.certificate_key_length_dict:
                    self.certificate_key_length_dict[cert_key_length] += 1
                else:
                    self.certificate_key_length_dict[cert_key_length] = 1

            if not_valid_after != '-' and not_valid_before != '-':
                valid_length_sec = float(not_valid_after) - float(not_valid_before)
                valid_length_days_not_round = int((valid_length_sec / (3600.0 * 24.0)))
                valid_length_days = round(valid_length_days_not_round, 2)
                self.certificate_valid_length += valid_length_days
                self.certificate_valid_length_pow += pow(valid_length_days, 2)
                self.the_number_of_certificate_valid += 1

            if x509_log['san.dns'] != '-':
                san_dns_list = x509_log['san.dns'].split(',')
                self.the_number_of_san_domains += len(san_dns_list)
                self.the_number_of_san_domains_index += 1
                self.san_x509_list.append(x509_log['san.dns'])

            if CN_part != '-':
                self.subject_x509_list.append(CN_part)

            if cert_issuer != '-':
                self.issuer_x509_list.append(cert_issuer)

            if cert_exponent != '':
                self.cert_exponent_x509_list.append(cert_exponent)
        else:
            self.certificate_serial_dict[cert_serial] += 1

    def is_SNI_in_cert(self, ssl_log, x509_log):
        server_name = ssl_log['server_name']
        san_dns_origin = x509_log['san.dns']
        if server_name != '-' and san_dns_origin != '-':
            SAN_dns_list = san_dns_origin.split(',')
            hit = 0
            for san_dns in SAN_dns_list:
                if san_dns.replace('*','') in server_name:
                    hit = 1
                    break
            self.is_SNI_in_san_dns.append(hit)

    def compare_ssl_and_x509(self, ssl_log, x509_log):
        # TODO 0306 gogosing~
        print('will do')

    def calculate_statistical_feature(self):
        # 1. Number of Flow
        self.the_number_of_flow = len(self.non_ssl_flow_list + self.ssl_flow_list)

        # 2. Mean of duration
        duration_list_size = len(self.duration_list)
        self.avg_duration = sum(self.duration_list) / float(duration_list_size)

        # 3. standard deviation of duration
        self.stdev_duration = statistics.stdev(self.duration_list) if len(self.duration_list) > 1 else 0

        # 4. standard deviation range of duration
        upper_limit = self.avg_duration + self.stdev_duration
        lower_limit = self.avg_duration - self.stdev_duration
        upper_out_range_of_duration = len(list(filter(lambda x : x > upper_limit, self.duration_list)))
        lower_out_range_of_duration = len(list(filter(lambda x : x < lower_limit, self.duration_list)))
        self.stdev_range_of_duration = float((upper_out_range_of_duration + lower_out_range_of_duration) / duration_list_size)

        # 5. payload bytes from originater (already calculated)
        # self.total_size_of_flows_orig

        # 6. payload bytes from responder (already calculated)
        # self.total_size_of_flows_resp

        # 7. Ratio of responder bytes and all bytes
        self.ratio_of_inbound_bytes = float(self.inbound_packets / (self.inbound_packets + self.outbound_packets))

        # 8. Ratio of established state of connection
        established_states = ['SF', 'S1', 'S2', 'S3', 'RSTO', 'RSTR']
        non_established_states = ['OTH', 'SO', 'REJ', 'SH', 'SHR', 'RSTOS0', 'RSTRH']
        the_number_of_established = 0
        the_number_of_non_established = 0
        for key in self.state_of_connection_dict:
            if key in established_states:
                the_number_of_established += self.state_of_connection_dict[key]
            elif key in non_established_states:
                the_number_of_non_established += self.state_of_connection_dict[key]
            else:
                print('[error] established states is unknown')
                raise RuntimeError
        self.ratio_of_established_state = float(the_number_of_established / (the_number_of_established + the_number_of_non_established))

        # 9. Inbound Packets Number
        # self.the_number_of_inbound_packets

        # 10. Inbound Packets Number
        # self.the_number_of_outbound_packets

        # 11. Periodicity mean
        # 12. Standard Deviation of Periodicity
        self.periodicity_mean, self.periodicity_stdev = self.get_periodicity_list()

    def get_periodicity_list(self):
        flow_list = self.ssl_flow_list + self.non_ssl_flow_list
        ts_list = map(lambda x : x['ts'], flow_list)
        sorted_ts_list = sorted(ts_list)
        T2_1 = None
        T2_2 = None
        T3 = None
        last_flow = None
        time_diff_list = []
        for ts in sorted_ts_list:
            if last_flow == None:
                last_flow = ts
                continue
            if T2_1 == None:
                t2_1 = ts - last_flow
                last_flow = ts
                continue
            T2_2 = ts - last_flow
            T3 = abs(T2_2 - T2_1)
            T2_1 = T2_2
            last_flow = ts
            time_diff_list.append(T3)
        mean = None
        stdev = None
        try:
            mean = float(sum(time_diff_list) / len(time_diff_list)) if len(time_diff_list) != 0 else 0
            stdev = statistics.stdev(time_diff_list) if len(time_diff_list) > 1 else 0
        except:
            print('error')
        return mean, stdev

    def get_features(self):
        feature = {
            'the_number_of_flows' : self.the_number_of_flow
            , 'avg_of_duration' : self.avg_duration
            , 'stdev_duration' : self.stdev_duration
            , 'stdev_range_of_duration' : self.stdev_range_of_duration
            , 'total_size_of_flows_orig' : self.total_size_of_flows_orig
            , 'total_size_of_flows_resp' : self.total_size_of_flows_resp
            , 'ratio_of_sizes' : self.ratio_of_inbound_bytes
            , 'ratio_of_established_states' : self.ratio_of_established_state
            , 'inbound_packets' : self.inbound_packets
            , 'outbound_packets' : self.outbound_packets
            , 'avg_periodicity' : self.periodicity_mean
            , 'stdev_periodicity' : self.periodicity_stdev
        }
        return feature


if __name__ == '__main__':
    l1 = [{'a':1,'b':2},{'a':3,'b':4}]
    l2 = [1,3,4,5,6,78,11]
    print(statistics.mean(l2))
