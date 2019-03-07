import statistics
import socket
import CommonUtil

class Connection4tuple():

    def __init__(self, tuple_index):

        # 1. basic information
        self.tuple_index = tuple_index
        self.label = ''
        self.ssl_log_list = []
        self.x509_log_list = []
        self.ssl_flow_list = []
        self.not_ssl_flow_list = []
        self.ssl_uid_list = []

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
        self.subject_diff = 0
        self.issuer_diff = 0
        self.SNI_is_in_CN = 0
        self.ssl_with_cert = 0
        self.ssl_without_cert = 0
        self.ssl_with_SNI = 0
        self.SNI_equal_DstIP = 0
        self.top_level_domain_error = 0
        self.missing_cert_in_cert_path = 0
        self.certificate_path_error = 0
        self.founded_root_certificate = 0
        self.not_founded_root_certificate = 0
        self.certificate_key_length_dict = dict()
        self.version_of_ssl_dict = dict()
        self.version_of_ssl_cipher_dict = dict()
        self.certificate_serial_dict = dict()
        self.certificate_path_length_dict = dict()
        self.cert_percent_validity = list()
        self.san_x509_list = list()
        self.subject_x509_list = list()
        self.issuer_x509_list = list()
        self.cert_exponent_x509_list = list()
        self.CN_hit_in_SAN_list = list()
        self.SNI_hit_in_san_dns = list()
        self.SNI_list = list()
        self.subject_ssl_list = list()
        self.issuer_ssl_list = list()

        self.top_level_domain_list = CommonUtil.get_tld_list()


    def add_ssl_flow(self, flow_log):
        self.ssl_flow_list.append(flow_log)
        self.add_flow(flow_log)

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
        if uid in self.uid_flow_dict:
            self.uid_flow_dict[uid] += 1
        else:
            self.uid_flow_dict[uid] = 1
        if state in self.state_of_connection_dict:
            self.state_of_connection_dict[state] += 1
        else:
            self.state_of_connection_dict[state] = 1
        if orig_bytes != '-':
            self.total_size_of_flows_orig += int(orig_bytes)
        if resp_bytes != '-':
            self.total_size_of_flows_resp += int(resp_bytes)
        self.duration_list.append(float(duration) if duration != '-' else 0)
        self.total_duration += float(duration) if duration != '-' else 0
        self.total_size_of_flows_ip_orig += int(orig_ip_bytes)
        self.total_size_of_flows_ip_resp += int(resp_ip_bytes)
        self.resp_packets += int(resp_pkts)
        self.orig_packets += int(orig_pkts)

    def add_ssl_log(self, ssl_log, x509_log):
        self.add_x509_log(x509_log)
        self.is_SNI_in_cert(ssl_log, x509_log)
        self.compare_ssl_and_x509(ssl_log, x509_log)
        self.compute_ssl_feature(ssl_log)

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
            SAN_dns_list = x509_log['san.dns'].split(',')
            hit_2 = 0
            for san_dns in SAN_dns_list:
                if san_dns.replace('*','')  in CN_part:
                    hit_2 = 1
                    break
            self.CN_hit_in_SAN_list.append(hit_2)


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
            self.SNI_hit_in_san_dns.append(hit)

    def compare_ssl_and_x509(self, ssl_log, x509_log):
        ssl_subject = ssl_log['subject']
        x509_subject = x509_log['certificate.subject']

        if ssl_subject != x509_subject:
            self.subject_diff += 1

        ssl_issuer = ssl_log['issuer']
        x509_issuer = x509_log['certificate.issuer']
        if ssl_issuer != x509_issuer:
            self.issuer_diff += 1

        server_name = ssl_log['server_name']
        CN = x509_log['certificate.subject']
        if server_name in CN:
            self.SNI_is_in_CN += 1

    def compute_ssl_feature(self, ssl_log):
        ssl_uid = ssl_log['uid']
        version_of_ssl = ssl_log['version']
        version_of_ssl_cipher = ssl_log['cipher']
        cert_path = ssl_log['cert_chain_fuids']
        server_name = ssl_log['server_name']
        subject = ssl_log['subject']
        issuer = ssl_log['issuer']

        self.ssl_log_list.append(ssl_log)
        self.ssl_uid_list.append(ssl_uid)
        if version_of_ssl in self.version_of_ssl_dict:
            self.version_of_ssl_dict[version_of_ssl] += 1
        else:
            self.version_of_ssl_dict[version_of_ssl] = 1
        if version_of_ssl_cipher in self.version_of_ssl_cipher_dict:
            self.version_of_ssl_cipher_dict[version_of_ssl_cipher] += 1
        else:
            self.version_of_ssl_cipher_dict[version_of_ssl_cipher] = 1

        if cert_path != '-':
            self.ssl_with_cert += 1
            x509_uid_list = cert_path.split(',')
            x509_uid_list_size = len(x509_uid_list)
            if x509_uid_list_size in self.certificate_path_length_dict:
                self.certificate_path_length_dict[x509_uid_list_size] += 1
            else:
                self.certificate_path_length_dict[x509_uid_list_size] = 1
        else:
            self.ssl_without_cert += 1

        if server_name != '-':
            self.ssl_with_SNI += 1
            self.SNI_list.append(server_name)
            try:
                socket.inet_aton(server_name)
                if self.SNI_equal_DstIP != -1:
                    dst_ip = self.tuple_index[1]
                    if dst_ip != server_name:
                        self.SNI_equal_DstIP = -1
                    else:
                        self.SNI_equal_DstIP = 1
            except:
                # tld = Top Level Domain
                is_tld = False
                for tld in self.top_level_domain_list:
                    if tld.lower() in server_name:
                        is_tld = True
                        break
                if is_tld is False:
                    self.top_level_domain_error += 1

        # TODO how can i figure out whether it is self-signed-cert??

        if subject != '-':
            self.subject_ssl_list.append(subject)
        if issuer != '-':
            self.issuer_ssl_list.append(issuer)

    def check_certificate_path(self, x509_log_list, is_found):
        if is_found:
            issuer = None
            for x509_log in x509_log_list:
                if issuer is not None:
                    x509_subject = x509_log['certificate.subject']
                    if x509_subject != issuer:
                        self.certificate_path_error += 1
                issuer = x509_log['certificate.issuer']
        else:
            self.missing_cert_in_cert_path += 1

    def check_root_certificate(self, x509_log_list):
        is_found = False

        for x509_log in x509_log_list:
            cert_subject = x509_log['certificate.subject']
            san_dns = x509_log['san.dns']
            for serial in CommonUtil.get_root_cert_list():
                if serial in cert_subject or serial in san_dns:
                    is_found = True
                    break
            if is_found:
                break;
        if is_found:
            self.founded_root_certificate += 1
        else:
            self.not_founded_root_certificate += 1

    def calculate_statistical_feature(self):
        # 1. Number of Flow
        self.the_number_of_flow = len(self.not_ssl_flow_list + self.ssl_flow_list)

        # 2. Mean of duration
        duration_list_size = len(self.duration_list)
        self.avg_duration = sum(self.duration_list) / float(duration_list_size)

        # 3. standard deviation of duration
        self.stdev_duration = statistics.stdev(self.duration_list) if len(self.duration_list) > 1 else -1

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
        sum_of_total_bytes = (self.total_size_of_flows_resp + self.total_size_of_flows_orig)
        if sum_of_total_bytes is not 0:
            self.ratio_of_inbound_bytes = float(self.total_size_of_flows_resp / (self.total_size_of_flows_resp + self.total_size_of_flows_orig))
        else:
            self.ratio_of_inbound_bytes = 0

        # 8. Ratio of established state of connection
        established_states = ['SF', 'S1', 'S2', 'S3', 'RSTO', 'RSTR']
        non_established_states = ['OTH', 'S0', 'REJ', 'SH', 'SHR', 'RSTOS0', 'RSTRH']
        the_number_of_established = 0
        the_number_of_non_established = 0
        for key in self.state_of_connection_dict:
            if key in established_states:
                the_number_of_established += self.state_of_connection_dict[key]
            elif key in non_established_states:
                the_number_of_non_established += self.state_of_connection_dict[key]
            else:
                print('[error] established states is unknown - {}'.format(key))
                raise RuntimeError
        self.ratio_of_established_state = float(the_number_of_established / (the_number_of_established + the_number_of_non_established))

        # 9. Inbound Packets Number
        # self.the_number_of_inbound_packets

        # 10. Inbound Packets Number
        # self.the_number_of_outbound_packets

        # 11. Periodicity mean
        # 12. Standard Deviation of Periodicity
        self.periodicity_mean, self.periodicity_stdev = self.get_periodicity_list()

        # 13. ratio of not ssl flows and ssl flows
        self.ratio_of_not_ssl = len(self.not_ssl_flow_list) / float(len(self.ssl_flow_list))

        # 14. avg public key length
        total = 0
        index = 0
        for key in self.certificate_key_length_dict:
            total += self.certificate_key_length_dict[key] * int(key)
            index += 1
        if index != 0:
            self.avg_public_key = total / float(index)
        else:
            self.avg_public_key = -1

        # 15. ratio of tls version
        tls = 0
        ssl = 0
        total = 0
        for key in self.version_of_ssl_dict:
            if 'tls' in key.lower():
                tls += self.version_of_ssl_dict[key]
            elif 'ssl' in key.lower():
                ssl += self.version_of_ssl_dict[key]
            total += self.version_of_ssl_dict[key]
        if total != 0:
            self.ratio_of_tls_version = tls / float(total)
        else:
            self.ratio_of_tls_version = -1

        # 16. avg_of_cert_length
        if self.the_number_of_certificate_valid != 0:
            self.avg_cert_length = self.certificate_valid_length / float(self.the_number_of_certificate_valid)
        else:
            self.avg_cert_length = -1

        # 17. stdev_cert_length
        if self.the_number_of_certificate_valid != 0:
            EX = self.certificate_valid_length / self.the_number_of_certificate_valid
            EX2 = self.certificate_valid_length_pow / self.the_number_of_certificate_valid
            DX = EX2 - (EX ** 2)
            self.stdev_cert_length = pow(DX, 0.5)
        else:
            self.stdev_cert_length = -1

        # 18. is_valid_cert_during_capture
        # self.the_number_of_not_valid_cert

        # 19. subject_diff
        # self.subject_diff

        # 20. issuer_diff
        # self.issuer_diff

        # 21. ratio of SNI
        self.ratio_of_SNI = self.ssl_with_SNI / float(len(self.ssl_log_list)) if len(self.cert_percent_validity) > 1 else -1

        # 22. SNI as IP(0: not ip / 1: servername == sni / -1: servername != sni
        # self.SNI_equal_DstIP

        # 23. mean of certificate validatity period
        self.avg_of_cert_validatity_period = statistics.mean(self.cert_percent_validity) if len(self.cert_percent_validity) > 1 else -1

        # 24. stdev of cert validatity period
        self.stdev_of_cert_validatity_period = statistics.stdev(self.cert_percent_validity) if len(self.cert_percent_validity) > 1 else -1

        # 25. number of cert path
        up = 0
        down = 0
        for key in self.certificate_path_length_dict:
            up += int(key) * self.certificate_path_length_dict[key]
            down += self.certificate_path_length_dict[key]
        if down != 0:
            self.the_number_of_cert_path = up / float(down)
        else:
            self.the_number_of_cert_path = -1

        # 26. is there any sni?
        if len(self.SNI_hit_in_san_dns) != 0:
            value = 1
            for sni_hit in self.SNI_hit_in_san_dns:
                if sni_hit == 0:
                    value = 0
                    break
            self.is_SNI_in_san_dns = value
        else:
            self.is_SNI_in_san_dns = -1

        # 27. is there any cn not in san.dns?
        if len(self.CN_hit_in_SAN_list) != 0:
            value = 1
            for cn_hit in self.CN_hit_in_SAN_list:
                if cn_hit == 0:
                    value = 0
                    break
            self.is_CN_in_san_dns = value
        else:
            self.is_CN_in_san_dns = -1

    def get_periodicity_list(self):
        flow_list = self.ssl_flow_list + self.not_ssl_flow_list
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
            mean = float(sum(time_diff_list) / len(time_diff_list)) if len(time_diff_list) != 0 else -1
            stdev = statistics.stdev(time_diff_list) if len(time_diff_list) > 1 else -1
        except:
            print('error')
        return mean, stdev

    def get_features(self):
        self.calculate_statistical_feature()
        feature = {
            'the_number_of_flows' : self.the_number_of_flow
            , 'avg_of_duration' : self.avg_duration
            , 'stdev_duration' : self.stdev_duration
            , 'stdev_range_of_duration' : self.stdev_range_of_duration
            , 'total_size_of_flows_orig' : self.total_size_of_flows_orig
            , 'total_size_of_flows_resp' : self.total_size_of_flows_resp
            , 'ratio_of_sizes' : self.ratio_of_inbound_bytes
            , 'ratio_of_established_states' : self.ratio_of_established_state
            , 'inbound_packets' : self.resp_packets
            , 'outbound_packets' : self.orig_packets
            , 'avg_periodicity' : self.periodicity_mean
            , 'stdev_periodicity' : self.periodicity_stdev
            , 'ratio_of_not_ssl' : self.ratio_of_not_ssl
            , 'avg_public_key_length' : self.avg_public_key
            , 'ratio_of_tls_version' : self.ratio_of_tls_version
            , 'avg_of_cert_length' : self.avg_cert_length
            , 'stdev_cert_length' : self.stdev_cert_length
            , 'the_number_of_not_valid_cert' : self.the_number_of_not_valid_cert
            , 'subject_diff' : self.subject_diff
            , 'isser_diff' : self.issuer_diff
            , 'ratio_of_sni' : self.ratio_of_SNI
            , 'sni_as_ip' : self.SNI_equal_DstIP
            , 'avg_of_cert_validatity_period' : self.avg_of_cert_validatity_period
            , 'stdev_of_cert_validatity_period' : self.stdev_of_cert_validatity_period
            , 'the_nubmer_of_cert_path' : self.the_number_of_cert_path
            , 'is_SNI_in_san_dns' : self.is_SNI_in_san_dns
            , 'is_CN_in_san_dns' : self.is_CN_in_san_dns
        }
        return feature


if __name__ == '__main__':
    feature = {
        'the_number_of_flows': 'the_number_of_flow' ,'avg_of_duration': 'avg_duration' ,'stdev_duration': 'stdev_duration' ,'stdev_range_of_duration': 'stdev_range_of_duration' ,'total_size_of_flows_orig': 'total_size_of_flows_orig' ,'total_size_of_flows_resp': 'total_size_of_flows_resp' ,'ratio_of_sizes': 'ratio_of_inbound_bytes' ,'ratio_of_established_states': 'ratio_of_established_state' ,'inbound_packets': 'resp_packets' ,'outbound_packets': 'orig_packets' ,'avg_periodicity': 'periodicity_mean' ,'stdev_periodicity': 'periodicity_stdev' ,'ratio_of_not_ssl': 'ratio_of_not_ssl' ,'avg_public_key_length': 'avg_public_key' ,'ratio_of_tls_version': 'ratio_of_tls_version' ,'avg_of_cert_length': 'avg_cert_length' ,'stdev_cert_length': 'stdev_cert_length' ,'the_number_of_not_valid_cert': 'the_number_of_not_valid_cert' ,'subject_diff': 'subject_diff' ,'isser_diff': 'issuer_diff' ,'ratio_of_sni': 'ratio_of_SNI' ,'sni_as_ip': 'SNI_equal_DstIP' ,'avg_of_cert_validatity_period': 'avg_of_cert_validatity_period' ,'stdev_of_cert_validatity_period': 'stdev_of_cert_validatity_period' ,'the_nubmer_of_cert_path': 'the_number_of_cert_path' ,'is_SNI_in_san_dns': 'is_SNI_in_san_dns' ,'is_CN_in_san_dns': 'is_CN_in_san_dns'
    }
    for key in feature:
        print('"{}",'.format(key))

