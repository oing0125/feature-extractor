class CertificationFeatures:

    def __init__(self):

        self.the_number_of_x509_log = 0
        self.the_number_of_not_valid_cert = 0
        self.server_name_dict = dict()
        self.cert_percent_validity = list()

    def add_server_name(self, server_name):
        self.server_name_dict[server_name] = 1

    def add_x509_info(self, x509_log):
        ts = x509_log['ts']
        not_valid_before = x509_log['certificate.not_valid_before']
        not_valid_after = x509_log['certificate.not_valid_after']
        if not_valid_after != '-' and not_valid_before != '-':
            if ts > not_valid_after or ts < not_valid_before:
                self.the_number_of_not_valid_cert += 1
            norm_after = not_valid_after - not_valid_before
            current_time_norm = ts - not_valid_before
            self.cert_percent_validity.append(current_time_norm / norm_after)
            self.the_number_of_x509_log += 1