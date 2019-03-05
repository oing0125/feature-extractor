

class Connection4tuple():

    def __init__(self, tuple_index):

        # 1. basic information
        self.tuple_index = tuple_index
        self.label = ''

        # 2. list of logs(conn, ssl, x509)
        self.conn_log_list = []
        self.ssl_log_list = []
        self.x509_log_list = []
        ## TODO : DO we need distinguish from between ssl and non-ssl


        # 3. statistical feature
        # 3.1) duration
        self.average_duration_power = 0
        self.flow_which_has_duration_number = 0
        self.duration_list = []
        self.datsets_names_list = []

        # 3.2) Connection Features
        self.number_of_ssl_flows = 0
        self.number_of_not_ssl_flows = 0
        self.number_of_ssl_logs = 0
        self.total_size_of_flows_resp = 0
        self.total_size_of_flows_orig = 0
        self.average_duration = 0

        # 3.3) Flow features
        self.state_of_connection_dict = dict()
        self.inbound_packtes = 0
        self.outbound_packtes = 0

        # 3.4) SSL flows
        self.version_of_ssl_dict = dict()
        self.version_of_ssl_cipher_dict = dict()
        self.certificate_path = dict()
        self.ssl_uids_list = []
        self.ssl_with_SNI = 0
        self.self_signed_cert = 0
        self.SNI_equal_DstIP = 0
        self.SNI_list = []
        self.subject_ssl_list = []
        self.issuer_ssl_list = []
        self.top_level_domain_error = 0
        self.certificate_path_error = 0
        self.missing_cert_in_cert_path = 0
        self.ssl_with_certificate = 0
        self.ssl_without_certificate = 0

        # 3.5) X509 features
        self.certificate_key_type_dict = dict()
        self.certificate_key_length_dict = dict()
        self.certificate_serial_dict = dict()
        self.certificate_valid_length = 0
        self.certificate_valid_length_pow = 0
        self.certificate_valid_number = 0
        self.not_valid_certificate_number = 0
        self.number_san_domains = 0
        self.number_san_domains_index = 0
        self.cert_percent_validity = []
        self.is_CN_in_SAN_list = []
        self.is_SNI_in_san_dns = []
        self.subject_x509_list = []
        self.issuer_x509_list = []
        self.san_x509_list = []
        self.certificate_exponent = 0
        self.temp_list = []
        self.founded_root_certificate = 0
        self.not_founded_root_certificate = 0

        # 3.6) Compare SSL and x509 features
        self.subject_diff = 0
        self.issuer_diff = 0
        self.SNI_is_in_CN = 0

        # Function
        # Read top level domain file.
        self.top_level_domain = []
        self.read_top_level_domain_file()


    def add_ssl_flow(self, flow, label):
        self.ssl_flow_list.append(flow)
        self.compute_classic_features(flow)

    def add_not_ssl_flow(self, flow, label):
        self.not_ssl_flow_list.append(flow)
        self.compute_classic_features(flow)

    def add_ssl_log(self, ssl_log, valid_x509_list, dataset_name):
        for i in range(0, len(valid_x509_list)):
            # print valid_x509_list[i]
            self.compute_x509_features(valid_x509_list[i])
            # Feature 28: is SAN DNS part of SNI ?
            self.is_SNI_in_certificate(ssl_log, valid_x509_list[i])
            # Compare
            self.compare_ssl_and_x509_lines(ssl_log, valid_x509_list[i])

        # compute ssl log
        self.compute_ssl_features(ssl_log)

        # add datasetname of this flow
        if not (dataset_name in self.datsets_names_list):
            self.datsets_names_list.append(dataset_name)

    def add_ssl_log_2(self, valid_x509_line):
        self.compute_x509_features(valid_x509_line)