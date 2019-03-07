top_level_domain_list = []
root_cert_list = []

def read_tld_file():
    with open('./top_level_domain') as file:
        for line in file:
            if line[0] == '#':
                continue
            top_level_domain_list.append(line.rstrip())

def read_root_cert_list():
    with open('./trusted_root_certificates') as file:
        for line in file:
            if line[0] == '#':
                continue
            root_cert_list.append(line.rstrip())

def get_tld_list():
    if len(top_level_domain_list) == 0:
        read_tld_file()
    return top_level_domain_list

def get_root_cert_list():
    if len(root_cert_list) == 0:
        read_root_cert_list()
    return root_cert_list
