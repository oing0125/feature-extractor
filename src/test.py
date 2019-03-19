from FeatureExtractor import FeatureExtractor
import pickle
import pandas as pd
import os

def parsing_datas(path, infected_ip_list = []):
    fe = FeatureExtractor(path)
    fe.prepare_data()
    list = fe.get_features_list()
    pdBenignDataList = pd.DataFrame.from_records(list)
    pdBenignDataList['is_malware'] = 0
    for infected_ip in infected_ip_list:
        pdBenignDataList[pdBenignDataList['src_ip'] == infected_ip] = 1
    pdBenignDataList.to_pickle(path + '/datas.pkl')

def parsing_all_benign():
    benign_path = '/home/sdsra/Downloads/CTU-13-Dataset/benign'
    benign_dir_list = os.listdir(benign_path)
    benign_datas = []
    for benign_dir in benign_dir_list:
        trgt_benign_dir = benign_path + '/' + benign_dir
        if os.path.isdir(trgt_benign_dir):
            fe = FeatureExtractor(trgt_benign_dir)
            fe.prepare_data()
            generated_datas = fe.get_features_list()
            benign_datas = benign_datas + generated_datas

    fe = FeatureExtractor('/home/sdsra/Downloads/Dataset/benign-capture')
    fe.prepare_data()
    generated_datas = fe.get_features_list()
    benign_datas = benign_datas + generated_datas

    tmpList = []
    for i in range(0, len(benign_datas)):
        tmpList.append(benign_datas[i])
        if i != 0 and i % 100000 == 0:
            pdBenignDataList = pd.DataFrame.from_records(tmpList)
            pdBenignDataList.to_pickle(benign_path + '/datas-{}.pkl'.format(str(i % 100000)))
            tmpList = []
    pdBenignDataList = pd.DataFrame.from_records(tmpList)
    pdBenignDataList.to_pickle(benign_path + '/datas-final.pkl')
    # with open(benign_2017_4_30_normal) as fr:
    #     fr.
    # pasing_datas(malware_9['path'], malware_9['infected_ip_list'])

def parsing_all_malware():
    malware_dir_list = [
        {'dir_name': '1', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '2', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '3', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '4', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '5', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '6', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '7', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '8', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '9', 'infected_ip': ['147.32.84.165','147.32.84.191','147.32.84.192','147.32.84.193','147.32.84.204','147.32.84.205','147.32.84.206','147.32.84.207','147.32.84.208','147.32.84.209']}
        , {'dir_name': '10', 'infected_ip': ['147.32.84.165','147.32.84.191','147.32.84.192','147.32.84.193','147.32.84.204','147.32.84.205','147.32.84.206','147.32.84.207','147.32.84.208','147.32.84.209']}
        , {'dir_name': '11', 'infected_ip': ['147.32.84.165', '147.32.84.191','147.32.84.192']}
        , {'dir_name': '12', 'infected_ip': ['147.32.84.165', '147.32.84.191','147.32.84.192']}
        , {'dir_name': '13', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '42', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '43', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '44', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '45', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '46', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '47', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '48', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '49', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '50', 'infected_ip': ['147.32.84.165','147.32.84.191','147.32.84.192','147.32.84.193','147.32.84.204','147.32.84.205','147.32.84.206','147.32.84.207','147.32.84.208','147.32.84.209']}
        , {'dir_name': '52', 'infected_ip': ['147.32.84.165', '147.32.84.191','147.32.84.192']}
        , {'dir_name': '53', 'infected_ip': ['147.32.84.165', '147.32.84.191','147.32.84.192']}
        , {'dir_name': '54', 'infected_ip': ['147.32.84.165']}
        , {'dir_name': '78-2', 'infected_ip': ['10.0.2.108']}
        , {'dir_name': '122', 'infected_ip': ['10.0.2.106']}
        , {'dir_name': '196', 'infected_ip': ['192.168.1.119']}

    ]
    malware_path = '/home/sdsra/Downloads/CTU-13-Dataset/malware'
    for malware_dir in malware_dir_list:
        trgt_malware_dir = malware_path + '/' + malware_dir['dir_name']
        if os.path.isdir(trgt_malware_dir):
            fe = FeatureExtractor(trgt_malware_dir)
            fe.prepare_data()
            list = fe.get_features_list()
            for data in list:
                for infected_ip in malware_dir['infected_ip']:
                    if data['src_ip'] ==infected_ip:
                        data['is_malware'] = 1
                    else:
                        data['is_malware'] = 0
            pd.DataFrame.from_records(list).to_pickle(trgt_malware_dir + '/datas-by-mine.pkl')

if __name__ == '__main__':
    print('=============================== start =============================')
    parsing_all_benign()
    # parsing_all_malware()
    # parsing_datas('/home/sdsra/Downloads/CTU-13-Dataset/malware/42', ['147.32.84.165'])
    print('=============================== end =============================')
