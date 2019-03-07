from FeatureExtractorByBro import FeatureExtractor
import pickle
import pandas as pd
import os

def pasing_datas(path, infected_ip_list = []):
    fe = FeatureExtractor(path)
    fe.extract_features()
    datas = []
    for key in fe.connections:
        if len(fe.connections[key].ssl_flow_list) > 0:
            src_ip = key[0]
            dst_ip = key[1]
            src_port = key[2]
            dst_port = key[3]
            features = fe.connections[key].get_features()
            features['src_ip'] = src_ip
            features['src_port'] = src_port
            features['dst_ip'] = dst_ip
            features['dst_port'] = dst_port
            features['label'] = 'Botnet' if src_ip in infected_ip_list else 'benign'
            datas.append(features)
    return datas


if __name__ == '__main__':
    malware_9 = {'infected_ip_list' : ['147.32.84.165', '147.32.84.191', '147.32.84.192', '147.32.84.193', '147.32.84.194',
                                  '147.32.84.204', '147.32.84.205', '147.32.84.206', '147.32.84.207', '147.32.84.208', '147.32.84.209']
                ,'path' : '/home/sdsra/Downloads/CTU-13-Dataset/malware/9'
    }

    benign_2017_4_30_normal = {
        'path': '/home/sdsra/Downloads/CTU-13-Dataset/benign/2017_04_30-normal'
    }
    print('=============================== start =============================')
    benign_path = '/home/sdsra/Downloads/CTU-13-Dataset/benign'
    benign_dir_list = os.listdir(benign_path)
    benign_datas = []
    for benign_dir in benign_dir_list:
        generated_datas = pasing_datas(benign_path + '/' + benign_dir)
        benign_datas = benign_datas + generated_datas

    pdBenignDataList = pd.DataFrame.from_records(benign_datas)
    pdBenignDataList.to_pickle(benign_path+'/datas.pkl')
    # with open(benign_2017_4_30_normal) as fr:
    #     fr.
    # pasing_datas(malware_9['path'], malware_9['infected_ip_list'])
    print('=============================== end =============================')
