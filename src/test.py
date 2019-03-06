from FeatureExtractorByBro import FeatureExtractor

print('=============================== start =============================')
path = '/home/sdsra/Downloads/CTU-13-Dataset/benign/2017_04_30-normal'
fe = FeatureExtractor(path)
fe.extract_features()
for flow in fe.connections:
    print(flow, fe.connections[flow].get_features())
print('================================ end ==============================')

