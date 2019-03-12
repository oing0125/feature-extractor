'''
Flows
2019-03-11
* Functions
- group by flow tuple : (src_ip, dst_ip, dst_port, protocol)
'''
class Flows:

    def __init__(self, tuple):
        self.tuple = tuple
        self.src_ip = tuple[0]
        self.dst_ip = tuple[1]
        self.dst_port = tuple[2]
        self.protocol = tuple[3]
