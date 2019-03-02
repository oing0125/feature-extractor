import subprocess
import platform
import os

class FeatureExtractor:
    def __init__(self, filePath):
        self.filePath = filePath
        self._tshark = self._get_tshark_path()
        self.pcap2tsv_with_tshark()

    def _get_tshark_path(self):
        if platform.system() == 'Windows':
            return 'C:\Program Files\Wireshark\\tshark.exe'
        else:
            system_path = os.environ['PATH']
            for path in system_path.split(os.pathsep):
                filename = os.path.join(path, 'tshark')
                if os.path.isfile(filename):
                    return filename
        return ''

    def pcap2tsv_with_tshark(self):
        fieldList = [

            "data"

            # frame
            , "frame.time_epoch"
            , "frame.len"

            #ethernet
            , "eth.src"
            , "eth.dst"
            , "eth.len"

            # ip
            , "ip.src"
            , "ip.dst"
            , "ip.len"
            , "ip.hdr_len"

            # tcp
            , "tcp.srcport"
            , "tcp.dstport"
            , "tcp.hdr_len"
            , "tcp.len"             # segment data
            , "tcp.option_len"
            , "tcp.ack"
            , "tcp.flags.ack"
            , "tcp.flags.cwr"
            , "tcp.flags.ecn"
            , "tcp.flags.fin"
            , "tcp.flags.ns"
            , "tcp.flags.push"
            , "tcp.flags.res"
            , "tcp.flags.reset"
            , "tcp.flags.str"
            , "tcp.flags.syn"
            , "tcp.flags.urg"
            , "tcp.options.unknown.payload"
            , "tcp.payload"
            , "tcp.connection.fin"
            , "tcp.connection.rst"
            , "tcp.connection.sack"
            , "tcp.connection.syn"
            , "tcp.segment"
            , "tcp.segment_data"
            , "tcp.window_size"
            , "tcp.analysis.zero_window"


            # tls
            # , "tls.handshake.ciphersuites"

            # upd
            , "udp.srcport"
            , "udp.dstport"
            , "udp.length"

            # icmp
            , "icmp.type"
            , "icmp.code"

            # arp
            , "arp.opcode"
            , "arp.src.hw_mac"
            , "arp.src.proto"
            , "arp.dst.hw_mac"
            , "arp.dst.proto"
        ]
        print('Parsing with tshark...')
        fields = " -e ".join([field for field in fieldList])
        cmd = '"' + self._tshark + '" -r ' + self.filePath + ' -T fields -e ' + fields + ' -E header=y -E occurrence=f > ' + self.filePath + ".csv"
        subprocess.call(cmd, shell=True)
        print("tshark parsing complete. File saved as: " + self.filePath + ".csv")