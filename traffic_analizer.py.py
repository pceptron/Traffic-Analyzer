#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers.inet import IP
import ipaddress
import logging
import threading
import time
import subprocess
import re
from datetime import datetime
import yaml

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Загрузка конфигурации из YAML файла
with open('/opt/scripts/config.yaml', 'r') as config_file:
    config = yaml.safe_load(config_file)

# Определяем диапазоны приватных IP-адресов согласно RFC1918
PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16')
]

# Определяем интересующие нас клиентские IP-адреса и сети
CLIENT_IPS = [ipaddress.ip_network(ip) for ip in config['CLIENT_IPS']]

# Определяем период ротации
RTIMER = config['RTIMER']

# Определяем интерфейс на котором снифим
SNIFF_INTERFACE = config['SNIFF_INTERFACE']

# IP-адреса маршрутизатора и VPN-сервера
ROUTER_IP = ipaddress.ip_address(config['ROUTER_IP'])
VPN_SERVER_IP = ipaddress.ip_address(config['VPN_SERVER_IP'])

# Файл для записи статистики
TRAFFIC_STAT_FILE = config['TRAFFIC_STAT_FILE']

# Шаблон для файла анализа
ANALYSIS_FILE_TEMPLATE = config['ANALYSIS_FILE_TEMPLATE']

# Статистика трафика
traffic_stats = {}

# Кэш для хранения результатов whois
whois_cache = {}

# Флаг для остановки захвата пакетов
stop_sniffing = threading.Event()

# Функция для проверки, является ли IP-адрес приватным
def is_private_ip(ip):
    return any(ipaddress.ip_address(ip) in network for network in PRIVATE_NETWORKS)

# Функция для проверки, является ли IP-адрес интересующим нас клиентским IP
def is_client_ip(ip):
    ip_addr = ipaddress.ip_address(ip)
    for client_ip in CLIENT_IPS:
        if isinstance(client_ip, ipaddress.IPv4Network):
            if ip_addr in client_ip:
                return True
        elif isinstance(client_ip, ipaddress.IPv4Address):
            if ip_addr == client_ip:
                return True
    return False

# Функция для преобразования диапазона IP в формат CIDR
def range_to_cidr(start_ip, end_ip):
    try:
        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)
        return str(list(ipaddress.summarize_address_range(start, end))[0])
    except ValueError:
        return f"{start_ip} - {end_ip}"

# Функция для получения информации whois с кэшированием
def get_whois_info(ip):
    if ip in whois_cache:
        cached_result = whois_cache[ip]
        return cached_result if len(cached_result) == 4 else ("Unknown", "Unknown", "Unknown", "Unknown")

    try:
        whois_info = subprocess.check_output(['whois', ip], universal_newlines=False)
        whois_info = whois_info.decode('utf-8', errors='ignore')
        network_info = "Unknown"
        inetnum_info = "Unknown"
        country_info = "Unknown"
        cidr_info = "Unknown"

        inetnum_match = re.search(r'inetnum:\s+(\d+\.\d+\.\d+\.\d+\s*-\s*\d+\.\d+\.\d+\.\d+)', whois_info, re.IGNORECASE)
        netname_match = re.search(r'netname:\s*(\S+)', whois_info, re.IGNORECASE)
        cidr_match = re.findall(r'CIDR:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+(?:, [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+)*)', whois_info, re.IGNORECASE)
        country_match = re.search(r'country:\s*(\S+)', whois_info, re.IGNORECASE)

        if inetnum_match:
            start_ip, end_ip = inetnum_match.group(1).split('-')
            inetnum_info = range_to_cidr(start_ip.strip(), end_ip.strip())

        if netname_match:
            network_info = netname_match.group(1).strip()

        if country_match:
            country_info = country_match.group(1).strip()

        if cidr_match:
            cidr_info = [cidr.strip() for cidr in cidr_match[0].split(', ')]
        else:
            cidr_info = "Unknown"

        whois_cache[ip] = (inetnum_info, cidr_info, network_info, country_info)
        time.sleep(1)
        return inetnum_info, cidr_info, network_info, country_info
    except subprocess.CalledProcessError as e:
        logging.error(f"Whois command failed for IP {ip}: {e}")
        whois_cache[ip] = ("Unknown", "Unknown", "Error retrieving info", "Error retrieving info")
        return "Unknown", "Unknown", "Error retrieving info", "Error retrieving info"
    except Exception as e:
        logging.error(f"Unexpected error for IP {ip}: {e}")
        whois_cache[ip] = ("Unknown", "Unknown", "Error retrieving info", "Error retrieving info")
        return "Unknown", "Unknown", "Error retrieving info", "Error retrieving info"

# Функция для обработки каждого захваченного пакета
def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Исключаем трафик между приватными адресами
        if is_private_ip(src_ip) and is_private_ip(dst_ip):
            return

        # Исключаем трафик между маршрутизатором и VPN-сервером
        if src_ip == str(VPN_SERVER_IP) or dst_ip == str(VPN_SERVER_IP):
            return

        # Исключаем трафик через туннельный интерфейс (например, tun2)
        # print (packet.sniffed_on)
        if packet.sniffed_on == 'tun2':
            return

        # Фильтруем трафик по клиентским IP
        if not is_client_ip(src_ip):
            return

        # Подсчет трафика
        packet_size = len(packet)
        if (src_ip, dst_ip) not in traffic_stats:
            traffic_stats[(src_ip, dst_ip)] = {'total': 0}

        traffic_stats[(src_ip, dst_ip)]['total'] += packet_size

        # Запись статистики в файл
        with open(TRAFFIC_STAT_FILE, 'a') as f:
            f.write(f"{src_ip},{dst_ip},{packet_size}\n")

# Функция для анализа собранной статистики
def analyze_traffic():
    print("Starting traffic analysis...")
    analysis_results = {}
    with open(TRAFFIC_STAT_FILE, 'r') as f:
        for line in f:
            src_ip, dst_ip, packet_size = line.strip().split(',')
            packet_size = int(packet_size)
            if (src_ip, dst_ip) not in analysis_results:
                analysis_results[(src_ip, dst_ip)] = {'total': 0}
            analysis_results[(src_ip, dst_ip)]['total'] += packet_size

    # Получение информации о владельце внешнего IP
    detailed_results = {}
    for (src_ip, dst_ip), data in analysis_results.items():
        inetnum_info, cidr_info, network_info, country_info = get_whois_info(dst_ip)
        if src_ip not in detailed_results:
            detailed_results[src_ip] = []
        detailed_results[src_ip].append({
            'dst_ip': dst_ip,
            'total': data['total'],
            'cidr_info': cidr_info,
            'inetnum_info': inetnum_info,
            'network_info': network_info,
            'country_info': country_info
        })

    # Сортировка данных по `total`
    for src_ip in detailed_results:
        detailed_results[src_ip].sort(key=lambda x: x['total'])

    # Запись результатов анализа в файл
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    analysis_file = ANALYSIS_FILE_TEMPLATE.format(timestamp=timestamp)
    with open(analysis_file, 'w') as f:
        for src_ip, entries in detailed_results.items():
            f.write(f"{src_ip}:\n")
            for entry in entries:
                f.write(f"  {entry['dst_ip']}, {entry['total']} bytes, "
                        f"Inetnum: {entry['inetnum_info']}, "
                        f"CIDR info: {entry['cidr_info']}, "
                        f"Network: {entry['network_info']}, "
                        f"Country: {entry['country_info']}\n")

    print(f"Traffic analysis completed. Results saved to {analysis_file}")

# Функция для очистки файла статистики
def clear_traffic_stat_file():
    with open(TRAFFIC_STAT_FILE, 'w') as f:
        f.truncate()

# Функция для захвата пакетов
#def sniff_packets():
#    scapy.sniff(iface='br-lan', prn=process_packet, stop_filter=lambda x: stop_sniffing.is_set(), store=False)
def sniff_packets():
    # Указываем интерфейсы, которые нужно отслеживать, исключая туннельные
    interfaces_to_sniff = [SNIFF_INTERFACE]
    scapy.sniff(iface=interfaces_to_sniff, prn=process_packet, stop_filter=lambda x: stop_sniffing.is_set(), store=False)

# Функция для запуска цикла сбора и анализа трафика
def traffic_monitoring_cycle():
    while True:
        print("Starting traffic collection...")
        # Запускаем захват пакетов на интерфейсе br-lan
        sniff_thread = threading.Thread(target=sniff_packets)
        sniff_thread.start()

        time.sleep(RTIMER)

        # Останавливаем захват пакетов
        stop_sniffing.set()
        sniff_thread.join()
        stop_sniffing.clear()

        # Анализируем собранный трафик
        analyze_traffic()

        # Очищаем файл статистики
        clear_traffic_stat_file()

        print("Cycle completed. Starting new cycle...")

if __name__ == "__main__":
    traffic_monitoring_cycle()

