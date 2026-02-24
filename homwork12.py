#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Форензический анализ сетевого дампа (pcap/pcapng).
Собирает: DNS, HTTP, ICMP, TCP/UDP соединения, порты, размеры пакетов.
Визуальная статистика: дашборд с графиками (как homework11).
"""

import os
import json
import glob
from io import BytesIO
from collections import Counter

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import seaborn as sns

PYSHARK_AVAILABLE = False
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    pass

import dpkt

# Стиль вывода (ASCII-совместимый для Windows)
BOX = {
    'tl': '+', 'tr': '+', 'bl': '+', 'br': '+',
    'h': '=', 'v': '|', 'ml': '+', 'mr': '+', 'm': '+',
}
SECTION = '-' * 52


def find_dump_file(folder):
    """Ищет файл дампа в папке."""
    for p in ['*.pcap', '*.pcapng', '*.cap']:
        for path in glob.glob(os.path.join(folder, p)):
            if os.path.isfile(path):
                return path
    return None


def print_box(title, content_lines, width=52):
    """Красивый вывод блока с рамкой."""
    pad = width - 4
    print(f"\n{BOX['tl']}{BOX['h'] * (width - 2)}{BOX['tr']}")
    print(f"{BOX['v']} {title[:pad].ljust(pad)} {BOX['v']}")
    print(f"{BOX['ml']}{BOX['h'] * (width - 2)}{BOX['mr']}")
    for line in content_lines:
        s = str(line)[:pad]
        print(f"{BOX['v']} {s.ljust(pad)} {BOX['v']}")
    print(f"{BOX['bl']}{BOX['h'] * (width - 2)}{BOX['br']}")


def print_section(title):
    """Заголовок секции."""
    print(f"\n  {SECTION}")
    print(f"  {title}")
    print(f"  {SECTION}")


def analyze_with_dpkt(pcap_file):
    """
    Расширенное извлечение артефактов.
    Возвращает: stats dict со всеми данными.
    """
    with open(pcap_file, 'rb') as f:
        data = f.read()
    bio = BytesIO(data)
    magic = int.from_bytes(data[:4], 'little')
    reader = dpkt.pcapng.Reader(bio) if magic in (0x0A0D0D0A, 0x1A2B3C4D, 0x4D3C2B1A) else dpkt.pcap.Reader(bio)

    dns_records = []
    http_records = []
    icmp_records = []
    connections = []
    all_ips = set()
    protocol_counts = Counter()
    port_counts = Counter()
    ip_packet_counts = Counter()
    total_bytes = 0
    packet_sizes = []

    for ts, buf in reader:
        try:
            packet_sizes.append(len(buf))
            total_bytes += len(buf)

            eth = dpkt.ethernet.Ethernet(buf)

            # ARP
            if isinstance(eth.data, dpkt.arp.ARP):
                protocol_counts['ARP'] += 1
                continue

            if not isinstance(eth.data, dpkt.ip.IP):
                protocol_counts['OTHER'] += 1
                continue

            ip = eth.data
            src = dpkt.utils.inet_to_str(ip.src)
            dst = dpkt.utils.inet_to_str(ip.dst)
            all_ips.update([src, dst])
            ip_packet_counts[src] += 1
            ip_packet_counts[dst] += 1

            # ICMP
            if isinstance(ip.data, dpkt.icmp.ICMP):
                protocol_counts['ICMP'] += 1
                icmp = ip.data
                icmp_records.append({
                    'timestamp': ts,
                    'src_ip': src,
                    'dst_ip': dst,
                    'type': icmp.type,
                    'code': icmp.code
                })
                continue

            # TCP
            if isinstance(ip.data, dpkt.tcp.TCP):
                protocol_counts['TCP'] += 1
                tcp = ip.data
                sport, dport = tcp.sport, tcp.dport
                port_counts[dport] += 1
                port_counts[sport] += 1

                connections.append({
                    'timestamp': ts,
                    'src_ip': src,
                    'dst_ip': dst,
                    'protocol': 'TCP',
                    'src_port': sport,
                    'dst_port': dport,
                    'size': len(buf)
                })

                # HTTP (порт 80)
                if (dport == 80 or sport == 80) and len(tcp.data) > 0:
                    try:
                        req = dpkt.http.Request(tcp.data)
                        host = req.headers.get('host', req.headers.get('Host', ''))
                        if isinstance(host, list):
                            host = host[0] if host else ''
                        http_records.append({
                            'timestamp': ts,
                            'method': req.method,
                            'host': host,
                            'uri': req.uri[:200] if req.uri else '',
                            'src_ip': src,
                            'dst_ip': dst
                        })
                    except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData, Exception):
                        pass
                continue

            # UDP
            if isinstance(ip.data, dpkt.udp.UDP):
                protocol_counts['UDP'] += 1
                udp = ip.data
                sport, dport = udp.sport, udp.dport
                port_counts[dport] += 1
                port_counts[sport] += 1

                connections.append({
                    'timestamp': ts,
                    'src_ip': src,
                    'dst_ip': dst,
                    'protocol': 'UDP',
                    'src_port': sport,
                    'dst_port': dport,
                    'size': len(buf)
                })

                # DNS
                if dport == 53 and len(udp.data) > 0:
                    try:
                        dns = dpkt.dns.DNS(udp.data)
                        if dns.qr == 0 and dns.qd:
                            for q in dns.qd:
                                qname = q.name if isinstance(q.name, str) else q.name.decode('utf-8', errors='replace')
                                dns_records.append({
                                    'timestamp': ts,
                                    'query': qname,
                                    'src_ip': src,
                                    'qtype': q.type
                                })
                    except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData, Exception):
                        pass
                continue

            protocol_counts['OTHER'] += 1

        except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData, IndexError, KeyError):
            continue

    # Имена для известных портов
    KNOWN_PORTS = {80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH', 25: 'SMTP', 110: 'POP3',
                   143: 'IMAP', 445: 'SMB', 139: 'NetBIOS', 67: 'DHCP-s', 68: 'DHCP-c',
                   8009: 'AJP', 8080: 'HTTP-Alt', 8000: 'HTTP-8k'}
    port_labels = {p: f"{p} ({KNOWN_PORTS.get(p, '')})" if KNOWN_PORTS.get(p) else str(p)
                   for p in port_counts}

    return {
        'dns_df': pd.DataFrame(dns_records),
        'http_df': pd.DataFrame(http_records),
        'icmp_df': pd.DataFrame(icmp_records),
        'conn_df': pd.DataFrame(connections),
        'ip_list': sorted(all_ips),
        'protocol_counts': dict(protocol_counts),
        'port_counts': dict(port_counts),
        'port_labels': port_labels,
        'ip_packet_counts': dict(ip_packet_counts.most_common(20)),
        'total_packets': len(packet_sizes),
        'total_bytes': total_bytes,
        'packet_sizes': packet_sizes,
    }


def analyze_pcap(pcap_file):
    """Выбор метода: pyshark или dpkt."""
    if PYSHARK_AVAILABLE:
        try:
            print("  Используется pyshark...")
            return _analyze_pyshark_fallback(pcap_file)
        except Exception as e:
            print(f"  pyshark недоступен: {e}")
    print("  Используется dpkt...")
    return analyze_with_dpkt(pcap_file)


def _analyze_pyshark_fallback(pcap_file):
    """Упрощённый анализ через pyshark — при ошибке fallback на dpkt."""
    try:
        cap = pyshark.FileCapture(pcap_file)
        # Проверка доступности
        _ = next(iter(cap))
        cap.close()
    except Exception:
        return analyze_with_dpkt(pcap_file)

    # pyshark работает — собираем базовые данные
    dns_records, connections, all_ips = [], [], set()
    protocol_counts, port_counts = Counter(), Counter()
    cap = pyshark.FileCapture(pcap_file)
    for pkt in cap:
        try:
            if hasattr(pkt, 'ip'):
                src, dst = pkt.ip.src, pkt.ip.dst
                all_ips.update([src, dst])
                proto = getattr(pkt, 'transport_layer', 'OTHER')
                protocol_counts[proto] += 1
                sport = dport = None
                if proto != 'OTHER' and hasattr(pkt, proto):
                    sport = getattr(pkt[proto], 'srcport', None)
                    dport = getattr(pkt[proto], 'dstport', None)
                    if dport:
                        port_counts[int(dport)] += 1
                connections.append({
                    'timestamp': float(pkt.sniff_timestamp),
                    'src_ip': src, 'dst_ip': dst,
                    'protocol': proto, 'src_port': sport, 'dst_port': dport, 'size': 0
                })
            if hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name'):
                if str(getattr(pkt.dns, 'flags_response', '1')) == '0':
                    dns_records.append({
                        'timestamp': float(pkt.sniff_timestamp),
                        'query': pkt.dns.qry_name,
                        'src_ip': getattr(pkt.ip, 'src', None), 'qtype': None
                    })
        except (AttributeError, KeyError):
            continue
    cap.close()

    KNOWN_PORTS = {80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH', 25: 'SMTP'}
    port_labels = {p: f"{p} ({KNOWN_PORTS.get(p, '')})" if KNOWN_PORTS.get(p) else str(p)
                   for p in port_counts}

    return {
        'dns_df': pd.DataFrame(dns_records),
        'http_df': pd.DataFrame(),
        'icmp_df': pd.DataFrame(),
        'conn_df': pd.DataFrame(connections),
        'ip_list': sorted(all_ips),
        'protocol_counts': dict(protocol_counts),
        'port_counts': dict(port_counts),
        'port_labels': port_labels,
        'ip_packet_counts': {},
        'total_packets': len(connections),
        'total_bytes': 0,
        'packet_sizes': [],
    }


def build_dashboard(stats, out_path):
    """Строит единый дашборд с несколькими графиками (как homework11)."""
    fig = plt.figure(figsize=(14, 10))
    fig.suptitle('Форензический анализ сетевого дампа — Статистика', fontsize=14, fontweight='bold', y=1.02)

    # 1. Протоколы (pie или bar)
    ax1 = fig.add_subplot(2, 2, 1)
    pc = stats['protocol_counts']
    if pc:
        labels = list(pc.keys())
        values = list(pc.values())
        colors = sns.color_palette('Set3', len(labels))
        ax1.pie(values, labels=labels, autopct='%1.1f%%', colors=colors, startangle=90)
        ax1.set_title('Распределение по протоколам')
    else:
        ax1.text(0.5, 0.5, 'Нет данных', ha='center', va='center')
        ax1.set_title('Протоколы')

    # 2. Топ портов
    ax2 = fig.add_subplot(2, 2, 2)
    port_counts = stats['port_counts']
    if port_counts:
        top_ports = sorted(port_counts.items(), key=lambda x: -x[1])[:10]
        ports = [str(p[0]) for p in top_ports]
        counts = [p[1] for p in top_ports]
        bars = ax2.barh(ports[::-1], counts[::-1], color=sns.color_palette('Blues_r', len(ports)))
        ax2.set_xlabel('Количество пакетов')
        ax2.set_title('Топ-10 портов назначения')
    else:
        ax2.text(0.5, 0.5, 'Нет данных', ha='center', va='center')
        ax2.set_title('Порты')

    # 3. Топ доменов (DNS)
    ax3 = fig.add_subplot(2, 2, 3)
    dns_df = stats['dns_df']
    if not dns_df.empty:
        top = dns_df['query'].value_counts().head(10)
        sns.barplot(y=top.index, x=top.values, hue=top.index, palette='Greens_r', legend=False, ax=ax3)
        ax3.set_xlabel('Запросов')
        ax3.set_title('Топ-10 DNS-запросов')
    else:
        ax3.text(0.5, 0.5, 'DNS не найден', ha='center', va='center')
        ax3.set_title('DNS-запросы')

    # 4. Топ IP по активности
    ax4 = fig.add_subplot(2, 2, 4)
    ip_counts = stats.get('ip_packet_counts', {})
    if ip_counts:
        ips = list(ip_counts.keys())[:10]
        cnts = list(ip_counts.values())[:10]
        sns.barplot(y=ips[::-1], x=cnts[::-1], hue=ips[::-1], palette='Oranges_r', legend=False, ax=ax4)
        ax4.set_xlabel('Пакетов')
        ax4.set_title('Топ-10 IP по активности')
    elif not stats['conn_df'].empty:
        conn = stats['conn_df']
        src_counts = conn['src_ip'].value_counts().head(10)
        sns.barplot(y=src_counts.index[::-1], x=src_counts.values[::-1], hue=src_counts.index[::-1], palette='Oranges_r', legend=False, ax=ax4)
        ax4.set_xlabel('Соединений')
        ax4.set_title('Топ-10 IP (источников)')
    else:
        ax4.text(0.5, 0.5, 'Нет данных', ha='center', va='center')
        ax4.set_title('IP-адреса')

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches='tight')
    plt.close()
    print(f"  Дашборд сохранён: {os.path.basename(out_path)}")


def plot_dns_over_time(df, out_path):
    """График DNS по времени."""
    if df.empty or len(df) < 2:
        return
    df = df.copy()
    df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
    df.set_index('datetime', inplace=True)
    interval = '1min' if len(df) > 60 else '10s'
    ts = df.resample(interval).size()
    plt.figure(figsize=(10, 4))
    ts.plot(kind='line', color='steelblue', linewidth=2)
    plt.title('Динамика DNS-запросов во времени')
    plt.xlabel('Время')
    plt.ylabel('Запросов')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    print(f"  График: {os.path.basename(out_path)}")


def plot_http_hosts(df, out_path):
    """Топ HTTP-хостов."""
    if df.empty:
        return
    hosts = df['host'].value_counts()
    hosts = hosts[hosts.index.astype(str).str.len() > 0].head(10)
    if hosts.empty:
        return
    plt.figure(figsize=(10, 5))
    sns.barplot(y=hosts.index, x=hosts.values, hue=hosts.index, palette='Purples_r', legend=False)
    plt.title('Топ HTTP-хостов')
    plt.xlabel('Запросов')
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    print(f"  График: {os.path.basename(out_path)}")


def main():
    import sys
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_file = sys.argv[1] if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]) else find_dump_file(script_dir)

    if not pcap_file:
        print("Файл дампа (pcap/pcapng) не найден в папке со скриптом.")
        return

    print(f"\n{BOX['tl']}{BOX['h'] * 50}{BOX['tr']}")
    print(f"{BOX['v']}  ФОРЕНЗИЧЕСКИЙ АНАЛИЗ СЕТЕВОГО ДАМПА".ljust(51) + BOX['v'])
    print(f"{BOX['v']}  Этап 1. Загрузка данных".ljust(51) + BOX['v'])
    print(f"{BOX['bl']}{BOX['h'] * 50}{BOX['br']}")
    print(f"  Файл: {os.path.basename(pcap_file)}")

    print_section("Этап 2. Извлечение артефактов")
    stats = analyze_pcap(pcap_file)

    dns_df = stats['dns_df']
    http_df = stats['http_df']
    icmp_df = stats['icmp_df']
    conn_df = stats['conn_df']
    ip_list = stats['ip_list']

    # ─── Красивый вывод статистики в консоль ─────────────────────────────────
    summary = [
        f"Всего пакетов: {stats['total_packets']}",
        f"Объём трафика: {stats['total_bytes'] / 1024:.1f} КБ" if stats['total_bytes'] else "Объём: N/A",
        f"Уникальных IP: {len(ip_list)}",
        f"Соединений: {len(conn_df)}",
        f"DNS-запросов: {len(dns_df)}",
        f"HTTP-запросов: {len(http_df)}",
        f"ICMP-пакетов: {len(icmp_df)}",
        "",
        "Протоколы: " + ", ".join(f"{k}: {v}" for k, v in stats['protocol_counts'].items()),
    ]
    print_box("Сводная статистика", summary)

    if stats['protocol_counts']:
        print_box("По протоколам", [f"  {k}: {v}" for k, v in sorted(stats['protocol_counts'].items(), key=lambda x: -x[1])])

    top_ports = sorted(stats['port_counts'].items(), key=lambda x: -x[1])[:15]
    if top_ports:
        plabels = stats.get('port_labels', {})
        print_box("Топ портов", [f"  {plabels.get(p, p)}: {c}" for p, c in top_ports])

    if not dns_df.empty:
        top_dns = dns_df['query'].value_counts().head(10)
        print_box("Топ DNS-доменов", [f"  {d}: {c}" for d, c in top_dns.items()])

    if not http_df.empty:
        hosts = http_df['host'].value_counts()
        hosts = hosts[hosts.index.astype(str).str.len() > 0].head(10)
        if not hosts.empty:
            print_box("Топ HTTP-хостов", [f"  {h}: {c}" for h, c in hosts.items()])

    if not icmp_df.empty:
        icmp_types = icmp_df.groupby(['type', 'code']).size().sort_values(ascending=False).head(5)
        lines = [f"  Записей: {len(icmp_df)}"] + [f"  type={t[0]} code={t[1]}: {c}" for t, c in icmp_types.items()]
        print_box("ICMP", lines)

    # ─── Сохранение файлов ───────────────────────────────────────────────────
    print_section("Этап 3. Сохранение результатов")

    dns_df.to_csv(os.path.join(script_dir, 'dns_queries.csv'), index=False)
    conn_df.to_csv(os.path.join(script_dir, 'connections.csv'), index=False)
    with open(os.path.join(script_dir, 'ip_addresses.json'), 'w', encoding='utf-8') as f:
        json.dump([{'ip': ip} for ip in ip_list], f, indent=2)
    if not http_df.empty:
        http_df.to_csv(os.path.join(script_dir, 'http_requests.csv'), index=False)

    report = {
        'dump': pcap_file,
        'packets': stats['total_packets'],
        'bytes': stats['total_bytes'],
        'protocols': stats['protocol_counts'],
        'top_ports': dict(top_ports[:10]) if top_ports else {},
        'unique_ips': len(ip_list),
    }
    with open(os.path.join(script_dir, 'forensics_report.json'), 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("  Файлы: dns_queries.csv, connections.csv, ip_addresses.json,")
    print("         forensics_report.json" + (", http_requests.csv" if not http_df.empty else ""))

    # ─── Визуализация ────────────────────────────────────────────────────────
    print_section("Графики и дашборд")

    build_dashboard(stats, os.path.join(script_dir, 'forensics_dashboard.png'))
    plot_dns_over_time(dns_df, os.path.join(script_dir, 'dns_over_time.png'))
    plot_http_hosts(http_df, os.path.join(script_dir, 'http_hosts.png'))

    print(f"\n  {BOX['tl']}{BOX['h'] * 50}{BOX['tr']}")
    print(f"  {BOX['v']}  Анализ завершён.".ljust(51) + BOX['v'])
    print(f"  {BOX['bl']}{BOX['h'] * 50}{BOX['br']}\n")


if __name__ == '__main__':
    main()
