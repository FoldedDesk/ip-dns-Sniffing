import pyshark as pys


def main():
    capture = pys.LiveCapture(interface='WLAN', display_filter='dns')
    capture.sniff(timeout=20)
    for packet in capture:
        if hasattr(packet.dns, 'qry_name'):
            domain = packet.dns.qry_name
            ips = []
            # 检查 IPv4 记录（A 记录）
            if hasattr(packet.dns, 'a'):
                ips.append(packet.dns.a)
            # 输出结果
            if ips:
                print(f"DNS 查询: {domain} -> IP: {', '.join(ips)}")
            else:
                print(f"DNS 查询: {domain} （未捕获响应 IP）")


if __name__ == '__main__':
    main()
