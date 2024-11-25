import os
import subprocess
import json
import nmap
from datetime import datetime

# Função para verificar se a porta 2049 está aberta
def check_port(ip):
    print("[*] Verificando a porta 2049...")
    nm = nmap.PortScanner()
    nm.scan(ip, '2049')
    if nm[ip].has_tcp(2049) and nm[ip]['tcp'][2049]['state'] == 'open':
        print("[+] Porta 2049 aberta.")
        return True
    else:
        print("[-] Porta 2049 fechada.")
        return False

# Função para listar compartilhamentos
def list_shares(ip):
    print("[*] Listando compartilhamentos...")
    try:
        result = subprocess.check_output(["showmount", "-e", ip], stderr=subprocess.STDOUT)
        shares = result.decode().strip().split("\n")[1:]
        shares_dict = [line.split()[0] for line in shares]
        print(f"[+] Compartilhamentos encontrados: {shares_dict}")
        return shares_dict
    except subprocess.CalledProcessError as e:
        print(f"[-] Erro ao listar compartilhamentos: {e.output.decode()}")
        return []

# Função para montar e analisar permissões
def analyze_share(ip, share):
    mount_dir = f"/tmp/nfs_mount_{share.replace('/', '_')}"
    os.makedirs(mount_dir, exist_ok=True)
    print(f"[*] Montando o compartilhamento {share} em {mount_dir}...")
    try:
        subprocess.check_call(["sudo", "mount", "-t", "nfs", f"{ip}:{share}", mount_dir])
        print("[+] Compartilhamento montado com sucesso.")
        
        # Listar conteúdo e permissões
        print("[*] Analisando conteúdo e permissões...")
        file_info = subprocess.check_output(["ls", "-lR", mount_dir]).decode()
        return {"share": share, "mount_point": mount_dir, "content": file_info}
    except subprocess.CalledProcessError as e:
        print(f"[-] Falha ao montar o compartilhamento {share}: {e}")
        return {"share": share, "mount_point": mount_dir, "error": str(e)}
    finally:
        subprocess.call(["sudo", "umount", mount_dir])

# Função principal
def main(ip):
    report = {"target": ip, "scanned_at": datetime.now().isoformat(), "shares": []}

    # Verificar a porta 2049
    if not check_port(ip):
        return

    # Listar compartilhamentos
    shares = list_shares(ip)
    if not shares:
        return

    # Analisar cada compartilhamento
    for share in shares:
        analysis = analyze_share(ip, share)
        report["shares"].append(analysis)

    # Salvar relatório em JSON
    output_file = f"nfs_report_{ip.replace('.', '_')}.json"
    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] Relatório salvo em {output_file}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Script avançado para explorar serviços NFS.")
    parser.add_argument("ip", help="Endereço IP do alvo")
    args = parser.parse_args()

    main(args.ip)
