# AUTO-PWN

Script em Python para automatizar etapas de auditoria WiFi com interfaces compatíveis:
coloca a interface em modo monitor, faz scan, verifica clientes, captura handshake
ou tenta alternativas (PMKID/WPS), e oferece cracking com aircrack-ng, hashcat
ou John the Ripper.

## Aviso legal

Use somente em redes próprias ou com autorizacao expressa. O uso indevido pode
ser ilegal. O autor e este repositório nao se responsabilizam por uso indevido.

Esta é uma ferramenta de pentest/seguranca ofensiva. Use com cautela e apenas
para fins de auditoria autorizada. A atividade de hacking sem permissao pode
violar leis locais e resultar em penalidades.

## Requisitos

- Linux
- Interface wireless com suporte a monitor mode
- Python 3
- Ferramentas principais:
  - `aircrack-ng` (airodump-ng, aireplay-ng, aircrack-ng)
  - `iw`
- Opcionais (para metodos alternativos e cracking):
  - `hcxdumptool`, `hcxpcapngtool`/`hcxpcaptool` (PMKID)
  - `reaver`, `bully`, `pixiewps` (WPS)
  - `hashcat`
  - `john` + `wpapcap2john`
  - `cap2hccapx`

## Instalacao rapida (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y aircrack-ng iw
```

Opcionais:

```bash
sudo apt install -y hcxdumptool hcxtools hashcat john reaver bully pixiewps
```

## Como usar

1) Conecte o adaptador wireless.
2) Execute como root:

```bash
sudo python3 auto-wifi.py
```

Opcionalmente, selecione a interface via argumento:

```bash
sudo python3 auto-wifi.py -i wlan1
```

O script nao mexe na interface `wlan0` (Wi-Fi interno), a menos que voce a selecione.

## O que o script faz

- Coloca `wlan1` em modo monitor
- Faz scan de redes e clientes
- Tenta captura de handshake com deauth
- Caso nao haja clientes, sugere metodos alternativos (ex.: PMKID/WPS)
- Oferece cracking via aircrack-ng, hashcat ou John

## Dicas

- Para melhor resultado, mantenha sinal forte (acima de -70 dBm).
- PMKID pode funcionar sem clientes conectados, mas depende do roteador.
- WPS tende a funcionar apenas em roteadores antigos.

## Solucao de problemas

- "Failed to enter monitor mode": verifique se `wlan1` existe e se ha conflitos
  com NetworkManager.
- "Scan failed - no CSV": confirme que `airodump-ng` esta instalado.
- Falha ao converter hashes: instale `hcxtools` e/ou `cap2hccapx`.
