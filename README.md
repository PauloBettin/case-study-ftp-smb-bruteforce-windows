📂 Case Study: FTP & SMB Brute Force in Windows
<br>

Case study: brute force detection and automated blocking in Windows IIS FTP environments.
<br>

<br>
Este estudo de caso investiga ataques de força bruta direcionados a serviços FTP hospedados em Windows Server com IIS. A partir da análise dos padrões de falhas de autenticação registrados nos logs do IIS FTP, propomos um mecanismo prático de defesa implementado por meio de scripts em PowerShell e automação do Windows Firewall, assim como o hardning nas configurações do ISS.

A solução:

- Monitora continuamente os arquivos de log
- Identifica tentativas repetidas de login
- Aplica bloqueios temporários de IP
- Mantém uma whitelist de endereços confiáveis

Os resultados demonstram que, mesmo sem ferramentas nativas como o fail2ban, ambientes Windows podem alcançar uma mitigação eficaz contra brute force através da observabilidade de configurações de segurança (hardening) ou utilização de scripts próprios.

<br>

🔑 Keywords / Palavras-chave

<br>

Keywords: Information Security; Brute Force Attacks; FTP; IIS; Windows Server; PowerShell; Automation; Firewall; Case Study.

Palavras-chave: Segurança da Informação; Ataques de Força Bruta; FTP; IIS; Windows Server; PowerShell; Automação; Firewall; Estudo de Caso.

<br>

---

<br>

🖥️ Ambiente Experimental / Experimental Environment
<br>

Para simular o ataque de brute force em FTP, foram utilizadas máquinas virtuais configuradas da seguinte forma:

<br>

🔹 Servidor Alvo
-SO: Windows Server 2012 R2
-Função instalada: IIS FTP Server

![Funções](imagens/servicos.jpg)

Configuração:

-Autenticação via Active Directory (verde)
-Autenticação anônima desativada (vermelho)

![Configurações](imagens/configuracoesftp.jpg)

🔹 Máquina Atacante
-SO: Kali Linux 2025.2
-Ferramentas: nmap, medusa
-Rede: mesma sub-rede da VM alvo (rede interna Hyper-V)

🔹 Máquina Cliente
-SO: Windows 11 24h2
-Função: Testes de conexão para serviços FTP, SMB e RDP (após obtenção da senha)
<br>

---

<br>
⚙️ Metodologia / Methodology

🔍 Identificando o IP no Kali Linux
No Kali (ou em qualquer distribuição Linux), usamos o comando:

![ipaddr](imagens/ipaddr.jpg)

🌐 Scaneando a rede
Para identificar os possíveis hosts ativos:

![nmaparede](imagens/nmaprede.jpg)

📖 Explicação dos parâmetros

nmap → ferramenta de mapeamento de rede

-sn → ping scan, apenas verifica hosts ativos

192.168.15.0/24 → intervalo de endereços da rede (255.255.255.0 → .1 até .254)

📊 O que o comando faz Percorre todo o segmento de rede e retorna uma lista de hosts online.


🔍 Escaneando o host alvo
Após identificar o host 192.168.15.3, realizamos um scan completo:

bash
nmap -A -p- -T4 192.168.15.3
📖 Explicação dos parâmetros

-A → modo agressivo (OS detection, versão de serviços, scripts NSE, traceroute)

-p- → escaneia todas as 65.535 portas TCP

-T4 → timing rápido e confiável para redes locais

192.168.15.3 → IP do host alvo

📊 O que o comando faz

Verifica todas as portas abertas

Identifica serviços e versões

Descobre o sistema operacional

Executa scripts NSE padrão

Faz traceroute até o host
