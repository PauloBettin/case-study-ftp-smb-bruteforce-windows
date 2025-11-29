# case-study-ftp-smb-bruteforce-windows

"Case study: brute force detection and automated blocking in Windows IIS FTP environments."

This case study investigates brute force attacks targeting FTP services hosted on Windows Server with IIS. By analyzing authentication failure patterns in IIS FTP logs, we propose a practical defense mechanism implemented through PowerShell scripting and Windows Firewall automation. The solution continuously monitors log files, identifies repeated login failures, and enforces temporary IP blocking while maintaining a whitelist of trusted addresses. Results demonstrate that even without native tools like fail2ban, Windows environments can achieve effective brute force mitigation through log observability and automated response. This work represents a practical reinterpretation of intrusion detection concepts adapted to the Windows ecosystem.

Estudo de caso: detecção de força bruta e bloqueio automatizado em ambientes Windows IIS FTP.

Este estudo de caso investiga ataques de força bruta direcionados a serviços FTP hospedados em Windows Server com IIS. A partir da análise dos padrões de falhas de autenticação registrados nos logs do IIS FTP, propomos um mecanismo prático de defesa implementado por meio de scripts em PowerShell e automação do Windows Firewall. A solução monitora continuamente os arquivos de log, identifica tentativas repetidas de login e aplica bloqueios temporários de IP, mantendo ao mesmo tempo uma lista de endereços confiáveis (whitelist). Os resultados demonstram que, mesmo sem ferramentas nativas como o fail2ban, ambientes Windows podem alcançar uma mitigação eficaz contra brute force através da observabilidade dos logs e da resposta automatizada. Este trabalho representa uma releitura prática dos conceitos de detecção de intrusão adaptados ao ecossistema Windows.


**Keywords:** Information Security; Brute Force Attacks; FTP; IIS; Windows Server; PowerShell; Automation; Firewall; Case Study.

**Palavras-chave:** Segurança da Informação; Ataques de Força Bruta; FTP; IIS; Windows Server; PowerShell; Automação; Firewall; Estudo de Caso.



🖥️ Ambiente Experimental / Experimental Environment


Para simular o ataque de brute force em FTP, foram utilizadas máquinas virtuais configuradas da seguinte forma:

- **Servidor alvo (Windows Server 2012 R2 com IIS FTP)**
  - Sistema operacional: Windows Server 2012 R2
  - Função instalada: IIS FTP Server

![Funções](imagens/servicos.jpg)

  - Usuários configurados para autenticação via Active Directory (verde) e inativação da autenticação anônima (vermelho)

![Configurações](imagens/configuracoesftp.jpg)


- **Máquina atacante (Linux Kali)**
  - Sistema operacional: Kali Linux 2025.2
  - Ferramentas utilizadas: `nmap`, `medusa`
  - Rede: mesma sub-rede da VM alvo (rede interna Microsoft Hyperv)
    

- **Máquina Cliente**
  - Sistema operacional: Windows 11 24h2
  - Função: Testes de conexão para serviços FTP, SBM e RDP (após obtenção da senha)



## Metodologia / Methodology

 
🔍 Identificando o IP no Kali Linux
No Kali (ou em qualquer distribuição Linux), usamos o comando em um terminal:

-> ip addr

![ipaddr](imagens/ipaddr.jpg)



🌐 Scaneando a rede para identificação dos possíveis hosts


Comando: nmap -sn 192.168.15.0/24

📖 Explicação dos parâmetros

nmap → ferramenta de mapeamento de rede, usada para descobrir hosts e serviços.

-sn → significa "ping scan" -> Com essa opção, o Nmap não escaneia portas, apenas verifica se os hosts estão ativos.

Ele envia pacotes ICMP (ping) e/ou TCP/ARP para identificar máquinas ligadas.

192.168.15.0/24 → intervalo de endereços IP da rede. -> /24 indica máscara de sub-rede 255.255.255.0. -> Isso cobre todos os IPs de 192.168.15.1 até 192.168.15.254.


📊 O que o comando faz
Esse comando percorre todo o segmento de rede 192.168.15.0/24 e retorna uma lista de hosts que responderam, ou seja, que estão online.


![nmaparede](imagens/nmaprede.jpg)



🔍 Scanear host alvo encontrado

Comando: nmap -A -p- -T4 192.168.15.3


📖 Explicação dos parâmetros
nmap → ferramenta de mapeamento de rede.


-A (Aggressive Scan) -> Ativa várias funcionalidades avançadas:

Detecção de sistema operacional (OS detection).

Detecção de versão dos serviços (service version detection).

Scripts NSE padrão (Nmap Scripting Engine).

Traceroute (caminho até o host).

É um modo “agressivo” porque coleta muitas informações de uma vez.


-p-

Escaneia todas as 65.535 portas TCP do host.

Por padrão, o Nmap só escaneia as 1.000 portas mais comuns; com -p-, você garante que nada fique de fora.


-T4

Define o timing template (velocidade do scan).

Vai de -T0 (paranoico, muito lento) até -T5 (insano, muito rápido).

-T4 é rápido e ainda relativamente confiável, usado em redes locais.


192.168.15.3

IP do host alvo que você já identificou como ativo.



📊 O que o comando faz
Esse comando realiza um escaneamento completo e agressivo do host alvo:

Verifica todas as portas TCP abertas.

Identifica quais serviços estão rodando em cada porta e suas versões.

Tenta descobrir o sistema operacional do host.

Executa scripts NSE padrão para coletar informações adicionais (como banners, vulnerabilidades conhecidas, etc.).

Faz traceroute para entender o caminho até o host.





 
