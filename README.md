📂 Case Study: FTP & SMB Brute Force in Windows
<br>

Case study: brute force detection and automated blocking in Windows IIS FTP environments.
<br>
---
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

🖥️ Ambiente Experimental / Experimental Environment
<br>
---
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

<br>

🔹 Máquina Atacante
-SO: Kali Linux 2025.2
-Ferramentas: nmap, medusa
-Rede: mesma sub-rede da VM alvo (rede interna Hyper-V)

<br>

🔹 Máquina Cliente
-SO: Windows 11 24h2
-Função: Testes de conexão para serviços FTP, SMB e RDP (após obtenção da senha)

<br>

⚙️Metodologia / Methodology
<br>
---
<br>

🔍 Identificando o IP no Kali Linux
No Kali (ou em qualquer distribuição Linux), usamos o comando: ip addr

![ipaddr](imagens/ipaddr.jpg)

<br>

🌐 Scaneando a rede
Para identificar os possíveis hosts ativos com o comando: nmap -sn 192.168.15.0/24

![nmaparede](imagens/nmaprede.jpg)

<br>

📖 Explicação dos parâmetros:

<br>

nmap → ferramenta de mapeamento de rede

-sn → ping scan, apenas verifica hosts ativos

192.168.15.0/24 → intervalo de endereços da rede (255.255.255.0 → .1 até .254)

<br>

📊 O que o comando faz Percorre todo o segmento de rede e retorna uma lista de hosts online.

<br>

🔍 Escaneando o host alvo:
Após identificar o host 192.168.15.3, realizamos um scan completo com o comando: nmap -A -p- -T4 192.168.15.3

<br>

📖 Explicação dos parâmetros

-A → modo agressivo (OS detection, versão de serviços, scripts NSE, traceroute)

-p- → escaneia todas as 65.535 portas TCP

-T4 → timing rápido e confiável para redes locais

192.168.15.3 → IP do host alvo

<br>

📊 O que o comando faz:

<br>

-Verifica todas as portas abertas

-Identifica serviços e versões

<br>

![nmaptargetports](imagens/nmaptargetportas.jpg)

<br>

-Descobre o sistema operacional

![nmaptargetos](imagens/nmaptargetos.jpg)

<br>

🔑 Criação da Password List / Password List Creation
<br>
---
<br>

Para simular ataques de força bruta contra o serviço FTP, foi criada uma lista de senhas personalizada utilizando Python. O script foi executado no Google Colab, permitindo edição e execução rápida em ambiente online.

<br>

📜 Script em Python

<br>

```python
# Script para gerar lista de senhas

# Nome do arquivo de saída
arquivo = "password_list.txt"

# Padrões de símbolos
padroes = [
    "{}*",
    "{}@",
    "@{}@",
    "*{}*",
    "*{}@",
    "@{}*"
]

# Sufixos comuns (anos)
letras = ["2010", "2011", "2012", "2013", "2014", "2015",
          "2016", "2017", "2018", "2019", "2020", "2021",
          "2022", "2023", "2024", "2025"]

# Senhas padrão conhecidas
senhas_padrao = [
    "admin", "Admin", "password", "Password", "root", "htmaster", "Htmaster",
    "123", "1234", "12345", "123456", "1234567", "12345678", "123456789",
    "100senha", "100senh@", 
    "Mudar123", "Mudar1234", "Mudar12345","Mudar123456",
    "mudar123", "mudar12345", "mudar123456", 
    "a1b1c1d1", "a1b2c3d4"
]

# Criar lista e salvar no arquivo
with open(arquivo, "w") as f:
    # 1. Senhas padrão puras
    for senha in senhas_padrao:
        f.write(senha + "\n")
    
    # 2. Senhas padrão com máscaras
    for senha in senhas_padrao:
        for p in padroes:
            f.write(p.format(senha) + "\n")
    
    # 3. Senhas padrão com anos adicionados
    for senha in senhas_padrao:
        for letra in letras:
            f.write(senha + letra + "\n")
            f.write(letra + senha + "\n")
            f.write(letra + senha + letra + "\n")
    
    # 4. Senhas padrão + anos + máscaras
    for senha in senhas_padrao:
        for letra in letras:
            for p in padroes:
                f.write(p.format(senha + letra) + "\n")
                f.write(p.format(letra + senha) + "\n")
                f.write(p.format(letra + senha + letra) + "\n")

print(f"Lista gerada com sucesso em: {arquivo}")
```

<br>

📖 Explicação:

<br>

- senhas_padrao → contém senhas comuns (admin, root, 123456, mudar123 etc.).

- letras → adiciona anos como sufixos/prefixos (2010–2025), simulando padrões reais de usuários.

- padroes → aplica símbolos como *, @ em diferentes posições, aumentando a complexidade.

- Loops → combinam senhas padrão com anos e símbolos, gerando centenas de variações automaticamente.

- Saída → todas as combinações são salvas em password_list.txt.

<br>

📊 Resultado:

<br>

O arquivo final password_list.txt contém uma lista extensa de senhas que imita padrões reais de usuários.

