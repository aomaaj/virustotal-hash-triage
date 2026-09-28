# VirusTotal Hash Triage Tool

Ferramenta leve de automação e triagem de Threat Intelligence desenvolvida para analistas de SOC (Tier 1) e equipes de Resposta a Incidentes. O script realiza consultas automatizadas na API v3 do VirusTotal para avaliar rapidamente Indicadores de Comprometimento (IoCs), identificando se hashes MD5, SHA-1 ou SHA-256 estão associados a malwares conhecidos.

---

## Visao Geral

Na rotina operacional de Seguranca da Informacao e SecOps, analistas frequentemente se deparam com hashes desconhecidos gerados por alertas de EDR, SIEM ou anexos de e-mails suspeitos de phishing.

Copiar e colar hashes manualmente em portais web consome tempo e cria gargalos na triagem de alertas. Este script agiliza a investigacao de artefatos consultando a API v3 do VirusTotal de forma programatica, validando a estrutura do hash, processando a taxa de deteccao dos motores antivirus e gerando relatorios estruturados no terminal ou em formato JSON.

---

## Funcionalidades Principais

- Validacao Previa de Algoritmos: Valida a estrutura dos hashes via expressoes regulares para MD5 (32 caracteres hexadecimais), SHA-1 (40 caracteres) e SHA-256 (64 caracteres) antes de realizar requisicoes de rede, evitando consumo desnecessario da cota da API.
- Modos Flexiveis de Execucao:
  - Modo Interativo: Solicita o hash via prompt caso o script seja executado sem parametros.
  - Consulta Unica via CLI: Suporta consultas diretas utilizando o parametro `--hash <hash>`.
  - Processamento em Lote: Le arquivos de texto com multiplos hashes (um por linha) utilizando `--file <caminho>`.
- Classificacao de Ameacas:
  - MALICIOUS: Alto numero de deteccoes por motores antivirus (>= 5 motores).
  - SUSPICIOUS: Poucas deteccoes ou heuristica suspeita (1 a 4 motores).
  - CLEAN: Nenhuma deteccao maliciosa registrada.
  - UNKNOWN: Artefato nunca observado ou submetido a base do VirusTotal.
- Enriquecimento com Threat Intelligence: Extrai nomes conhecidos do arquivo, tipo de formato, reputacao na comunidade e rotulo sugerido da ameaca (ex: trojan, ransomware, adware).
- Exportacao Estruturada: Suporta exportar o resultado completo da triagem em formato JSON (`--export <arquivo.json>`) para documentacao de incidentes ou abertura de chamados.
- Praticas de Seguranca (DevSecOps): Suporta leitura da chave de API por variaveis de ambiente ou arquivo `.env`, evitando credenciais expostas no codigo.

---

## Fluxo de Execucao

```
+--------------------------------------------------------+
| Entrada: Prompt Interativo / Argumento CLI / Arquivo   |
+--------------------------------------------------------+
                           |
                           v
+--------------------------------------------------------+
| Validacao Regex: MD5 (32) / SHA-1 (40) / SHA-256 (64)  |
+--------------------------------------------------------+
                           |
                           v
+--------------------------------------------------------+
| Requisicao HTTP na API v3 do VirusTotal (Header Auth)  |
+--------------------------------------------------------+
                           |
       +-------------------+-------------------+
       |                   |                   |
       v                   v                   v
[200 OK: Dados]      [404: Nao Encontrado] [429 / 401 / Erro]
       |                   |                   |
       v                   v                   v
Processa Metricas      Veredito:           Trata Erro /
e Familia de Ameaca    UNKNOWN             Notifica Analista
       |
       +-------------------+
                           |
                           v
+--------------------------------------------------------+
| Saida: Resumo Formatado no Terminal e/ou Export JSON   |
+--------------------------------------------------------+
```

---

## Requisitos

- Python 3.8 ou superior
- Chave de API publica do VirusTotal (gratuita em virustotal.com)

---

## Instalacao

1. Clone o repositorio:
```bash
git clone https://github.com/aomaaj/virustotal-hash-triage.git
cd virustotal-hash-triage
```

2. (Opcional) Crie e ative um ambiente virtual:
```bash
python -m venv venv
# No Windows:
.\venv\Scripts\activate
# No Linux/macOS:
source venv/bin/activate
```

3. Instale as dependencias (opcional, o script tambem possui suporte nativo sem bibliotecas externas):
```bash
pip install -r requirements.txt
```

---

## Configuracao da Chave de API

Defina sua chave de API do VirusTotal de forma segura utilizando um dos metodos:

### Metodo A: Arquivo de Ambiente (.env)
Copie o modelo de exemplo e insira sua chave:
```bash
copy .env.example .env
```
Edite o arquivo `.env`:
```ini
VT_API_KEY=sua_chave_virustotal_aqui
```

### Metodo B: Variavel de Ambiente do Sistema
- Windows (PowerShell):
  ```powershell
  $env:VT_API_KEY="sua_chave_virustotal_aqui"
  ```
- Linux / macOS:
  ```bash
  export VT_API_KEY="sua_chave_virustotal_aqui"
  ```

---

## Como Usar

### 1. Modo Interativo
Execute o script sem argumentos para digitar o hash no prompt:
```bash
python hash_triage.py
```

### 2. Consulta Direta de Hash Unico
```bash
python hash_triage.py --hash 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c
```

### 3. Processamento em Lote (Multiplos Hashes)
Analise varios hashes listados em um arquivo de texto:
```bash
python hash_triage.py --file sample_hashes.txt
```

### 4. Exportando Resultados para JSON
Gere um relatorio JSON com todas as analises realizadas:
```bash
python hash_triage.py --file sample_hashes.txt --export relatorio_triagem.json
```

---

## Exemplo de Saida no Terminal

```text
[INFO] Consultando VirusTotal para SHA-256: 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c...

============================================================
Target Hash : 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c
------------------------------------------------------------
Verdict     : [ALERT] MALICIOUS
File Name   : ed01ebbf4704cbf7bddde7d71d8670aa.bin
File Type   : Win32 EXE
Threat Label: trojan.ransom.wannacry
Reputation  : -687
------------------------------------------------------------
Detections  : 68/73 engines flagged as malicious
Breakdown   : Malicious: 68 | Suspicious: 0 | Harmless: 0 | Undetected: 5
============================================================
```

---

## Casos de Uso em SOC e Seguranca Defensiva

- Triagem de Incidentes: Classificacao imediata de binarios suspeitos detectados em endpoints da rede corporativa.
- Investigacao de Phishing: Verificacao de hashes de anexos extraidos de e-mails suspeitos reportados por usuarios.
- Threat Hunting: Cruzamento de historicos de hashes de processos em logs de SIEM contra bases de inteligencia de ameacas.
- Consolidacao de Indicadores: Padronizacao de metricas de artefatos para documentacao de incidentes e revisao de vulnerabilidades.
