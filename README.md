# API de Análise de Hashes (CTI)

API Rest para análise de hashes de arquivos maliciosos. Utilizando integração com VirusTotal, MalwareBazaar e AlienVault OTX, a API também executa análise automatizada de CTI via LLM (LangGraph + Groq "llama-3.3-70b-versatile").

## Funcionalidades

Consulta de hashes (MD5, SHA1, SHA256, SHA512) em três plataformas de Threat Intelligence com tiers gratuitos de consumo; 

Análise de Inteligência automatizada com identificação de família, variante, TTPs (MITRE ATT&CK), modo de distribuição e relatório executivo;

Histórico de consultas em banco de dados local (SQLite);

Autenticação via API Key;

Rate limiting (considerando o uso de APIs gratuitas cujas requisições são limitadas);

Security Headers do FastAPI.

## Pré-Requisitos

Python 3.11+

Chaves de API: VirusTotal (https://www.virustotal.com), MalwareBazaar (https://bazaar.abuse.ch), AlienVaultOTX (https://otx.alienvault.com) e Grog (https://console.groq.com).

## Como executar

**1. Clone o repositório**
```bash
git clone <url-do-repositorio>
cd <pasta-do-projeto>
```

**2. Crie e ative o ambiente virtual**
```bash
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac
```

**3. Instale as dependências**
```bash
pip install -r requirements.txt
```

**4. Configure as variáveis de ambiente**
```bash
cp .env.example .env
```
Edite o `.env` com suas chaves de API. O campo `APP_API_KEY` pode ser qualquer string que escolher. Ela será usada para autenticar nas requisições. 

**5. Inicie a API**
```bash
uvicorn main:app --reload
```

A API estará disponível em `http://localhost:8000/` / `http://127.0.0.1:8000/`

## DETALHAMENTO 

Acesse `http://localhost:8000/docs` para usar o Swagger UI. 

Antes da requisição, clique em **Authorize** e insira o valor da `APP_API_KEY`, conforme tenha escolhido para se autenticar.

Todas os endpoints exigem o header `X-API-Key: <valor-do-APP_API_KEY>`. 

## Endpoints

`/root` - [GET] - Status da API

`/hash/scan` - [POST] - Escaneia um hash nas três plataformas e executa a análise com o LLM.

`/history/`- [GET] - Lista histórico de consultas. Por padrão, recorre as 20 últimas. Conteúdo resumido.

`/history/{id}` - [GET] - Detalha o registro em específico por completo.

## Docker

Se desejar, pode executar através do Docker disponibilizado.

**Build da imagem**
```bash 
docker build -t jsb-cti-api .
```

**Rode o container**

```bash
docker run -p 8000:8000 --env-file .env jsb-cti-api
``` 

O arquivo .env não é incluído na imagem, sendo usadas em runtime. Lembre-se de alterar com suas próprias keys.







