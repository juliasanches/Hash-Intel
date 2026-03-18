from fastapi import FastAPI, HTTPException, Depends, Header, Query, Request, Security
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from datetime import datetime
from database import init_db, save_scan, get_history, get_history_complete
from agent import executar_agente
from dotenv import load_dotenv
import httpx
import asyncio
import os
import re

load_dotenv()

# Definindo um ratelimit para o consumo das APIs externas, pois são gratuitas.
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Desafio MELI CTI- API de Análise de Hashes", description="API para consultar informações sobre hashes de arquivos em distintas plataformas.", version="1.0")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

init_db()

api_key = os.getenv("API_KEY_VIRUSTOTAL")
api_key_mb = os.getenv("API_KEY_MALWAREBAZAAR")
api_key_otx = os.getenv("API_KEY_OTX")

# Manter boas práticas de Security Header. 
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Cache-Control"] = "no-store"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Também para manter uma boa prática, a API vai exigir autenticação. 
api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=True)

async def verify_api_key(x_api_key: str = Security(api_key_scheme)):
    app_key = os.getenv("APP_API_KEY")
    if not app_key or x_api_key != app_key:
        raise HTTPException(status_code=401, detail="Não autorizado.")

# Validar o formato do hash para evitar consultas corrompidas e envio de injection.
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$")

def validate_hash(hash: str):
    if not HASH_PATTERN.match(hash):
        raise HTTPException(
            status_code=422,
            detail="Hash inválido. Informe um hash MD5, SHA1, SHA256 ou SHA512 válido."
        )


def unix_datetime(timestamp): # Converte timestamp unix para formato legível. Necessário por conta do VT.
    if not timestamp:
        return None
    return datetime.fromtimestamp(timestamp).strftime("%d/%m/%Y")


def str_date(date_str): # Converte string de data para formato legível. Necessário por conta do Malware Bazaar.
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%d/%m/%Y")
    except:
        return date_str

async def virus_total(hash: str):
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(
            f"https://www.virustotal.com/api/v3/files/{hash}",
            headers={"x-apikey": api_key}
        )

    if response.status_code == 404:
        return {"status": "Not Found", "message": "Hash não encontrado na base de dados do Virus Total."}

    if response.status_code == 429:
        return {"status": "Too Many Requests", "message": "Limite diário de requisições atingido. Tente novamente mais tarde."}

    if response.status_code != 200:
        return {"status": "Error", "message": f"Erro ao consultar o Virus Total: {response.status_code}"}

    data = response.json()
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values())
    malicious = stats.get("malicious", 0)

    if total == 0:
        return {"status": "Pending", "message": "Nenhuma análise disponível para este hash."}

    if malicious == 0:
        return {"status": "Clean", "message": "Nenhuma detecção maliciosa encontrada para este hash."}

    return {
        "nome": attrs.get("meaningful_name"),
        "tipo": attrs.get("type_description"),
        "malicious": malicious,
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": total,
        "detections": f"{malicious}/{total} motores de análise detectaram este hash como malicioso.",
        "threat_label": attrs.get("popular_threat_classification", {})
                            .get("suggested_threat_label"),
        "creation_date": unix_datetime(attrs.get("creation_date")),
        "last_analysis_date": unix_datetime(attrs.get("last_analysis_date")),
        "first_submission_date": unix_datetime(attrs.get("first_submission_date")),
        "sandbox_verdicts": attrs.get("sandbox_verdicts", {}),
        "crowdsourced_yara_results": attrs.get("crowdsourced_yara_results", []),
    }

async def malware_bazaar(hash: str):
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"Auth-Key": api_key_mb},
            data={"query": "get_info", "hash": hash},
        )

    if response.status_code != 200:
        return {"status": "Error", "message": f"Erro ao consultar o Malware Bazaar: {response.status_code}"}

    data = response.json()
    if data.get("query_status") != "ok":
        return {"status": "Not Found", "message": "Hash não encontrado."}

    entry = data.get("data", [{}])[0]

    return {
        "mb_status": data.get("query_status"),
        "signature": entry.get("signature"),
        "tags": entry.get("tags", []),
        "first_seen": str_date(entry.get("first_seen")),
        "last_seen": str_date(entry.get("last_seen")),
        "file_information": entry.get("file_information", {}),
        "delivery_method": entry.get("delivery_method"),
        "ssdeep": entry.get("ssdeep"),
        "origin_country": entry.get("origin_country"),
        "vendor_intel": entry.get("vendor_intel", {}),
    }

async def alien_vault(hash: str):
    url_general = f"https://otx.alienvault.com/api/v1/indicators/file/{hash}/general"
    url_analysis = f"https://otx.alienvault.com/api/v1/indicators/file/{hash}/analysis"

    async with httpx.AsyncClient(timeout=15.0) as client:
        general_response, analysis_response = await asyncio.gather(
            client.get(url_general, headers={"X-OTX-API-KEY": api_key_otx}),
            client.get(url_analysis, headers={"X-OTX-API-KEY": api_key_otx}),
            return_exceptions=True
        )

    if isinstance(general_response, Exception) or general_response.status_code == 404:
        return {"status": "Not Found", "message": "Hash não encontrado no AlienVault OTX."}

    if general_response.status_code != 200:
        return {"status": "Error", "message": f"Erro ao consultar o AlienVault OTX: {general_response.status_code}"}

    general = general_response.json()

    analysis = {}
    if not isinstance(analysis_response, Exception) and analysis_response.status_code == 200:
        analysis = analysis_response.json()

    info = analysis.get("analysis", {}).get("info", {}).get("results", {})
    dynamic = analysis.get("analysis", {}).get("dynamic", {}).get("results", {})
    network = dynamic.get("network", {})

    return {
        "pulse_count": general.get("pulse_info", {}).get("count", 0),
        "pulses": [
            {
                "name": p.get("name"),
                "author": p.get("author_name"),
                "tags": p.get("tags", []),
                "malware_families": p.get("malware_families", []),
                "attack_ids": p.get("attack_ids", []),
            }
            for p in general.get("pulse_info", {}).get("pulses", [])[:5]
        ],
        "attack_ids": list({
            attack["id"]
            for p in general.get("pulse_info", {}).get("pulses", [])
            for attack in p.get("attack_ids", [])
            if attack.get("id")
        }),
        "type_title": general.get("type_title"),
        "reputation": general.get("reputation"),
        "analysis": {
            "exiftool": info.get("exiftool", {}),
            "strings": info.get("strings", [])[:20],
            "http_requests": network.get("http", []),
            "dns_lookups": network.get("dns", []),
            "tcp_connections": network.get("tcp", []),
            "processes": dynamic.get("processes", []),
            "signatures": dynamic.get("signatures", []),
        }
    }

@app.get("/")
def root():
    return {"status": "Online", "message": "API Virus Total - MELI Challenge"}


@app.post("/hash/scan",
          summary="Escanear Hash",
          description="Endpoint para escanear um hash nas plataformas Virus Total, Malware Bazaar e AlienVault OTX. O resultado é salvo no histórico de consultas.",
          dependencies=[Depends(verify_api_key)])
@limiter.limit("10/minute")
async def scan_hash(request: Request, hash: str):
    validate_hash(hash)

    try:
        vt_result, mb_result, otx_result = await asyncio.gather(
            virus_total(hash),
            malware_bazaar(hash),
            alien_vault(hash),
            return_exceptions=True
        )

        analise_agente = await executar_agente(
            dados_vt=vt_result,
            dados_mb=mb_result,
            dados_otx=otx_result
        )

        result = {
            "hash": hash,
            "virus_total": vt_result,
            "malware_bazaar": mb_result,
            "alien_vault": otx_result,
            "analise_cti": analise_agente,
        }
        save_scan(hash, result)
        return result

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Erro interno ao processar o hash.")


@app.get("/history",
         summary="Histórico de Consultas",
         description="Endpoint para consultar o histórico de hashes escaneados. Retorna os últimos 20 registros por padrão, mas é possível ajustar a quantidade através do parâmetro 'limit' (máximo 100).",
         dependencies=[Depends(verify_api_key)])
@limiter.limit("30/minute")
def history(request: Request, limit: int = Query(default=20, ge=1, le=100)):
    return get_history(limit)

@app.get("/history/{id}",
         summary="Histórico de Consulta detalhado",
         description="Endpoint para consultar um registro específico no histórico de consultas, a partir do ID salvo no banco de dados. Retorna o resultado completo do escaneamento para o hash.",
         dependencies=[Depends(verify_api_key)])
@limiter.limit("30/minute")
def history_detail(request: Request, id: int):
    result = get_history_complete(id)
    if not result:
        return {"status": "Not Found", "message": f"Histórico com id {id} não foi encontrado."}
    return result
