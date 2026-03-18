import json
import os
from typing import TypedDict
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langgraph.graph import StateGraph, END

load_dotenv()

groq_api_key = os.getenv("API_KEY_GROQ")

def get_llm():
    return ChatGroq(
        groq_api_key=groq_api_key, 
        model="llama-3.3-70b-versatile", 
        temperature=0.2)

class EstadoCTI(TypedDict):
    dados_vt: dict
    dados_mb: dict
    dados_otx: dict

    #Estrutura de info em cada nó do grafo:

    identificacao: dict # Informações básicas iniciais.
    propagacao: dict # Informações sobre a disseminação do artefato, como países afetados, métodos de entrega e afins.
    ttps: dict # Comportamento do artefato na execução.
    deteccao: dict # Informações sobre a detecção, como YARA, sandbox, vereditos de AVs.
    relatorio: dict # Descrição final com base nas informações anteriores, incluindo um resumo e uma classificação de risco.

async def no_identificacao(estado: EstadoCTI) -> EstadoCTI:
    llm = get_llm()

    prompt = f"""Você é um especialista em Cyber Threat Intelligence (CTI). Com base nos dados abaixo de três plataformas de threat intelligence, responda APENAS com um JSON válido, sem texto adicional, sem markdown, sem explicações.

Dados do VirusTotal:
{json.dumps(estado["dados_vt"], indent=2)}

Dados do MalwareBazaar:
{json.dumps(estado["dados_mb"], indent=2)}

Dados do AlienVault OTX:
{json.dumps(estado["dados_otx"], indent=2)}

Responda com este JSON:
{{
    "familia": "nome da família do malware",
    "variante": "variante específica se identificável, ou null/desconhecido se não houver identificação clara",
    "nivel_ameaca": "critico | alto | medio | baixo",
    "justificativa_nivel": "por que esse nível de ameaça",
    "threat_actor": "grupo APT ou threat actor associado, ou null/desconhecido se não houver associação clara",
    "contexto_historico": "breve contexto sobre esse malware e sua história, como campanhas famos associadas, evolução ao longo do tempo, etc."
}}"""

    resposta = await llm.ainvoke(prompt)

    try:
        raw = resposta.content.strip()
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0].strip()
        resultado = json.loads(raw)
    except Exception:
        resultado = {"erro": "Falha ao parsear resposta do LLM"}

    return {**estado, "identificacao": resultado}

async def no_propagacao(estado: EstadoCTI) -> EstadoCTI:
    llm = get_llm()

    prompt = f"""Você é um especialista em Cyber Threat Intelligence (CTI). Com base nos dados e na identificação anterior, responda APENAS com um JSON válido, sem texto adicional, sem markdown, sem explicações.

Identificação já realizada:
{json.dumps(estado["identificacao"], indent=2)}

Dados do VirusTotal:
{json.dumps(estado["dados_vt"], indent=2)}

Dados do MalwareBazaar:
{json.dumps(estado["dados_mb"], indent=2)}

Dados do AlienVault OTX:
{json.dumps(estado["dados_otx"], indent=2)}

Responda com este JSON:
{{
    "paises_origem": ["lista de países de origem identificados"],
    "paises_alvo": ["lista de países ou regiões tipicamente alvos desse malware"],
    "primeiro_visto": "data mais antiga identificada nos dados",
    "metodo_distribuicao": "método de distribuição identificado",
    "infraestrutura_c2": ["lista de IPs ou domínios de C2 identificados nos dados"],
    "timeline": "resumo da linha do tempo desse malware desde o primeiro registro"
}}"""

    resposta = await llm.ainvoke(prompt)

    try:
        raw = resposta.content.strip()
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0].strip()
        resultado = json.loads(raw)
    except Exception:
        resultado = {"erro": "Falha ao parsear resposta do LLM"}

    return {**estado, "propagacao": resultado}

async def no_ttps(estado: EstadoCTI) -> EstadoCTI:
    llm = get_llm()

    prompt = f"""Você é um especialista em Cyber Threat Intelligence (CTI) com elevados conhecimentos em MITRE ATT&CK e entendimento de caminho de ataque (Attack Path Analysis). Com base nos dados abaixo, responda APENAS com um JSON válido, sem texto adicional, sem markdown, sem explicações.
    
Identificação realizada:
{json.dumps(estado["identificacao"], indent=2)}

Propagação e infraestrutura:
{json.dumps(estado["propagacao"], indent=2)}

Dados do VirusTotal:
{json.dumps(estado["dados_vt"], indent=2)}

Dados do MalwareBazaar:
{json.dumps(estado["dados_mb"], indent=2)}

Dados do AlienVault OTX:
{json.dumps(estado["dados_otx"], indent=2)}

Responda com este JSON:
{{
    "cadeia_infeccao": "descrição narrativa da cadeia de infecção do início ao fim",
    "ttps": [
        {{
            "tactic": "nome da tática MITRE ATT&CK",
            "technique_id": "T1XXX",
            "technique_name": "nome da técnica",
            "descricao": "como essa técnica é usada por esse artefato especificamente",
            "evidencia": "qual dado nos inputs suporta essa identificação"
        }}
    ],
    "comportamentos_caracteristicos": [
        "lista dos comportamentos mais característicos e únicos desse malware"
    ],
    "tecnicas_evasao": [
        "técnicas usadas para evadir antivírus e soluções de segurança"
    ],
    "mecanismos_persistencia": [
        "como o malware garante sua permanência no sistema"
    ],
    "capacidades": [
        "lista de capacidades do malware: keylogger, screenshot, exfiltração, etc."
    ],
    "impacto": "descrição do impacto efetivo na máquina infectada",
    "artefatos_forenses": {{
        "registry_keys": ["chaves de registro criadas ou modificadas"],
        "arquivos": ["arquivos criados ou modificados"],
        "processos": ["processos criados"],
        "mutexes": ["mutexes utilizados"],
        "scheduled_tasks": ["tarefas agendadas criadas para persistência"],
        "services": ["serviços Windows instalados pelo malware"],
        "usuarios_criados": ["contas de usuário criadas pelo malware"],
        "drivers": ["drivers instalados"],
        "named_pipes": ["pipes nomeados utilizados"],
        "network": ["padrões de tráfego de rede observados"]
    }},
    "indicadores_comprometimento": {{
        "hashes": ["hashes relacionados além do principal"],
        "ips": ["endereços IP maliciosos"],
        "dominios": ["domínios maliciosos"],
        "urls": ["URLs maliciosas"],
        "emails": ["endereços de email usados em campanhas"],
        "fingerprints": ["impressões digitais únicas do malware, como strings específicas, comportamentos únicos, etc."],
        "certificados": ["certificados digitais usados para assinar o malware, se aplicável"]
    }}
}}"""

    resposta = await llm.ainvoke(prompt)

    try:
        raw = resposta.content.strip()
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0].strip()
        resultado = json.loads(raw)
    except Exception:
        resultado = {"erro": "Falha ao parsear resposta do LLM"}

    return {**estado, "ttps": resultado}

async def no_deteccao(estado: EstadoCTI) -> EstadoCTI:
    llm = get_llm()

    prompt = f"""Você é um especialista em Cyber Threat Intelligence (CTI) com foco em detecção e resposta a incidentes. Com base nos dados abaixo, responda APENAS com um JSON válido, sem texto adicional, sem markdown, sem explicações.

Identificação realizada:
{json.dumps(estado["identificacao"], indent=2)}

TTPs e artefatos forenses:
{json.dumps(estado["ttps"], indent=2)}

Regras YARA disponíveis:
{json.dumps(estado["dados_vt"].get("crowdsourced_yara_results", []), indent=2)}

Responda com este JSON:
{{
    "regras_yara": [
        {{
            "nome": "nome da regra",
            "descricao": "o que essa regra detecta",
            "fonte": "origem da regra se identificável nos dados",
            "relevancia": "por que essa regra é relevante para esse malware"
        }}
    ],
    "queries_hunting": [
        {{
            "plataforma": "Splunk | Elastic | QRadar | generico",
            "descricao": "o que essa query detecta",
            "query": "a query em si"
        }}
    ],
    "mitigacoes_d3fend": [
        {{
            "ttp": "T1XXX",
            "technique_name": "nome da técnica ATT&CK",
            "d3fend_id": "D3-XXX",
            "d3fend_name": "nome da técnica D3FEND",
            "acao": "ação específica e concreta para implementar essa mitigação",
            "prioridade": "critica | alta | media | baixa"
        }}
    ],
    "recomendacoes_imediatas": [
        "ações que o analista deve tomar imediatamente numa máquina potencialmente infectada"
    ],
    "recomendacoes_preventivas": [
        "controles e configurações para prevenir infecção futura"
    ]
}}"""

    resposta = await llm.ainvoke(prompt)

    try:
        raw = resposta.content.strip()
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0].strip()
        resultado = json.loads(raw)
    except Exception:
        resultado = {"erro": "Falha ao parsear resposta do LLM"}

    return {**estado, "deteccao": resultado}

async def no_relatorio(estado: EstadoCTI) -> EstadoCTI:
    llm = get_llm()

    prompt = f"""Você é um especialista em Cyber Threat Intelligence (CTI).Com base em toda a análise realizada abaixo, produza um relatório final consolidado. Reesponda APENAS com um JSON válido, sem texto adicional, sem markdown, sem explicações.

Identificação:
{json.dumps(estado["identificacao"], indent=2)}

Propagação e Infraestrutura:
{json.dumps(estado["propagacao"], indent=2)}

TTPs e Cadeia de Infecção:
{json.dumps(estado["ttps"], indent=2)}

Detecção e Mitigação:
{json.dumps(estado["deteccao"], indent=2)}

Responda com este JSON:
{{
    "resumo_executivo": "parágrafo único e direto resumindo a ameaça para um analista de segurança que precisa entender rapidamente o essencial sobre esse malware",
    "score_criticidade": {{
        "valor": 0.0,
        "justificativa": "por que esse score"
    }},
    "iocs_consolidados": {{
        "hashes": [],
        "ips": [],
        "dominios": [],
        "urls": [],
        "emails": []
    }},
    "acoes_prioritarias": [
        {{
            "ordem": 1,
            "acao": "descrição da ação",
            "responsavel": "SOC | TI | Gestão de Riscos | Liderança | Outro",
            "urgencia": "imediata | 24h | 7 dias | 30 dias"
        }}
    ],
    "conclusao": "avaliação final do analista sobre o nível de risco e contexto geral da ameaça"
}}"""

    resposta = await llm.ainvoke(prompt)

    try:
        raw = resposta.content.strip()
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0].strip()
        resultado = json.loads(raw)
    except Exception:
        resultado = {"erro": "Falha ao parsear resposta do LLM"}

    return {**estado, "relatorio": resultado}

def build_agent():
    grafo = StateGraph(EstadoCTI)

    grafo.add_node("identificacao", no_identificacao)
    grafo.add_node("propagacao", no_propagacao)
    grafo.add_node("ttps", no_ttps)
    grafo.add_node("deteccao", no_deteccao)
    grafo.add_node("relatorio", no_relatorio)

    grafo.set_entry_point("identificacao")

    grafo.add_edge("identificacao", "propagacao")
    grafo.add_edge("propagacao", "ttps")
    grafo.add_edge("ttps", "deteccao")
    grafo.add_edge("deteccao", "relatorio")
    grafo.add_edge("relatorio", END)

    return grafo.compile()


async def executar_agente(dados_vt: dict, dados_mb: dict, dados_otx: dict) -> dict:
    pipeline = build_agent()

    estado_inicial = {
        "dados_vt": dados_vt,
        "dados_mb": dados_mb,
        "dados_otx": dados_otx,
        "identificacao": {},
        "propagacao": {},
        "ttps": {},
        "deteccao": {},
        "relatorio": {},
    }

    resultado = await pipeline.ainvoke(estado_inicial)

    return {
        "identificacao": resultado["identificacao"],
        "propagacao": resultado["propagacao"],
        "ttps": resultado["ttps"],
        "deteccao": resultado["deteccao"],
        "relatorio": resultado["relatorio"],
    }