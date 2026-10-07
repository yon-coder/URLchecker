import os
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse
import ipaddress
from pathlib import Path
import hashlib
from typing import Dict, List, Set, Tuple, Any, Optional

# ==============================================================================
# CONFIGURAÇÕES CENTRAIS E CONSTANTES
# ==============================================================================
BASE_DIR = Path(__file__).resolve().parent
CACHE_DIR = BASE_DIR / "cache"
CACHE_EXPIRACAO_SEGUNDOS = 86400  # Cache válido por 24 horas

HTTP_TIMEOUT_FEEDS = 10
HTTP_TIMEOUT_ANALISE = 5
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
HEADERS = {'User-Agent': USER_AGENT}

# Pesos de Suspeita Heurística
PESO_IP_DIRETO = 25       # Oculta registro de domínio real; forte indicador de suspeita.
PESO_URL_LONGA = 5        # Indicador fraco isoladamente (comum em tokens/URLs legítimas).
PESO_HTTP = 5             # Indicador fraco isoladamente (sistemas legados).
PESO_PALAVRA_CHAVE = 5    # Indicador fraco isoladamente (usado em portais legítimos).
PESO_COMBINADO = 15       # Bônus ativado apenas em acúmulo de múltiplos indicadores fracos.
PESO_REDIR_SUBDOMINIO = 5 # Baixo risco (redirecionamentos internos/CDNs).
PESO_REDIR_EXTERNO = 20   # Risco maior (redirecionamento para domínios não relacionados).

LIMITE_COMPRIMENTO_URL = 75
MINIMO_INDICADORES_FRACOS = 3
PALAVRAS_CHAVE_SUSPEITAS = ['login', 'verify', 'account', 'banking', 'secure', 'update', 'senha']

# Faixas de Pontuação
LIMIAR_BAIXO_RISCO = 20      # 0 a 19: Baixo Risco
LIMIAR_RISCO_MODERADO = 40   # 20 a 39: Risco Moderado
LIMIAR_ALTO_RISCO = 60       # 40 a 59: Alto Risco
                             # 60+: Muito Alto Risco

FEEDS_AMEACAS = [
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://openphish.com/feed.txt",
    "https://threatfox.abuse.ch/export/urls/recent/"
]


# ==============================================================================
# FUNÇÕES DE NORMALIZAÇÃO E VALIDAÇÃO
# ==============================================================================
def eh_url_valida(url: str) -> bool:
    """Valida se a URL possui esquema HTTP/HTTPS e hostname definidos."""
    try:
        resultado = urlparse(url)
        return all([resultado.scheme in ('http', 'https'), resultado.netloc])
    except ValueError:
        return False


def normalizar_url(url: str) -> str:
    """Padroniza esquema e hostname para comparação precisa, preservando o caminho."""
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        if path == '/':
            path = ''
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{netloc}{path}{query}"
    except ValueError:
        return url


def dominios_relacionados(dom1: str, dom2: str) -> bool:
    """Verifica se dois hostnames pertencem ao mesmo domínio raiz."""
    partes1 = dom1.split('.')
    partes2 = dom2.split('.')
    if len(partes1) >= 2 and len(partes2) >= 2:
        return partes1[-2:] == partes2[-2:]
    return dom1 == dom2


def eh_endereco_ip(host: str) -> bool:
    """Detecta se o hostname é um IPv4 ou IPv6 válido utilizando a biblioteca ipaddress."""
    host_limpo = host.split(':')[0].strip('[]')
    try:
        ipaddress.ip_address(host_limpo)
        return True
    except ValueError:
        return False


# ==============================================================================
# GESTÃO DE CACHE E BLACKLISTS ESTÁTICAS
# ==============================================================================
def obter_caminho_cache(feed_url: str) -> Path:
    """Gera um nome de arquivo único e seguro para o cache de cada feed."""
    nome_arquivo = hashlib.md5(feed_url.encode()).hexdigest() + ".txt"
    return CACHE_DIR / nome_arquivo


def carregar_base_de_dados() -> Set[str]:
    """Gerencia o download e carregamento das URLs, mantendo caches separados por feed."""
    print("⏳ [Fase 1] Verificando bases de dados estáticas (Blacklists)...")
    
    # Cria a pasta cache/ automaticamente se ela não existir
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    urls_maliciosas = set()
    tempo_atual = time.time()

    for feed_url in FEEDS_AMEACAS:
        arquivo_cache = obter_caminho_cache(feed_url)
        usar_cache = False

        if arquivo_cache.exists():
            tempo_modificacao = arquivo_cache.stat().st_mtime
            if (tempo_atual - tempo_modificacao) < CACHE_EXPIRACAO_SEGUNDOS:
                usar_cache = True

        if usar_cache:
            try:
                with open(arquivo_cache, 'r', encoding='utf-8') as f:
                    for linha in f:
                        linha_limpa = linha.strip()
                        if linha_limpa:
                            urls_maliciosas.add(linha_limpa)
                print(f"  └─ 📦 Carregado do cache : {feed_url}")
            except Exception as e:
                print(f"  └─ ⚠️ Falha ao ler cache de {feed_url}: {e}")
        else:
            try:
                req = urllib.request.Request(feed_url, headers=HEADERS)
                with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_FEEDS) as resposta:
                    linhas = resposta.read().decode('utf-8', errors='ignore').splitlines()
                    
                    urls_feed = set()
                    for linha in linhas:
                        linha_limpa = linha.strip()
                        if linha_limpa and not linha_limpa.startswith('#'):
                            url_norm = normalizar_url(linha_limpa)
                            urls_feed.add(url_norm)
                            urls_maliciosas.add(url_norm)
                    
                    with open(arquivo_cache, 'w', encoding='utf-8') as f:
                        for u in urls_feed:
                            f.write(f"{u}\n")
                            
                print(f"  └─ 🌐 Baixado e cacheado: {feed_url}")

            except urllib.error.HTTPError as e:
                print(f"  └─ ⚠️ Erro HTTP {e.code} ao acessar {feed_url}")
            except urllib.error.URLError as e:
                print(f"  └─ ⚠️ Erro de conexão ao acessar {feed_url}: {e.reason}")
            except TimeoutError:
                print(f"  └─ ⚠️ Tempo limite excedido ao baixar {feed_url}")

    print(f"✅ Base carregada! {len(urls_maliciosas):,} URLs conhecidas na memória.\n")
    return urls_maliciosas


# ==============================================================================
# MOTOR DE ANÁLISE DINÂMICA (HEURÍSTICA)
# ==============================================================================
def classificar_score(score: int) -> Tuple[str, str, str]:
    """Retorna a classificação, explicação do risco e recomendação ao usuário."""
    if score < LIMIAR_BAIXO_RISCO:
        nivel = "BAIXO RISCO ✅"
        explicacao = "A URL não apresentou indícios significativos de comportamento suspeito."
        recomendacao = "Nenhum indicador crítico foi encontrado, mas sempre verifique o remetente do link antes de inserir dados de login."
    elif score < LIMIAR_RISCO_MODERADO:
        nivel = "RISCO MODERADO ⚠️"
        explicacao = "A URL possui características atípicas isoladas que elevam o grau de suspeita."
        recomendacao = "Acesse apenas se conhecer e confiar no remetente. Evite inserir credenciais de acesso."
    elif score < LIMIAR_ALTO_RISCO:
        nivel = "ALTO RISCO 🚨"
        explicacao = "A URL reúne múltiplos indicadores de risco associados a páginas fraudulentas."
        recomendacao = "Evite o acesso a este link. A estrutura indica uma provável tentativa de engenharia social."
    else:
        nivel = "MUITO ALTO RISCO ☠️"
        explicacao = "A URL possui padrão comportamental fortemente compatível com golpes de phishing ou malware."
        recomendacao = "NÃO ACESSE ESTE LINK. Altíssima probabilidade de ser uma ameaça digital."

    return nivel, explicacao, recomendacao


def testar_redirecionamento(url: str, domain_original: str) -> Tuple[int, str, str]:
    """Avalia redirecionamentos de forma segura sem interpretar falhas de acesso como maliciosas."""
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_ANALISE) as resposta:
            url_final = resposta.geturl()
            domain_final = urlparse(url_final).netloc
            
            if domain_final and domain_final != domain_original:
                if dominios_relacionados(domain_original, domain_final):
                    return (
                        PESO_REDIR_SUBDOMINIO,
                        f"Redirecionamento para subdomínio/domínio relacionado ({domain_final})",
                        "Conexão bem-sucedida"
                    )
                else:
                    return (
                        PESO_REDIR_EXTERNO,
                        f"Redirecionamento para domínio externo não relacionado ({domain_final})",
                        "Conexão bem-sucedida"
                    )
            return 0, "Sem redirecionamento externo", "Conexão bem-sucedida"

    except urllib.error.HTTPError as e:
        return 0, "Não foi possível avaliar redirecionamentos", f"Erro HTTP {e.code} ({e.reason})"
    except urllib.error.URLError as e:
        return 0, "Não foi possível avaliar redirecionamentos", f"Falha na conexão ({e.reason})"
    except TimeoutError:
        return 0, "Não foi possível avaliar redirecionamentos", "Tempo limite de resposta excedido"


def analisar_heuristica_url(url: str) -> Dict[str, Any]:
    """Executa a análise dinâmica e atribui pontuação de suspeita à URL."""
    pontos_suspeitos = 0
    indicadores = []
    indicadores_fracos = 0
    
    parsed = urlparse(url)
    domain = parsed.netloc

    # 1. Verificação de Endereço IP
    if eh_endereco_ip(domain):
        pontos_suspeitos += PESO_IP_DIRETO
        indicadores.append("Uso de endereço IP direto em substituição ao nome de domínio")

    # 2. Comprimento da URL
    if len(url) > LIMITE_COMPRIMENTO_URL:
        pontos_suspeitos += PESO_URL_LONGA
        indicadores_fracos += 1
        indicadores.append(f"Comprimento extenso da URL (maior que {LIMITE_COMPRIMENTO_URL} caracteres)")

    # 3. Palavras-chave de Engenharia Social
    if any(palavra in url.lower() for palavra in PALAVRAS_CHAVE_SUSPEITAS):
        pontos_suspeitos += PESO_PALAVRA_CHAVE
        indicadores_fracos += 1
        indicadores.append("Presença de palavras-chave comuns em páginas de autenticação/fraude")

    # 4. Protocolo HTTP não criptografado
    if parsed.scheme == 'http':
        pontos_suspeitos += PESO_HTTP
        indicadores_fracos += 1
        indicadores.append("Uso de protocolo não criptografado (HTTP)")

    # 5. Efeito Combinado de Indicadores Fracos
    if indicadores_fracos >= MINIMO_INDICADORES_FRACOS:
        pontos_suspeitos += PESO_COMBINADO
        indicadores.append("Combinação de múltiplos indicadores de risco secundários")

    # 6. Teste de Redirecionamento
    peso_redir, msg_redir, status_conexao = testar_redirecionamento(url, domain)
    pontos_suspeitos += peso_redir
    if peso_redir > 0:
        indicadores.append(msg_redir)

    nivel, explicacao, recomendacao = classificar_score(pontos_suspeitos)

    return {
        "score": pontos_suspeitos,
        "nivel": nivel,
        "explicacao": explicacao,
        "recomendacao": recomendacao,
        "indicadores": indicadores,
        "status_conexao": status_conexao,
        "redirecionamento": msg_redir
    }


# ==============================================================================
# APRESENTAÇÃO E RELATÓRIO
# ==============================================================================
def exibir_relatorio(url_analisada: str, em_blacklist: bool, dados_heuristica: Optional[Dict[str, Any]] = None) -> None:
    """Exibe um relatório estruturado e explicativo dos resultados da verificação."""
    print("\n" + "=" * 65)
    print("           🛡️ RELATÓRIO DE ANÁLISE DE SEGURANÇA DA URL")
    print("=" * 65)
    print(f"📍 URL Analisada      : {url_analisada}")

    if em_blacklist:
        print("📋 Status em Blacklist: ENCONTRADA 🚨")
        print("-" * 65)
        print("🚨 CLASSIFICAÇÃO        : AMEAÇA CONFIRMADA ☠️")
        print("📝 Diagnóstico          : A URL consta em bases públicas de distribuição de malware ou phishing.")
        print("💡 Ação Recomendada     : NÃO ACESSE ESTE LINK em nenhuma hipótese.")
    else:
        print("📋 Status em Blacklist: NÃO ENCONTRADA ✅")
        print("-" * 65)
        if dados_heuristica:
            print(f"📊 Score de Suspeita   : {dados_heuristica['score']}/100")
            print(f"🚨 Classificação       : {dados_heuristica['nivel']}")
            print(f"📝 Diagnóstico         : {dados_heuristica['explicacao']}")
            print(f"🌐 Status da Conexão   : {dados_heuristica['status_conexao']}")
            print(f"🔄 Redirecionamento    : {dados_heuristica['redirecionamento']}")
            
            print("\n🚩 Indicadores Identificados:")
            if dados_heuristica['indicadores']:
                for ind in dados_heuristica['indicadores']:
                    print(f"  • {ind}")
            else:
                print("  • Nenhum fator atípico foi identificado.")

            print(f"\n💡 Recomendação        : {dados_heuristica['recomendacao']}")

    print("=" * 65)
    print("ℹ️ Nota: A análise heurística indica o grau de probabilidade e suspeita,")
    print("   não constituindo garantia absoluta da presença ou ausência de ameaças.")
    print("=" * 65 + "\n")


def verificar_url() -> None:
    base_urls = carregar_base_de_dados()

    print("-" * 65)
    print("🛡️  SISTEMA HÍBRIDO DE VERIFICAÇÃO DE URLs")
    print(" (1) Consulta a Blacklists  |  (2) Análise Dinâmica Heurística")
    print(" Digite 'sair' para encerrar.")
    print("-" * 65)

    while True:
        link_usuario = input("🔗 Cole a URL para verificar: ").strip()

        if link_usuario.lower() == 'sair':
            print("Encerrando o programa... Navegue com segurança!")
            break

        if not link_usuario:
            continue

        if not eh_url_valida(link_usuario):
            print("❌ ERRO: URL inválida. Certifique-se de incluir http:// ou https://\n")
            continue

        link_normalizado = normalizar_url(link_usuario)

        if link_normalizado in base_urls or link_usuario in base_urls:
            exibir_relatorio(link_usuario, em_blacklist=True)
        else:
            print("🔎 URL ausente das blacklists. Executando análise dinâmica...")
            resultado_heuristico = analisar_heuristica_url(link_normalizado)
            exibir_relatorio(link_usuario, em_blacklist=False, dados_heuristica=resultado_heuristico)


if __name__ == "__main__":
    verificar_url()