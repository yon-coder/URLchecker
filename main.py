import re
import urllib.request
from urllib.parse import urlparse

FEEDS_AMEACAS = [
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://openphish.com/feed.txt",
    "https://threatfox.abuse.ch/export/urls/recent/"
]

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

def eh_url_valida(url: str) -> bool:
    try:
        resultado = urlparse(url)
        return all([resultado.scheme in ('http', 'https'), resultado.netloc])
    except Exception:
        return False

def carregar_base_de_dados():
    print("⏳ [Fase 1] Carregando bases de dados estáticas (Blacklists)...")
    urls_maliciosas = set()

    for feed_url in FEEDS_AMEACAS:
        try:
            req = urllib.request.Request(feed_url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=10) as resposta:
                linhas = resposta.read().decode('utf-8', errors='ignore').splitlines()
                
                for linha in linhas:
                    linha_limpa = linha.strip()
                    if linha_limpa and not linha_limpa.startswith('#'):
                        urls_maliciosas.add(linha_limpa)
                print(f"  └─ Sucesso ao ler: {feed_url}")
        except Exception as erro:
            print(f"  └─ ⚠️ Falha ao baixar ({feed_url}): {erro}")

    print(f"✅ Bases carregadas! {len(urls_maliciosas):,} URLs conhecidas na memória.\n")
    return urls_maliciosas

def analisar_heuristica_url(url: str) -> dict:
    pontos_suspeitos = 0
    motivos = []
    parsed = urlparse(url)
    domain = parsed.netloc

    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        pontos_suspeitos += 30
        motivos.append("Uso de IP direto em vez de nome de domínio.")

    if len(url) > 75:
        pontos_suspeitos += 15
        motivos.append("Comprimento da URL muito longo (> 75 caracteres).")

    palavras_chave = ['login', 'verify', 'account', 'banking', 'secure', 'update', 'senha']
    if any(palavra in url.lower() for palavra in palavras_chave):
        pontos_suspeitos += 20
        motivos.append("Contém palavras-chave comumente associadas a fraudes.")

    if parsed.scheme == 'http':
        pontos_suspeitos += 10
        motivos.append("Conexão não criptografada (HTTP).")

    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=5) as resposta:
            url_final = resposta.geturl()
            if urlparse(url_final).netloc != domain:
                pontos_suspeitos += 25
                motivos.append(f"Redirecionamento suspeito para: {url_final}")
    except Exception as e:
        pontos_suspeitos += 10
        motivos.append(f"Erro ao acessar ou domínio bloqueado: {e}")

    if pontos_suspeitos >= 40:
        nivel = "ALTO RISCO 🚨"
    elif pontos_suspeitos >= 20:
        nivel = "MÉDIO RISCO ⚠️"
    else:
        nivel = "BAIXO RISCO ✅"

    return {"score": pontos_suspeitos, "nivel": nivel, "motivos": motivos}

def verificar_url():
    base_urls = carregar_base_de_dados()

    print("-" * 60)
    print("🛡️  SISTEMA HÍBRIDO DE VERIFICAÇÃO DE URLs")
    print(" (1) Checagem em Blacklists  |  (2) Análise Heurística")
    print(" Digite 'sair' para encerrar.")
    print("-" * 60)

    while True:
        link_usuario = input("\n🔗 Cole a URL para verificar: ").strip()

        if link_usuario.lower() == 'sair':
            print("Encerrando... Navegue com segurança!")
            break

        if not link_usuario:
            continue

        if not eh_url_valida(link_usuario):
            print("❌ ERRO: URL inválida. Inclua http:// ou https://")
            continue

        link_normalizado = link_usuario.rstrip('/')

        if link_usuario in base_urls or link_normalizado in base_urls:
            print("\n🚨 RESULTADO: PERIGO EXTREMO!")
            print("  Motivo: A URL está presente em bases globais de distribuição de malware/phishing.")
            print("  Ação Recomendada: NÃO ACESSE ESTE LINK.")
            continue 

        print("🔎 URL não encontrada nas blacklists. Iniciando análise dinâmica...")
        resultado = analisar_heuristica_url(link_usuario)

        print(f"\n📊 RESULTADO HEURÍSTICO: {resultado['nivel']} (Score: {resultado['score']}/100)")
        
        if resultado['motivos']:
            print("  Fatores identificados:")
            for motivo in resultado['motivos']:
                print(f"  • {motivo}")
        
        if resultado['score'] == 0:
            print("  Nenhum fator de risco óbvio foi encontrado pela heurística.")

if __name__ == "__main__":
    verificar_url()
