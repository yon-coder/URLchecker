import urllib.request
from urllib.parse import urlparse

#lista de feeds públicos contendo URLs maliciosas em formato texto plano
FEEDS_AMEACAS = [
    "https://urlhaus.abuse.ch/downloads/text/",   #feed principal URLhaus
    "https://openphish.com/feed.txt",              #feed de phishing da OpenPhish
    "https://threatfox.abuse.ch/export/urls/recent/" #feed de IoCs de URLs da ThreatFox
]

def eh_url_valida(url: str) -> bool:
    """Verifica se a string informada possui estrutura válida de URL (http ou https)."""
    try:
        resultado = urlparse(url)
        # Exige protocolo (http/https) e um domínio ou endereço IP
        return all([resultado.scheme in ('http', 'https'), resultado.netloc])
    except Exception:
        return False

def carregar_base_de_dados():
    print("⏳ Atualizando banco de dados de ameaças de múltiplas fontes... aguarde.")
    urls_maliciosas = set()

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

    for feed_url in FEEDS_AMEACAS:
        try:
            req = urllib.request.Request(feed_url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resposta:
                linhas = resposta.read().decode('utf-8', errors='ignore').splitlines()

                contador_feed = 0
                for linha in linhas:
                    linha_limpa = linha.strip()
                    # Ignora comentários (#) e linhas vazias
                    if linha_limpa and not linha_limpa.startswith('#'):
                        urls_maliciosas.add(linha_limpa)
                        contador_feed += 1

                print(f"  └─ Carregadas {contador_feed:,} URLs de: {feed_url}")

        except Exception as erro:
            print(f"  └─ ⚠️ Falha ao baixar feed ({feed_url}): {erro}")

    print(f"\n✅ Base consolidada! {len(urls_maliciosas):,} URLs maliciosas únicas na memória.\n")
    return urls_maliciosas

def verificar_url():
    base_urls = carregar_base_de_dados()

    if not base_urls:
        print("Encerrando o programa por falha no download de todas as bases.")
        return

    print("-" * 55)
    print("🛡️  VERIFICADOR DE URLS SUSPEITAS")
    print("Digite 'sair' a qualquer momento para fechar.")
    print("-" * 55)

    while True:
        link_usuario = input("\n🔗 Cole o link aqui: ").strip()

        if link_usuario.lower() == 'sair':
            print("Encerrando... Navegue com segurança!")
            break

        if not link_usuario:
            continue

        #validação do formato da URL
        if not eh_url_valida(link_usuario):
            print("❌ ERRO: URL inválida!")
            print("   Certifique-se de incluir o protocolo (exemplo: https://exemplo.com/pagina)")
            continue

        #normalização simples (remove barra final para padronizar buscas)
        link_normalizado = link_usuario.rstrip('/')

        #verifica se a URL ou sua versão normalizada está na base de bloqueio
        if link_usuario in base_urls or link_normalizado in base_urls:
            print("🚨 STATUS: PERIGOSO!")
            print("   Motivo: Este link está listado em bases públicas de distribuição de malware ou phishing.")
        else:
            print("⚠️ STATUS: NÃO DEFINIDO / APARENTEMENTE SEGURO")
            print("   Nota: O link não consta nas bases consultadas. Mantenha a cautela com links desconhecidos.")

if __name__ == "__main__":
    verificar_url()
