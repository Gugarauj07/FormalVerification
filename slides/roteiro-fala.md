# Roteiro de fala — Resultados e Nova Vulnerabilidade

## Slide — CVEs Cobertos

Primeiro vou explicar como a gente validou a metodologia.

Na tabela vocês veem CVE e CWE. CVE é o identificador público de uma falha — tipo “CVE-2017-7651”. CWE é a categoria do defeito: overflow, vazamento de memória, bypass de ACL, e assim por diante.

Por que gastar tempo com bugs que já foram documentados? Porque a gente não está tentando redescobrir esses bugs. Já sabemos que existiram e em qual versão foram corrigidos.

Usamos esses CVEs como oráculo: se o ESBMC, com nossos harnesses, detecta o defeito na versão vulnerável e para de reclamar na versão corrigida, ganhamos confiança de que a ferramenta e a modelagem estão funcionando.

São sete CVEs do Mosquitto na tabela, de 2017 a 2024 — todos defeitos clássicos de C em software de rede.

No total são 21 execuções do ESBMC
---

## Slide — Resultados: Detecção

Esta tabela responde à pergunta central: o ESBMC encontrou o bug na versão vulnerável e deixou de encontrar na versão corrigida?

FAILED na coluna Vuln. é o resultado esperado — a ferramenta achou o defeito. SUCCESSFUL em Fix é o que queremos — com o patch do Mosquitto, a propriedade passa a valer. Se invertesse, algo estaria errado na metodologia.

O primeiro bloco são CVEs em harnesses isolados: extraímos a função vulnerável, simplificamos structs e verificamos num mini-programa. Na maioria usamos flags automáticas do ESBMC — overflow sem sinal, memory leak ou unwind para limitar loops.

O segundo bloco testa os mesmos bugs, mas pelo caminho que o broker usa de verdade. No bloco anterior os bytes vinham de um array fixo dentro do programa. Aqui o parser chama recv — a função que lê dados do socket quando um cliente se conecta. O ESBMC não entende rede real, então a gente criou substitutos: quando o código chama recv, nosso stub devolve bytes simbólicos, como se um atacante controlasse o que chega na conexão. Repetimos isso para dois CVEs — remaining length e primeiro pacote. Se o ESBMC acha o bug por esse caminho também, sabemos que os stubs funcionam, não só o mini-programa isolado.

O terceiro bloco é a falha nova que encontramos em proxy_v2, no código atual: FAILED com o bug; SUCCESSFUL depois da guarda que propomos.

---

## Slide — Resultados: Desempenho

Detectar o bug é uma coisa; outra é saber se a abordagem é viável em tempo e memória. Rodamos todos os harnesses com ESBMC 8.3 e solver Z3 — script automatizado, resultados em bench_results.csv.

A boa notícia: 19 de 21 harnesses terminam em menos de 4 segundos e menos de 170 MB. 

O outlier é o ACL bypass: cerca de 88 segundos e 2,2 GB. O cenário é um atacante com username desconhecido tentando ler o tópico victim/data. O broker compara isso com o padrão %u/data caractere a caractere, em loop — e o ESBMC precisa considerar todas as possibilidades de username e todos os caminhos do matching com wildcard. Por isso usamos unwind 32 e o custo explode. Na versão corrigida cai para cerca de 23 segundos: o patch valida o username antes e elimina caminhos inválidos cedo, então o solver trabalha menos — ainda pesado, mas mostra que o fix simplifica a análise.

Conclusão: para subsistemas isolados do Mosquitto, o custo é aceitável para pesquisa e reprodução. O ACL é o caso que exige calibrar parâmetros ou aceitar custo maior.

---

## Transição (antes da vulnerabilidade)

Validamos a metodologia nos CVEs conhecidos. O passo seguinte foi aplicar a mesma lógica ao código atual do Mosquitto 2.1.x — e encontramos algo que ainda não está no NVD.

---

## Slide — Vulnerabilidade (1/2)

A falha está em proxy_v2.c, função read_tlv_ssl — parser de sub-TLVs SSL do PROXY Protocol v2.

Contexto: quando o Mosquitto fica atrás de um load balancer com uma configuracao especifica, chega um cabeçalho extra antes do MQTT, com blocos aninhados no formato TLV — tipo, tamanho, valor. Não é configuração padrão.

O código precisa saber quanto ainda falta ler dentro do bloco SSL. No contraexemplo do slide, sobram 251 bytes. Chega um sub-bloco que declara 253 bytes de conteúdo.

Antes de consumir, o Mosquitto pergunta só uma coisa: isso cabe no pacote inteiro? Cabe — o buffer tem 500 bytes. Mas não pergunta: cabe nos 251 que ainda restam? Subtrai mesmo assim. O contador estoura e vira 65531.

O ESBMC encontrou um contraexemplo em menos de 1 segundo — os valores estão no slide. Harness vulnerável: FAILED. Com a guarda if (3 + tlv_len > len) return erro: SUCCESSFUL.

Sobre impacto: severidade baixa — config específica, conexão acaba rejeitada, sem RCE demonstrado. Mesmo assim é falha real, CWE-191. Vamos reportar ao Eclipse em divulgação coordenada.

---

## Slide — Vulnerabilidade (2/2)

Por que isso não apareceu com fuzzing nem com as flags automáticas do ESBMC?

Porque não dá crash. A subtração acontece em aritmética int com sinal; o resultado negativo é válido até o cast para uint16_t. Por isso --unsigned-overflow-check não dispara, --overflow-check também não, e UBSan não acusa — o cast de inteiro negativo para uint16_t é comportamento definido em C.

O fuzzer que o próprio Mosquitto adicionou para esse arquivo em janeiro de 2026 — commit 23c918ee — também não encontrou. Sem crash, sem sanitizer violado, o fuzzer segue em frente.

O que funcionou foi escrever a regra correta do protocolo como asserção: 3 + tlv_len tem que ser menor ou igual a len antes da subtração. O ESBMC não inventa essa regra — nós especificamos com base na leitura do código. Ele só pergunta: existe alguma entrada que viola? Existe, e devolve o contraexemplo.

Esse é o ponto metodológico: fuzzing acha crashes; verificação formal com invariante acha falhas lógicas que não crasham. Os resultados anteriores mostram que a abordagem funciona nos CVEs antigos; aqui mostra que também serve para achar problema novo no código atual.
