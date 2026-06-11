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

*(Apontar o bloco de cima do slide)*

Aqui está o achado novo. Arquivo `proxy_v2.c`, função `read_tlv_ssl`. É o pedaço do Mosquitto que lê um cabeçalho especial chamado PROXY Protocol v2.

Quando isso importa? Só quando o broker está atrás de um load balancer e a opção `proxy_protocol true` está ligada no `mosquitto.conf`. Não é o cenário padrão — a maioria das instalações não usa. 

O que o código faz, em termos simples: dentro desse cabeçalho tem um bloco SSL, e dentro dele podem vir blocos menores. O programa guarda num contador — a variável `len` no slide — quantos bytes **ainda faltam ler dentro desse bloco SSL**.

O bug está nessa linha que o slide destaca: o programa **subtrai** do contador o tamanho do bloco menor **sem checar antes** se aquele bloco realmente cabe no que ainda restava. Falta uma validação simples: “isso cabe no que sobrou?”

*(Apontar a tabela “Contraexemplo ESBMC”)*

O ESBMC montou um exemplo concreto em menos de 1 segundo.

Primeira linha: o bloco SSL tem tamanho total 256. Depois de ler o cabeçalho fixo de 5 bytes, sobram **251 bytes** no contador — é o `len` igual a 251 que aparece aí.

Segunda linha: chega um bloco interno que declara **253 bytes** de conteúdo — o `tlv_len` igual a 253. O Mosquitto pergunta: “253 cabe no pacote inteiro?” Cabe — o buffer geral tem até 500 bytes, então **passa** no check que está na tabela.

O problema é outro: 253 é **maior** que os 251 que ainda restavam **dentro** do bloco SSL. Mas o código não faz essa segunda pergunta. Ele subtrai mesmo assim — na prática, tira 256 de 251, o resultado fica **negativo**. Só que o contador não guarda negativo: ele converte esse valor e acaba virando **65.531**. O programa então acha que ainda faltam esses de bytes para ler, quando na verdade não deveria.

*(Apontar FAILED / SUCCESSFUL)*

Rodamos o harness com o comportamento atual: **VERIFICATION FAILED** — o ESBMC provou que esse cenário é possível.

Quando colocamos no harness a correção que falta — basicamente, rejeitar o pacote se o bloco interno for maior que o que sobrou — passa para **SUCCESSFUL**.

*(Apontar a nota de rodapé)*

Impacto: severidade baixa. A conexão acaba sendo rejeitada; Vamos reportar ao Eclipse em divulgação coordenada.

---
## Slide — Vulnerabilidade (2/2)

Agora a pergunta natural: se o bug existe, por que fuzzing e as checagens automáticas do ESBMC não pegaram sozinhas?

Resposta curta: **porque o programa não quebra**. Não tem crash, não tem corrupção de memória óbvia. O que acontece eh que o broker lê errado, o contador fica inconsistente, mas no fim a conexão é recusada e a execução termina “normalmente”.

Por isso as flags automáticas do ESBMC não ajudam aqui:

- `--unsigned-overflow-check` — não dispara, porque a subtração problemática não acontece direto em tipo unsigned.
- `--overflow-check` — também não, porque o resultado intermediário ainda é um número inteiro válido

*(Apontar a nota do commit na parte de baixo)*

Inclusive o próprio Mosquitto ganhou um fuzzer para esse arquivo em janeiro de 2026 — commit `23c918ee` — e mesmo assim **não** achou esse caso.

*(Apontar o bloco “Por que o ESBMC com harness detectou”)*

O que a gente fez de diferente foi escrever no harness a **regra que o código deveria obedecer**, usando `__ESBMC_assert`.

a regra é: “antes de subtrair o tamanho do bloco interno do contador, esse bloco tem que caber no que ainda restava.”

Aí a ferramenta pergunta: existe alguma combinação de tamanhos que viola essa regra? Existe — e é exatamente o contraexemplo da tabela do slide anterior.