# Roteiro de fala — Defesa final

Tempo sugerido: 14 a 17 minutos, sem contar perguntas. Use o texto como guia de raciocínio; não é necessário decorar palavra por palavra.

## Slide 1 — Título

Boa tarde. Nós somos Gustavo Lima, Willian Jean e Paulo Gomes. Este trabalho foi desenvolvido na Universidade Federal do Amazonas, sob orientação do professor Lucas Cordeiro.

Investigamos como usar o ESBMC para verificar vulnerabilidades em brokers MQTT, tendo o Eclipse Mosquitto como estudo de caso.

## Slide 2 — Roteiro

Vou apresentar o problema, posicionar a proposta em relação aos trabalhos relacionados, explicar a arquitetura e os modelos de rede e então mostrar a avaliação experimental. Depois detalho o achado de segurança, as ameaças à validade e a conclusão.

## Slide 3 — Problema, objetivo e entregas

O broker é um ponto central em sistemas MQTT e processa pacotes controlados pela rede. O Mosquitto é escrito em C, mas sua verificação pelo ESBMC encontra uma barreira: chamadas externas como `recv`, `select` e `poll` não representam automaticamente os comportamentos da rede.

O objetivo foi abstrair essas APIs sem simular o kernel ou TCP/IP. Como entregas, temos modelos para nove funções POSIX, 21 harnesses simbólicos, avaliação em CVEs e no snapshot `v2.1.2-132-ga609c263`, além da contribuição upstream 5388 e do Security Report 551.

A pergunta central é: como modelar a interação com a rede para verificar vulnerabilidades reais do Mosquitto com ESBMC?

## Slide 4 — Comparação com abordagens relacionadas

Fuzzing executa entradas concretas e funciona muito bem quando há um oráculo observável, como crash ou sanitizer. Frama-C com WP usa prova dedutiva e contratos ACSL. O CBMC também usa BMC e possui infraestrutura de harnesses e modelos.

Nossa proposta não substitui essas abordagens. O diferencial é combinar, no ESBMC, modelos POSIX, rede simbólica, comparação entre versões vulnerável e corrigida e invariantes específicos do domínio. A garantia continua limitada pelo `unwind`, com contraexemplo quando há violação.

## Slide 5 — Arquitetura do método proposto

A arquitetura possui cinco etapas. Primeiro selecionamos CVEs, parsers ou o snapshot atual. Depois construímos um harness com entradas simbólicas e um ambiente C reduzido.

Os modelos POSIX substituem as dependências da rede por comportamentos não determinísticos. O front-end Clang e o `c2goto` processam o programa; o ESBMC desenrola os laços, gera a forma SSA, codifica as operações em bit-vectors e envia a fórmula ao Z3.

Por fim coletamos resultado, contraexemplo, tempo e memória. A validação espera `FAILED` na variante vulnerável e `SUCCESSFUL` na corrigida. Cada etapa deixa um artefato auditável: código, comando, modelo ou log.

## Slide 6 — Modelos operacionais de rede

Um modelo operacional substitui uma função externa por uma abstração que conserva os comportamentos relevantes.

Para `socket` e `accept`, modelamos descritores possíveis. `bind`, `listen` e `close` têm efeitos simplificados. `send` retorna uma quantidade possível de bytes enviados.

O modelo central é `recv`: ele preenche o buffer com bytes não determinísticos e escolhe um comprimento permitido. Assim, os bytes representam qualquer entrada enviada por um atacante.

`select` e `poll` representam conjuntos possíveis de descritores e eventos prontos, permitindo alcançar o loop de eventos sem simular o kernel.

## Slide 7 — Avaliação: objetivos, benchmarks e setup

A avaliação responde a quatro perguntas: o método detecta vulnerabilidades conhecidas; os modelos preservam os defeitos quando o caminho passa pela rede; qual é o custo computacional; e propriedades de domínio revelam falhas no código atual?

O corpus contém sete CVEs, uma regressão CWE-193, propriedades MQTT, casos de integração via `recv` e as variantes do achado novo, totalizando 21 execuções.

Executamos ESBMC 8.3 com Z3 em Windows 11 e processador Intel Core i7. O `unwind` varia de 4 a 32. Medimos o resultado da propriedade, o tempo de parede e o pico de memória. Fontes, comandos e logs estão versionados.

## Slide 8 — Resultados de detecção

Nos casos isolados, `FAIL` na variante vulnerável significa que o ESBMC encontrou a violação. Onde temos a correção, o resultado muda para `SUCC`.

Nos pares de integração, o parser recebe bytes pelo modelo de `recv`, e não por um vetor fixo. O mesmo padrão mostra que a abstração de rede preserva os caminhos necessários para alcançar o defeito.

Todos os casos produziram o resultado esperado dentro do limite configurado, respondendo às duas primeiras questões de pesquisa.

## Slide 9 — Resultados de desempenho

Dezoito dos 21 casos terminam em menos de seis segundos e abaixo de 170 megabytes. O harness corrigido de QoS 2 leva cerca de 20,6 segundos, ainda com memória baixa.

O outlier é o bypass de ACL: 389,3 segundos e aproximadamente 2,2 gigabytes na variante vulnerável. O matching de strings e curingas, combinado com `unwind 32`, produz uma fórmula SMT muito maior.

Portanto, a abordagem é viável para a maioria dos subsistemas isolados, mas sensível à profundidade de busca.

## Slide 10 — Falha no snapshot v2.1.2-132-ga609c263

O achado está em `src/proxy_v2.c`, na função `read_tlv_ssl`, que interpreta sub-TLVs SSL do PROXY Protocol v2.

O contador `len` representa os bytes restantes dentro da TLV SSL. A função subtrai três bytes de cabeçalho mais `tlv_len`, mas valida o tamanho apenas contra o buffer global.

O contraexemplo declara 256 bytes para a TLV SSL. Após o cabeçalho, restam 251. A sub-TLV declara 253 bytes; somando o cabeçalho são 256, valor maior que 251. A conversão para `uint16_t` faz o contador virar 65.531.

O cenário requer `proxy_protocol true` e foi reportado ao Eclipse como Security Report 551.

## Slide 11 — Por que o harness encontrou a falha?

Pelas promoções da linguagem C, a subtração ocorre como `int`. O resultado negativo intermediário é válido e a conversão posterior para `uint16_t` é comportamento definido. Portanto, não há necessariamente overflow sinalizado, comportamento indefinido ou crash.

O harness fornece o oráculo que faltava: antes da subtração, `3 + tlv_len` deve ser menor ou igual a `len`. O ESBMC encontra uma entrada que viola essa regra.

O código original falha em 3,71 segundos. Com a guarda proposta, passa em 2,17 segundos. Isso mostra a complementaridade entre fuzzing e verificação formal orientada por propriedades de domínio.

## Slide 12 — Evidências e transferência dos resultados

À esquerda está o Security Report 551, com o snapshot analisado, a configuração afetada e o trecho responsável pelo underflow. O status confidencial faz parte do processo de divulgação coordenada autorizado para esta apresentação.

À direita está a contribuição upstream 5388 no ESBMC, incorporando modelos POSIX de `socket`, `select` e `poll`.

Esses registros mostram que o trabalho produziu resultados transferidos para as comunidades envolvidas, e não apenas experimentos locais.

## Slide 13 — Contribuições e ameaças à validade

As contribuições principais são a arquitetura de verificação, os nove modelos POSIX, os 21 harnesses reproduzíveis, a validação em CVEs, a contribuição upstream e o reporte ao Eclipse.

As conclusões precisam ser lidas dentro de quatro limites: os harnesses reduzem o contexto do broker; as garantias dependem de `unwind`, hipóteses e asserts; o estudo cobre um broker e um subconjunto de APIs e CVEs; e o desempenho foi medido em uma única máquina.

Mitigamos esses riscos comparando variantes vulneráveis e corrigidas, criando casos via `recv` e versionando comandos, fontes e logs.

## Slide 14 — Conclusão

Modelos POSIX e harnesses simbólicos tornam as entradas de rede acessíveis ao ESBMC sem simular a pilha TCP/IP.

A metodologia reproduziu CVEs, distinguiu variantes vulneráveis e corrigidas e apresentou baixo custo na maioria dos casos. Ao expressar uma regra de domínio que não corresponde diretamente a um crash, também revelou uma falha no snapshot analisado.

Assim, a verificação formal não substitui testes ou fuzzing. Ela complementa essas técnicas com exploração simbólica e oráculos lógicos explícitos.

## Slide 15 — Obrigado

Obrigado. Ficamos à disposição para perguntas.

Os harnesses, comandos, logs e modelos estão organizados nos diretórios indicados no slide.

## Respostas curtas para perguntas prováveis

### “Vocês verificaram o Mosquitto inteiro?”

Não. Verificamos subsistemas isolados e caminhos de integração delimitados, com dependências reduzidas e modelos de rede.

### “SUCCESSFUL prova ausência total de bugs?”

Não. Prova que a propriedade especificada não foi violada dentro das hipóteses do harness e do limite de desenrolamento utilizado.

### “Qual é a diferença para o CBMC?”

As duas ferramentas usam BMC. A contribuição está na arquitetura aplicada ao ESBMC, nos modelos POSIX, nos harnesses comparativos e na avaliação sobre o Mosquitto.

### “Por que não usar apenas fuzzing?”

Fuzzing é excelente quando existe um oráculo observável. Neste achado não há necessariamente crash; a asserção formal fornece o oráculo lógico que faltava.

### “Qual foi exatamente a versão analisada?”

O snapshot `v2.1.2-132-ga609c263`, revisão curta `a609c263`, de junho de 2026.

### “Qual é o impacto da falha?”

O cenário requer `proxy_protocol true`. O contador interno sofre wraparound e o parser pode processar além do comprimento declarado da TLV SSL. A classificação final depende da análise coordenada com o Eclipse.
