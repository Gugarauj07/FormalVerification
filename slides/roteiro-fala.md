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

Agora que a gente já explicou como os modelos de rede funcionam, eu vou mostrar como avaliamos a proposta na prática.

A avaliação foi guiada pelas quatro perguntas do lado esquerdo. Primeiro: o método encontra vulnerabilidades conhecidas? Segundo: quando a entrada passa pela rede modelada, o defeito continua aparecendo? Terceiro: quanto tempo e memória essa análise exige? E, por último: conseguimos encontrar algum problema no código atual?

Para responder a isso, fizemos vinte e uma execuções, incluindo CVEs, testes de integração e uma versão recente do Mosquitto. Como aparece no lado direito, usamos o ESBMC 8.3 com o Z3 e medimos o resultado, o tempo e o pico de memória de cada teste.

## Slide 8 — Resultados de detecção

Começando pelos resultados de detecção, as duas últimas colunas comparam o código vulnerável com o corrigido. `FAIL` na versão vulnerável significa que o ESBMC encontrou o defeito. Já `SUCC` na corrigida significa que a violação deixou de acontecer.

E foi esse o padrão observado nos CVEs do primeiro bloco. O mesmo ocorreu nos testes de integração do segundo bloco, em que os bytes chegam pelo modelo de `recv`, como se viessem da rede, e não por uma entrada fixa preparada no código.

Então, o resultado principal é que conseguimos reproduzir as vulnerabilidades conhecidas e que a abstração da rede não escondeu os defeitos. Com isso, respondemos positivamente às duas primeiras perguntas da avaliação.

## Slide 9 — Resultados de desempenho

Depois de confirmar que a detecção funciona, a próxima pergunta é: qual é o custo disso?

Os três primeiros casos da tabela encontram as falhas em aproximadamente um a três segundos. O `proxy_v2_tlv`, nosso achado novo, também falha em 3,7 segundos e passa em 2,2 segundos depois da correção.

O principal caso fora desse padrão está nas duas linhas do `acl_bypass`. A variante vulnerável levou cerca de 389 segundos e consumiu mais de 2,2 gigabytes de memória. Isso acontece porque esse caso trabalha com comparação de strings e curingas e, principalmente, porque usa `unwind 32`.

O `unwind` define quantas vezes os laços são desenrolados durante a análise. Quanto maior esse valor, mais caminhos o ESBMC representa e maior fica a fórmula enviada ao solver. Ele permite analisar execuções mais profundas, mas aumenta bastante o custo.

Mesmo com esse caso extremo, o quadro inferior mostra que dezoito dos vinte e um testes terminaram em menos de seis segundos e abaixo de cento e setenta megabytes. Portanto, a abordagem foi viável na maioria dos casos, embora seja sensível à profundidade de busca.

## Slide 10 — Falha no snapshot v2.1.2-132-ga609c263

E isso nos leva à quarta pergunta: conseguimos encontrar uma falha no código atual? A resposta foi sim, e esse é o principal achado novo do trabalho.

Como aparece no primeiro bloco, a falha está no arquivo `src/proxy_v2.c`, dentro da função `read_tlv_ssl`. TLV significa tipo, tamanho e valor: é uma estrutura usada pelo protocolo para organizar os campos recebidos. Essa função processa as sub-TLVs que ficam dentro de uma TLV SSL. A variável `len` representa quantos bytes ainda restam, enquanto `tlv_len` representa o tamanho informado pela sub-TLV atual.

A operação vulnerável está no centro do slide. O código atualiza `len` subtraindo três bytes de cabeçalho mais `tlv_len`, sem verificar antes se `3 + tlv_len` é menor ou igual ao `len` disponível.

Na tabela inferior está o contraexemplo. A TLV SSL declara 256 bytes e, depois do cabeçalho SSL, `len` fica em 251. A sub-TLV informa `tlv_len` igual a 253. Somando os três bytes do cabeçalho, ela precisa de 256 bytes, mas só existem 251.

A subtração resulta em menos cinco. Como o valor é convertido para um unsigned int de 16 bits, `len` passa a valer 65.531. Em vez de indicar que o limite foi ultrapassado, o contador diz que ainda existe uma quantidade enorme de dados para processar.

Essa falha depende de o Proxy Protocol estar habilitado. Nós reportamos o caso de forma responsável ao projeto Eclipse, no relatório de segurança número quinhentos e cinquenta e um.

## Slide 11 — Por que o harness encontrou a falha?

Mas por que esse problema foi encontrado pelo nosso teste e não apareceu automaticamente em outras ferramentas?

O primeiro quadro mostra o motivo. A opção `unsigned-overflow-check` não sinaliza a operação porque, pelas regras de C, a subtração é calculada como um `int`. O `overflow-check` também não acusa erro porque o resultado negativo intermediário ainda é válido. E UBSan e libFuzzer não identificam necessariamente o problema, pois a conversão é definida pela linguagem e não produz um crash imediato.

O programa continua executando, mas com um contador incorreto. O que fez a diferença foi a propriedade do segundo quadro: antes da subtração, `3 + tlv_len` precisa ser menor ou igual a `len`. Essa asserção informa ao ESBMC o que é um estado inválido nesse contexto.

Com essa regra, o código original falhou em 3,71 segundos. A correção proposta é a que aparece logo abaixo: rejeitar a TLV antes da subtração quando o tamanho informado for maior do que o espaço restante. Depois dessa guarda, o mesmo harness terminou com sucesso em 2,17 segundos.

## Slide 12 — Evidências e transferência dos resultados

Por fim, este slide mostra que os resultados não ficaram apenas dentro do nosso ambiente de pesquisa.

Na imagem à esquerda está o Security Report 551, enviado ao Eclipse. Ele registra o snapshot analisado anteriormente.

Na imagem à direita está o pull request que fizemos ao ESBMC. Por meio dessa contribuição, os modelos POSIX de `socket`, `select` e `poll` desenvolvidos no trabalho foram incorporados ao verificador.

Então, além dos resultados experimentais, o trabalho gerou duas contribuições concretas: uma para a segurança do Mosquitto e outra para ampliar a capacidade de análise do ESBMC.

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
