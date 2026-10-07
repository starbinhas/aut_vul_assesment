"""Scan de composição de software (SCA): confere a lista de dependências do site contra falhas
conhecidas (OSV). É um scan à parte, com um tipo de entrada diferente dos demais — a "lista de
ingredientes" (manifesto) que o cliente fornece —, porque dependências vulneráveis (A03) não são
visíveis num scan de caixa-preta. Sobrepõe a etapa 3 do time: alinhar fronteira antes de produção.
"""
