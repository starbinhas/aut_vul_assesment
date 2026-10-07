Falha: {{ title }}
Regra de origem: {{ tool }} {{ rule_id }}{% if rule_name %} ({{ rule_name }}){% endif %}
CWE: {{ cwe or "não informado" }}
OWASP Top 10:{{ owasp_version }}: {{ owasp or "não mapeado" }}{% if owasp_name %} — {{ owasp_name }}{% endif %}
Stack detectada: {{ stack }}
Idioma do relatório: {{ language }}
{% if description %}
Descrição técnica da ferramenta:
{{ description }}
{% endif %}
