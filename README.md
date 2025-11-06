# Sistema de Detecção de Phishing v2.0

## Métricas de Performance
- Acurácia: 99.67%
- Recall (Phishing): 99.59%
- Precision: 99.41%
- Threshold: 0.2

## Componentes
1. Modelo ML: CNN + Embedding
2. Sistema Híbrido: ML + Heurísticas
3. Whitelist: 20+ domínios confiáveis
4. Blacklist: Phishings confirmados

# Estrutura Interna
- Config → Armazena parâmetros globais, listas e caminhos.
- PhishingDetector → Classe principal que integra ML + heurísticas.
- verificar_heuristicas → Detecta padrões suspeitos em URLs.
- predict_ml → Predição usando CNN carregada de .h5.
- classificar → Combina ambas as análises e define status.
- classificar_batch → Análise em lote.
- relatorio_detalhado → Retorna relatório completo e legível.

## Como Usar
```python
from sistema_phishing import classificar_url

url = "https://example.com"
status, probabilidade, alertas = classificar_url(url)

if status == "PHISHING":
    bloquear_url(url)
elif status == "SUSPEITO":
    alertar_usuario(url)
else:  # SEGURO
    permitir_acesso(url)
```

## Manutenção
- Atualizar whitelist mensalmente
- Adicionar novos phishings à blacklist
- Re-treinar modelo a cada 3 meses
  
# Saídas Possíveis 
| Status          | Descrição                            |
| --------------- | ------------------------------------ |
| 🟢 **SEGURO**   | Nenhum indicador de risco            |
| 🟡 **SUSPEITO** | Alguns sinais suspeitos detectados   |
| 🔴 **PHISHING** | Confirmado por heurísticas ou modelo |

