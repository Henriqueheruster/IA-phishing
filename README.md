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

## Estrutura Interna
- Config → Armazena parâmetros globais, listas e caminhos.
- PhishingDetector → Classe principal que integra ML + heurísticas.
- verificar_heuristicas → Detecta padrões suspeitos em URLs.
- predict_ml → Predição usando CNN carregada de .h5.
- classificar → Combina ambas as análises e define status.
- classificar_batch → Análise em lote.
- relatorio_detalhado → Retorna relatório completo e legível.

## Como Usar
```python
from detector_phishing import PhishingDetector

detector = PhishingDetector()
status, prob, alertas = detector.classificar("https://suspicious-site123.tk")

print(status)   # "PHISHING"
print(prob)     # 0.91
print(alertas)  # ["TLD de alto risco", "Palavra suspeita: ..."]
```
Ou gerar relatório completo:

```python
from detector_phishing import gerar_relatorio
print(gerar_relatorio("https://www.pisocks.com"))
```
## Requisitos e Dependências
```python
---

## ⚙️ Como Usar

### 🔧 Requisitos

- Python 3.10 ou superior  
- TensorFlow 2.x  
- NumPy  
- Pickle  
- (opcional) Jupyter ou VSCode para testes

Instale as dependências:

```bash
pip install tensorflow numpy
```

## Manutenção
- Atualizar whitelist mensalmente
- Adicionar novos phishings à blacklist
- Re-treinar modelo a cada 3 meses
  
## Saídas Possíveis 
| Status          | Descrição                            |
| --------------- | ------------------------------------ |
| 🟢 **SEGURO**   | Nenhum indicador de risco            |
| 🟡 **SUSPEITO** | Alguns sinais suspeitos detectados   |
| 🔴 **PHISHING** | Confirmado por heurísticas ou modelo |

