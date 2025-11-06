import pandas as pd
import pickle
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import load_model
from tensorflow.keras.callbacks import ModelCheckpoint, EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.optimizers import Adam
from collections import Counter


def carregar_dataset_local(caminho_csv):
    if not os.path.exists(caminho_csv):
        raise FileNotFoundError(f"CSV não encontrado: {caminho_csv}")
    
    df = pd.read_csv(caminho_csv)
    
    # Verificar se tem as colunas necessárias
    if 'text' in df.columns:
        df = df.rename(columns={"text": "url"})
    
    # Usar 'label' como nome da coluna de classe
    df = df.dropna(subset=["url", "label"])
    df = df.drop_duplicates(subset=["url"])
    
    return df

# ===============================
# CONFIGURAÇÕES
# ===============================
CAMINHO_CSV = "Dataset_new.csv"
CAMINHO_MODELO = "modelo_phishing.h5"  # ⬅️ Defina o caminho do seu modelo
CAMINHO_MODELO_NOVO = "modelo_phishing_atualizado.h5"
CAMINHO_TOKENIZER = "tokenizer.pkl"
CAMINHO_LABEL_ENCODER = "label_encoder.pkl"
MAX_LEN = 200

# ===============================
# Carregar dataset
# ===============================
df = carregar_dataset_local(CAMINHO_CSV)

# Features e labels (ajustado para usar 'label' ao invés de 'type')
X = df['url']
y = df['label']  # ⬅️ Corrigido

# ===============================
# Carregar LabelEncoder salvo
# ===============================
with open(CAMINHO_LABEL_ENCODER, "rb") as f:
    le = pickle.load(f)

# Verificar se há classes novas no dataset
classes_novas = set(y.unique()) - set(le.classes_)
if classes_novas:
    print(f"⚠️ ATENÇÃO: Encontradas classes novas não vistas no treino original: {classes_novas}")
    print("Removendo essas amostras...")
    df = df[df['label'].isin(le.classes_)]
    X = df['url']
    y = df['label']

# Transformar labels para números
y = le.transform(y)

# ===============================
# Separar treino e teste
# ===============================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ===============================
# Carregar Tokenizer salvo
# ===============================
with open(CAMINHO_TOKENIZER, "rb") as f:
    tokenizer = pickle.load(f)

# Transformar URLs em sequências numéricas
seq_train = tokenizer.texts_to_sequences(X_train)
seq_test = tokenizer.texts_to_sequences(X_test)

# Padding
X_train_pad = pad_sequences(seq_train, maxlen=MAX_LEN, padding='post')
X_test_pad = pad_sequences(seq_test, maxlen=MAX_LEN, padding='post')

# ===============================
# Carregar modelo
# ===============================
print(f"Carregando modelo de: {CAMINHO_MODELO}")
modelo = load_model(CAMINHO_MODELO)

# Mostrar arquitetura
print("\n Arquitetura do Modelo:")
modelo.summary()

print("\n📊 Distribuição das classes:")
print("Treino:", Counter(y_train))
print("Teste:", Counter(y_test))

# Calcular pesos
class_weights = compute_class_weight(
    'balanced',
    classes=np.unique(y_train),
    y=y_train
)
class_weight_dict = dict(enumerate(class_weights))
print(f"\n⚖️ Pesos calculados: {class_weight_dict}")

# ===============================
# RE-COMPILAR COM LR MENOR
# ===============================

modelo.compile(
    optimizer=Adam(learning_rate=1e-5),
    loss='binary_crossentropy',  # ⬅️ CORRETO para 1 neurônio de saída
    metrics=['accuracy']
)

print("\n🔧 Modelo re-compilado com learning rate reduzido")

# ===============================
# CONFIGURAR CALLBACKS
# ===============================
callbacks = [
    ModelCheckpoint(
        CAMINHO_MODELO_NOVO,
        monitor='val_accuracy',
        save_best_only=True,
        mode='max',
        verbose=1
    ),
    EarlyStopping(
        monitor='val_loss',
        patience=5,  # ⬅️ Aumentei a paciência
        restore_best_weights=True,
        verbose=1
    ),
    ReduceLROnPlateau(
        monitor='val_loss',
        factor=0.5,
        patience=3,
        min_lr=1e-7,
        verbose=1
    )
]

# ===============================
# TREINAR COM PESOS
# ===============================
print("\n🚀 Iniciando treinamento com class weights...")
history = modelo.fit(
    X_train_pad, y_train,
    validation_data=(X_test_pad, y_test),
    epochs=30,
    batch_size=512,
    class_weight=class_weight_dict,  # ⬅️ CRUCIAL!
    callbacks=callbacks,
    verbose=1
)

# ===============================
# Avaliar modelo
# ===============================
print("\n📈 Avaliando modelo...")
loss, acc = modelo.evaluate(X_test_pad, y_test, verbose=0)
print(f"Test Loss: {loss:.4f}")
print(f"Test Accuracy: {acc:.4f}")

# Gerar previsões (CORRETO PARA BINÁRIO)
y_pred_probs = modelo.predict(X_test_pad, verbose=0)  # Shape: (n, 1)
y_pred = (y_pred_probs > 0.5).astype(int).flatten()   # ⬅️ Threshold binário

# y_test já está no formato correto (não precisa de argmax)
y_true = y_test

# Defina os nomes reais das suas classes
NOMES_CLASSES = {
    0: "Legítimo",
    1: "Phishing",    
}

# Converter para lista ordenada
target_names = [NOMES_CLASSES[i] for i in sorted(NOMES_CLASSES.keys())]

# Relatório detalhado
print("\n📋 Relatório de Classificação:")
report = classification_report(y_true, y_pred, target_names=target_names, zero_division=0)
print(report)

# ===============================
# Matriz de confusão
# ===============================
cm = confusion_matrix(y_true, y_pred)

plt.figure(figsize=(10, 8))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=le.classes_, yticklabels=le.classes_,
            cbar_kws={'label': 'Contagem'})
plt.xlabel("Predito", fontsize=12)
plt.ylabel("Verdadeiro", fontsize=12)
plt.title("Matriz de Confusão - Modelo Atualizado", fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig("matriz_confusao_atualizada.png", dpi=300, bbox_inches='tight')
plt.show()

# ===============================
# Plotar histórico de treino
# ===============================
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

# Acurácia
ax1.plot(history.history['accuracy'], label='Treino', marker='o')
ax1.plot(history.history['val_accuracy'], label='Validação', marker='s')
ax1.set_title('Acurácia por Época')
ax1.set_xlabel('Época')
ax1.set_ylabel('Acurácia')
ax1.legend()
ax1.grid(True, alpha=0.3)

# Loss
ax2.plot(history.history['loss'], label='Treino', marker='o')
ax2.plot(history.history['val_loss'], label='Validação', marker='s')
ax2.set_title('Loss por Época')
ax2.set_xlabel('Época')
ax2.set_ylabel('Loss')
ax2.legend()
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig("historico_treinamento.png", dpi=300, bbox_inches='tight')
plt.show()

print(f"\n✅ Modelo atualizado salvo em: {CAMINHO_MODELO_NOVO}")