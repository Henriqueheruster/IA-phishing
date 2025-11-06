import os
import pickle
import numpy as np
import pandas as pd
from datasets import load_dataset
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout
from tensorflow.keras.callbacks import ModelCheckpoint, EarlyStopping

def carregar_dataset_local(caminho_csv):
    if not os.path.exists(caminho_csv):
        raise FileNotFoundError(f"CSV não encontrado: {caminho_csv}")
    
    # Carregar CSV
    df = pd.read_csv(caminho_csv)
    
    # Renomear coluna 'text' → 'url' para manter consistência
    df = df.rename(columns={"text": "url"})    
    
    # Remover linhas inválidas
    df = df.dropna(subset=["url", "label"])
    df = df.drop_duplicates(subset=["url"])
    
    return df

# Carregar dataset
df = carregar_dataset_local("BasesDados\Dataset_new.csv")
print(f"✅ Total de URLs: {len(df)}")
print(df["label"].value_counts())

# ===============================
# 2️⃣ Preparar dados
# ===============================

X = df["url"].astype(str)
y = df["label"].astype(int)

# Codificação dos rótulos (aqui é binário, mas manteremos LabelEncoder)
le = LabelEncoder()
y = le.fit_transform(y)

# Divisão em treino/teste
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Tokenização
tokenizer = Tokenizer(num_words=10000, oov_token="<OOV>")
tokenizer.fit_on_texts(X_train)

# Padding
max_len = 200
X_train_pad = pad_sequences(tokenizer.texts_to_sequences(X_train), maxlen=max_len, padding="post")
X_test_pad = pad_sequences(tokenizer.texts_to_sequences(X_test), maxlen=max_len, padding="post")

# ===============================
# 3️⃣ Definir modelo CNN binário
# ===============================

model = Sequential([
    Embedding(input_dim=10000, output_dim=64, input_length=max_len),
    Conv1D(128, 5, activation="relu"),
    GlobalMaxPooling1D(),
    Dense(128, activation="relu"),
    Dropout(0.5),
    Dense(1, activation="sigmoid")  # Binário → 1 saída
])

model.compile(
    optimizer="adam",
    loss="binary_crossentropy",
    metrics=["accuracy"]
)

model.summary()

# ===============================
# 4️⃣ Callbacks (checkpoint + early stopping)
# ===============================

os.makedirs("checkpoints", exist_ok=True)

checkpoint_cb = ModelCheckpoint(
    filepath="checkpoints/modelo_phishing_epoca_{epoch:02d}_acc_{val_accuracy:.3f}.h5",
    save_best_only=False,
    monitor="val_accuracy",
    mode="max",
    verbose=1
)

early_stop_cb = EarlyStopping(
    monitor="val_loss",
    patience=3,
    restore_best_weights=True
)

# ===============================
# 5️⃣ Treinar modelo
# ===============================

history = model.fit(
    X_train_pad, y_train,
    validation_data=(X_test_pad, y_test),
    epochs=10,
    batch_size=512,
    callbacks=[checkpoint_cb, early_stop_cb],
    verbose=1
)

# ===============================
# 6️⃣ Salvar tokenizer e label encoder
# ===============================

with open("tokenizer.pkl", "wb") as f:
    pickle.dump(tokenizer, f)

with open("label_encoder.pkl", "wb") as f:
    pickle.dump(le, f)