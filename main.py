import os
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report
import seaborn as sns
import matplotlib.pyplot as plt
from imblearn.over_sampling import SMOTE

# Параметры
DATASET_PATH = 'datasets/data/different_features/'
MODEL_PATH = 'models/different_features_model.pth'
EPOCHS = 50
BATCH_SIZE = 32
LEARNING_RATE = 0.001
CATEGORIES = ['games', 'music', 'social_network', 'video_hosting', 'cloud_service', 'e-mail', 'other']
NOISE_STD = 0.1  # Стандартное отклонение для шума

# Устройство
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"Using device: {device}")

# Функция для добавления шума
def add_noise(X, std=NOISE_STD):
    """Добавляет гауссовский шум к признакам."""
    noise = np.random.normal(0, std, X.shape)
    return X + noise

# Загрузка и обработка данных
try:
    data = pd.read_csv(DATASET_PATH + 'traffic_features.csv', delimiter=',')
    print(f"Загружен файл traffic_features.csv: {data.shape[0]} строк, {data.shape[1]} столбцов")

    # Очистка данных
    data.columns = data.columns.str.strip()
    data = data.fillna(0).replace([np.inf, -np.inf], 0)

    # Проверка столбца Label
    if 'Label' not in data.columns:
        raise KeyError(f"Столбец 'Label' не найден. Доступные столбцы: {data.columns.tolist()}")

    # Проверка распределения классов
    print(f"Уникальные значения в столбце Label: {data['Label'].unique()}")
    print("\nРаспределение классов до аугментации:")
    print(data['Label'].value_counts(normalize=True))

    # Кодирование меток
    le = LabelEncoder()
    data['Label'] = le.fit_transform(data['Label'])
    print(f"Закодированные метки: {dict(zip(le.classes_, range(len(le.classes_))))}")

    # Разделение признаков и меток
    X = data.drop('Label', axis=1).values
    y = data['Label'].values

    # Нормализация признаков
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Аугментация: SMOTE
    smote = SMOTE(random_state=13052003)
    X_smote, y_smote = smote.fit_resample(X, y)
    print(f"\nПосле SMOTE: {X_smote.shape[0]} строк, распределение классов:")
    print(pd.Series(y_smote).value_counts(normalize=True))

    # Аугментация: Добавление шума
    X_noisy = add_noise(X_smote, std=NOISE_STD)
    y_noisy = y_smote.copy()
    print(f"После добавления шума: {X_noisy.shape[0]} строк")

    # Объединение данных
    X_augmented = np.vstack([X_smote, X_noisy])
    y_augmented = np.hstack([y_smote, y_noisy])
    print(f"Итоговый аугментированный набор: {X_augmented.shape[0]} строк")

    # Разделение на train и validation
    X_train, X_val, y_train, y_val = train_test_split(
        X_augmented, y_augmented, test_size=0.2, random_state=13052003, stratify=y_augmented
    )
    print(f"Train: {X_train.shape[0]} строк, Validation: {X_val.shape[0]} строк")

    # Вычисление весов для классов
    class_counts = pd.Series(y_train).value_counts().sort_index()
    class_weights = 1.0 / class_counts
    class_weights = class_weights / class_weights.sum() * len(class_counts)
    class_weights = torch.FloatTensor(class_weights.values).to(device)
    print(f"Веса классов: {class_weights}")

    # Преобразование в тензоры
    X_train_tensor = torch.FloatTensor(X_train).to(device)
    y_train_tensor = torch.LongTensor(y_train).to(device)
    X_val_tensor = torch.FloatTensor(X_val).to(device)
    y_val_tensor = torch.LongTensor(y_val).to(device)

    # Создание DataLoader
    train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
    val_dataset = TensorDataset(X_val_tensor, y_val_tensor)
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE)

except Exception as e:
    print(f"Ошибка при обработке данных: {e}")
    exit()

# Определение нейронной сети
class TrafficClassifier(nn.Module):
    def __init__(self, input_size, num_classes):
        super(TrafficClassifier, self).__init__()
        self.model = nn.Sequential(
            nn.Linear(input_size, 256),
            nn.ReLU(),
            nn.BatchNorm1d(256),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.BatchNorm1d(128),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Dropout(0.3),
            nn.Linear(64, num_classes)
        )

    def forward(self, x):
        return self.model(x)

# Инициализация модели
input_size = X_train.shape[1]
num_classes = len(CATEGORIES)
model = TrafficClassifier(input_size, num_classes).to(device)
criterion = nn.CrossEntropyLoss(weight=class_weights)
optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)

# Обучение модели
print("\nОбучение модели...")
best_val_accuracy = 0
best_model_path = MODEL_PATH

for epoch in range(EPOCHS):
    model.train()
    train_loss = 0
    train_correct = 0
    train_total = 0

    for X_batch, y_batch in train_loader:
        optimizer.zero_grad()
        outputs = model(X_batch)
        loss = criterion(outputs, y_batch)
        loss.backward()
        optimizer.step()

        train_loss += loss.item()
        _, predicted = torch.max(outputs.data, 1)
        train_total += y_batch.size(0)
        train_correct += (predicted == y_batch).sum().item()

    train_loss /= len(train_loader)
    train_accuracy = 100 * train_correct / train_total

    # Валидация
    model.eval()
    val_loss = 0
    val_correct = 0
    val_total = 0
    val_predictions = []
    val_true = []
    with torch.no_grad():
        for X_batch, y_batch in val_loader:
            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)
            val_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            val_total += y_batch.size(0)
            val_correct += (predicted == y_batch).sum().item()
            val_predictions.extend(predicted.cpu().numpy())
            val_true.extend(y_batch.cpu().numpy())

    val_loss /= len(val_loader)
    val_accuracy = 100 * val_correct / val_total

    # Сохранение лучшей модели
    if val_accuracy > best_val_accuracy:
        best_val_accuracy = val_accuracy
        os.makedirs(os.path.dirname(best_model_path), exist_ok=True)
        torch.save(model.state_dict(), best_model_path)
        print(f"Сохранена лучшая модель на эпохе {epoch+1} с Val Accuracy: {val_accuracy:.2f}%")

    print(f"Эпоха {epoch+1}/{EPOCHS}: "
          f"Train Loss: {train_loss:.4f}, Train Accuracy: {train_accuracy:.2f}%, "
          f"Val Loss: {val_loss:.4f}, Val Accuracy: {val_accuracy:.2f}%")

# Загрузка лучшей модели
model.load_state_dict(torch.load(best_model_path))
print(f"\nЛучшая модель загружена из {best_model_path}")

# Матрица ошибок и отчёт
cm = confusion_matrix(val_true, val_predictions)
print("\nМатрица ошибок:")
print(cm)
print("\nОтчёт классификации:")
print(classification_report(val_true, val_predictions, target_names=le.classes_))

# Визуализация матрицы ошибок
plt.figure(figsize=(10, 8))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=le.classes_, yticklabels=le.classes_)
plt.xlabel('Predicted')
plt.ylabel('True')
plt.title('Confusion Matrix')
plt.show()

# Итоговые метки
print(f"\nСоответствие меток: {dict(zip(range(len(le.classes_)), le.classes_))}")