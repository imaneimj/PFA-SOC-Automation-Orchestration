FROM python:3.12-slim

# Empêche la création des fichiers .pyc
ENV PYTHONDONTWRITEBYTECODE=1

# Affiche directement les logs Python
ENV PYTHONUNBUFFERED=1

# Répertoire de travail
WORKDIR /app

# Installer les dépendances système (optionnel mais utile)
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copier les dépendances Python
COPY requirements.txt .

# Installer les dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copier le projet
COPY . .

# Port exposé
EXPOSE 8090

# Lancer FastAPI
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8090"]