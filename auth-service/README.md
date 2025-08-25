# Auth Service

Сервис авторизации на FastAPI с PostgreSQL и Docker.

## Возможности

- Регистрация пользователей
- Аутентификация через JWT токены
- Управление профилем пользователя
- Роли пользователей (обычный/админ)
- Миграции базы данных с Alembic
- Тесты с pytest

## Быстрый старт

1. Клонируйте репозиторий:
```bash
git clone <repository-url>
cd auth-service
```

2. Создайте файл .env:
```bash
cp .env.example .env
```

3. Запустите с Docker Compose:
```bash
docker-compose up -d
```

4. Примените миграции:
```bash
docker-compose exec app alembic upgrade head
```

5. API будет доступно по адресу: http://localhost:8000

## Документация API

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Основные эндпоинты

- `POST /api/v1/auth/register` - Регистрация
- `POST /api/v1/auth/login` - Вход
- `GET /api/v1/users/me` - Текущий пользователь
- `PUT /api/v1/users/me` - Обновление профиля

## Тестирование

```bash
pytest
```

## Разработка без Docker

1. Установите зависимости:
```bash
pip install -r requirements.txt
```

2. Запустите PostgreSQL

3. Примените миграции:
```bash
alembic upgrade head
```

4. Запустите сервер:
```bash
uvicorn app.main:app --reload
```
