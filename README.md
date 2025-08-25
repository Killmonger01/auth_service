# Auth Service

Сервис авторизации на FastAPI с PostgreSQL и Docker.

## Запуск

```bash
git clone git@github.com:Killmonger01/auth_service.git
cd auth-service
docker-compose up --build
```

## Проверка в другом терминале

### 1. Основной эндпоинт
```bash
curl http://localhost:8000/
```
Ответ: `{"message":"Auth Service API"}`

### 2. Регистрация
```bash
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "testpass123",
    "full_name": "Test User"
  }'
```

### 3. Авторизация (получение JWT токена)
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test@example.com&password=testpass123"
```
Ответ:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```
Скопируйте значение `access_token` для следующего шага.

### 4. Получение данных пользователя
```bash
curl -X GET "http://localhost:8000/api/v1/users/me" \
  -H "Authorization: Bearer ВАШ_ТОКЕН"
```

## Документация API

http://localhost:8000/docs