## JWT Service

### Описание
Фрагмент, реализующий часть сервиса авторизации.

### Сборка
В корневой директории выполнить команду
```shell
docker-compose up -d
```
Или эту с явным указанием `docker-compose` файла
```shell
docker-compose -f docker-compose.yml up -d
```

### Swagger
Открыть Swagger UI в браузере:
```shell
localhost:port/swagger/index.html
```

### Эндпоинты
| Метод | Путь                      | Описание                                           | Защита     |
|-------|---------------------------|----------------------------------------------------|------------|
| GET   | `/api/v1/tokens/generate` | Выдаёт пару токенов (access, refresh) по `user_id` | публичный  |
| POST  | `/api/v1/tokens/refresh`  | Обновляет пару токенов                             | публичный  |
| GET   | `/api/v1/whoami`          | Возвращает `user_id` текущего пользователя         | Bearer JWT |
| POST  | `/api/v1/logout`          | Деавторизация: отзывает токены                     | Bearer JWT |
