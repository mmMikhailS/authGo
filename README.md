# DeepBoard

![status](https://img.shields.io/badge/status-in%20development-orange)
![go](https://img.shields.io/badge/language-Go-00ADD8)

> 🚧 **Проєкт у розробці та ще дуже сирий.** Можливі баги, неповна функціональність і відсутня документація. API та структура можуть змінюватися без попередження.

TODO: одне-два речення про те, що таке DeepBoard і яке завдання він розв'язує.

## Можливості

Реалізована лише логіка і тести, ендпоінти поки не працюють
- Сервіс автентифікації (`internal/auth`): реєстрація, вхід, оновлення токенів, підтвердження акаунта, зміна та скидання пароля, керування сесіями.

## Структура проєкту

```
internal/
├── auth/            # auth service
└── common/          # shared library
```

TODO: доповнити в міру появи нових сервісів.

## Auth API
Усі шляхи вказано відносно адреси сервісу. Захищені методи використовують Bearer-токен (`bearerAuth`).

| Метод | Шлях                    | Призначення                          |
|-------|-------------------------|--------------------------------------|
| POST  | `/auth/register`        | Реєстрація користувача               |
| POST  | `/auth/login`           | Вхід                                 |
| POST  | `/auth/logout`          | Вихід                                |
| POST  | `/auth/refresh`         | Оновлення токенів                    |
| POST  | `/auth/validate`        | Перевірка access-токена              |
| POST  | `/auth/verify`          | Підтвердження акаунта                |
| POST  | `/auth/verify/resend`   | Повторне надсилання підтвердження    |
| POST  | `/auth/password/change` | Зміна пароля                         |
| POST  | `/auth/password/forgot` | Запит на скидання пароля             |
| POST  | `/auth/password/reset`  | Скидання пароля за кодом             |
| GET   | `/auth/sessions`        | Список активних сесій                |
| POST  | `/auth/sessions/revoke` | Завершення сесії за `device_id`      |

Повна специфікація: TODO (шлях до `openapi.yaml`).

## Швидкий старт

### Встановлення та запуск

```bash
git clone https://github.com/mmMikhailS/DeepBoard.git
cd DeepBoard

cp .env.TODO .env   # заповніть значення
```

## Генерація клієнта

Клієнт і моделі в `internal/common/client/auth` згенеровано за допомогою [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen) v2.6.0. Файли із суфіксом `.gen.go` вручну не редагуйте.

```bash
go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.6.0
oapi-codegen -config TODO/config.yaml TODO/openapi.yaml
```

## Розробка

```bash
go build ./...
go test ./...
```
