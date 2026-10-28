# Wolf Tower Universal

Объединённая сборка исходников Wolf Tower: YouTube, Instagram и WhatsApp (включая WhatsApp Business), с Telegram из исходной универсальной архитектуры, если он уже описан в коде/профилях.

## Состав
- Базовая версия: Wolf-Tower-YI (более новые проверки скорости пробы, IPv4-only для ByeDPI, выбор сервисов и локализация).
- Добавлен профиль WhatsApp из Wolf-Tower-WApp.
- В `profiles/profiles.json` объединены профили и каталоги стратегий.
- Сохранены исходники обеих версий и desktop/Android исходники.

## Сборка Android
```bash
gradle -p android assembleDebug
```

## Важно: статус интеграции
Это объединение исходников и профилей, а не подтверждённый релиз. Конфликтующие Kotlin/JS файлы сохранены из более новой YI-версии; стратегии WhatsApp с UDP нужно проверить на совместимость с текущими `StrategyArgs.kt` и `desktop/src/profiles.js`. В интерфейсе проверить, что WhatsApp можно включить, что `com.whatsapp`/`com.whatsapp.w4b` маршрутизируются, и что звонки работают. Также требуется сборка Android и desktop-тесты в реальной сети. Не публикуйте APK до прохождения этих проверок.

## Лицензии
См. `third_party/LICENSES/` и лицензии сторонних библиотек.
