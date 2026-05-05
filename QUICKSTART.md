# Краткая шпаргалка - Новые функции Whatsminer M50S

## 🎮 Быстрый старт

```bash
# Первый запуск (сканирование)
python3 asic.py --scan 192.168.1.0/24

# Обычный запуск
python3 asic.py
```

## ⌨️ Горячие клавиши (НОВЫЕ)

| Клавиша | Действие | Параметры |
|---------|----------|-----------|
| **C** | Установить частоту | 50-100% |
| **V** | Установить напряжение | 700-1000 мВ |
| **G** | Просмотреть логи | Последние 50 строк |
| **H** | Информация о хеш-платах | - |
| **B** | Резервная копия конфигурации | Автоматическое имя |
| **N** | Изменить пароль | Требует ввода пароля |

## 📊 Поддерживаемые команды

### Получение информации
- `get.device.info` - Информация об устройстве
- `get.miner.status` - Статус майнера
- `get.miner.status?param=chip` - Температуры чипов
- `get.miner.status?param=hashboard` - Информация о хеш-платах
- `get.miner.status?param=performance` - Статистика производительности
- `get.system.logs` - Системные логи
- `get.system.usb` - USB устройства
- `get.miner.config` - Конфигурация

### Установка параметров
- `set.miner.target_freq` - Частота (50-100%)
- `set.miner.voltage` - Напряжение (700-1000 мВ)
- `set.miner.power_limit` - Лимит мощности (100-3000W)
- `set.miner.power_mode` - Режим питания
- `set.miner.pools` - Пулы майнинга
- `set.fan.zero_speed` - Управление вентиляторами
- `set.system.led` - Управление LED
- `set.system.reboot` - Перезагрузка
- `set.system.factory_reset` - Сброс заводских
- `set.system.auto_recovery` - Автовосстановление
- `set.system.thermal_throttling` - Тепловое ограничение
- `set.user.change_passwd` - Изменить пароль

## 🔢 Диапазоны значений

| Параметр | Минимум | Максимум | Единица | Команда |
|----------|---------|----------|---------|---------|
| Частота | 50 | 100 | % | C |
| Напряжение | 700 | 1000 | мВ | V |
| Мощность | 100 | 3000 | W | L |
| Вентилятор | 0 | 1 | (0/1) | F |
| LED | - | - | цвет | L |
| Режим питания | - | - | normal/low/high | M |

## 📝 Примеры использования через Python

### Создание монитора
```python
import asyncio
from asic import DeviceMonitor

async def main():
    devices = ['192.168.1.100', '192.168.1.101', '192.168.1.102']
    monitor = DeviceMonitor(devices)
    
    # Выбрать первое устройство
    monitor.selected_devices = {'192.168.1.100'}
    
    # Установить частоту 85%
    await monitor.set_frequency(85)
    
    # Установить напряжение 850 мВ
    await monitor.set_voltage(850)
    
    # Получить температуры чипов
    temps = await monitor.get_chip_temperatures('192.168.1.100')
    print(f"Температуры: {temps}")
    
    # Создать резервную копию
    await monitor.backup_configuration('192.168.1.100')
    
    # Получить логи
    logs = await monitor.get_system_logs('192.168.1.100', lines=20)
    for log in logs:
        print(log)

asyncio.run(main())
```

### Валидация данных
```python
# Проверить IP адрес
monitor.validate_ip('192.168.1.100')  # True

# Проверить частоту
monitor.validate_frequency(85)  # True
monitor.validate_frequency(150)  # False

# Проверить напряжение
monitor.validate_voltage(850)  # True
monitor.validate_voltage(500)  # False

# Проверить мощность
monitor.validate_power(1500)  # True
monitor.validate_power(5000)  # False
```

## 🛠️ Устранение неполадок

### Проблема: Ошибка подключения
```
Решение: Проверьте IP адрес и доступность устройства
python3 -c "import asyncio; from asic import DeviceMonitor; m = DeviceMonitor(['IP']); print(asyncio.run(m.check_connection('IP')))"
```

### Проблема: Неверная частота/напряжение
```
Решение: Проверьте диапазон значений перед установкой
- Частота: 50-100%
- Напряжение: 700-1000 мВ
```

### Проблема: Ошибка обновления прошивки
```
Решение: 
1. Убедитесь что файл firmware.bin существует
2. Проверьте размер файла
3. Убедитесь что устройство онлайн
4. Посмотрите логи в asic_monitor.log
```

## 📊 Структура ответов

### Информация о устройстве
```json
{
  "ip": "192.168.1.100",
  "online": true,
  "model": "M50S",
  "fw_version": "03.0.1.2",
  "hashrate": 45.5,
  "temp": 65.5,
  "fan_in": 4500,
  "fan_out": 5000,
  "power": 3180,
  "target_freq": 85
}
```

### Информация о чипах
```json
{
  "chip_temp_max": 75,
  "chip_temp_min": 60,
  "chip_temp_avg": 68,
  "error_count": 0
}
```

### Логи
```python
[
  "2024-01-15 10:30:45 INFO: Miner started",
  "2024-01-15 10:31:00 INFO: Pool connected",
  "2024-01-15 10:31:15 DEBUG: Hash accepted"
]
```

## 🔒 Безопасность

- **Все команды SET требуют токена**: SHA256 хеш команды + пароль + соль + время
- **Шифрование**: AES-256 CBC для чувствительных параметров
- **Соль**: Кэшируется для оптимизации
- **Лимиты**: Валидация всех входных значений

## 📚 Файлы данных

- `asic_devices.json` - Список найденных устройств
- `asic_monitor.log` - Логи работы (ротация по дням)
- `config_backup_*.json` - Резервные копии конфигурации

## 🎯 Типичный рабочий процесс

1. **Сканирование**: `python3 asic.py --scan 192.168.1.0/24`
2. **Запуск мониторинга**: `python3 asic.py`
3. **Выбор устройств**: `Space` для одного, `A` для всех
4. **Просмотр информации**: `D` для детальной информации
5. **Изменение параметров**:
   - `C` для частоты
   - `V` для напряжения
   - `M` для режима питания
   - `B` для резервной копии
6. **Операции**:
   - `R` для перезагрузки
   - `U` для обновления
   - `F` для сброса

## ✨ Полезные сочетания

```bash
# Только мониторинг (без управления)
python3 asic.py  # и нажимайте только стрелки для навигации

# Обновление с прошивкой
python3 asic.py --firmware /path/to/custom_firmware.bin

# Запуск с определённого IP
python3 asic.py --scan 192.168.1.0/24 && python3 asic.py

# Просмотр логов во время работы
tail -f asic_monitor.log
```

## 🔧 Сложные операции

### Оптимизация энергопотребления
1. Выбрать все устройства: `A`
2. Снизить частоту: `C` → 70
3. Установить напряжение: `V` → 750
4. Снизить питание: `L` → 1500

### Резервная копия перед изменениями
1. Выбрать устройство: `Space`
2. Создать резервную копию: `B`
3. Внести изменения
4. При необходимости восстановить вручную

### Диагностика проблем
1. Включить детальный просмотр: `D`
2. Просмотреть логи: `G`
3. Проверить хеш-платы: `H`
4. Проверить связь с устройством через код

## 📞 Контроль очереди операций

```python
# Проверить статус очереди
print(f"В очереди: {monitor.operation_queue.qsize()} операций")

# Проверить выполняемые операции
print(f"Идёт выполнение: {monitor.operation_progress}")

# Проверить активные задачи
print(f"Активных задач: {len(monitor.active_tasks)}")
```

## 🎓 Продвинутое использование

```python
# Кастомная команда
response = await monitor.send_command('192.168.1.100', {
    "cmd": "get.miner.status",
    "param": "summary"
})

# Множественные команды с asyncio.gather
tasks = [
    monitor.set_frequency(80),
    monitor.set_voltage(800),
    monitor.get_hashboard_info('192.168.1.100')
]
results = await asyncio.gather(*tasks)

# Обработка ошибок с try-except
try:
    await monitor.set_frequency(85)
except ValidationError as e:
    print(f"Ошибка валидации: {e}")
except Exception as e:
    print(f"Неизвестная ошибка: {e}")
```

---

**Версия**: v1.3  
**Дата**: 2024-05-01  
**Поддержка**: Whatsminer M50S и совместимые модели
