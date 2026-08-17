```markdown
# LazyRoot v2.0 — адаптивный контейнер данных

> *«Скажи своему процессору спасибо»*


## 🇷🇺 Русская версия

### Что это?

**LazyRoot** — это протокол упаковки данных, который подстраивается под объём оперативной памяти вашего компьютера. Он разбивает файл на блоки размером, зависящим от корня из RAM, и раскладывает их по матрицам 4×4 змейкой.

**Это не шифр.** Это способ подготовить данные так, чтобы процессору было удобно их обрабатывать: крупные, ровные блоки, без мусорных огрызков, с предсказуемым обходом.

### Проблема: почему 128 бит — это плохо?

AES и другие стандартные алгоритмы используют фиксированный блок в **128 бит (16 байт)**. Это удобно для математики, но **неудобно для процессора**:

- Современные CPU читают данные кэш-линиями по **64 байта**. Работа с блоками по 16 байт создаёт лишние микро-операции и неэффективно использует кэш.
- Маленькие блоки приводят к фрагментации и мусорным хвостам (< 16 байт).
- Размер блока не зависит от объёма RAM, хотя чем больше памяти — тем крупнее блоки можно обрабатывать за раз.

**LazyRoot решает эту проблему**, динамически подбирая размер блока под ваше железо.

### Решение: адаптивный блок от √RAM

LazyRoot вычисляет максимальный размер блока по формуле:

```

max_block_bits = round_up( sqrt( RAM_GB * 1024 ) )

```

И округляет до ближайшей степени двойки: **256 бит** (32 байта) или **512 бит** (64 байта).

Чем больше оперативной памяти, тем крупнее блоки — это снижает накладные расходы на управление и улучшает кэш-локальность.

**Минимальный порог:** 32 ГБ, чтобы избежать блоков меньше 256 бит (иначе появляются нежелательные половинные блоки размером 64/128).

### Правила заполнения (строго!)

В системе существуют **только два типа блоков**:

- **Полный** — `256/256` или `512/512` (размер равен максимуму)
- **Половинный** — `128/256` или `256/512` (ровно половина максимума)

Если остаток данных меньше половины блока, он дополняется нулями (padding) до половинного блока. Если остаток больше половины — дополняется до полного.

Это гарантирует, что в системе никогда не появляется блок с "мусорным" размером (например, `32/256` или `64/512`). Это упрощает парсинг и делает структуру предсказуемой.

### Змеиное заполнение и ленивые матрицы

Данные укладываются в матрицы **4×4** (16 ячеек) обходом «змейкой»:

- Чётные строки → слева направо (`➔`)
- Нечётные строки → справа налево (`◀`)

Пример змейки в матрице (номера ячеек по порядку заполнения):

```
0  1  2  3
7  6  5  4
8  9 10 11
15 14 13 12
```

Матрицы создаются **лениво**: только тогда, когда в предыдущей закончились свободные ячейки. При этом **одна матрица заполняется полностью, прежде чем создаётся следующая**. Если в текущей матрице есть хотя бы одна пустая ячейка — новая матрица не создаётся. Это предотвращает фрагментацию на уровне матриц.

### Интеграция с AES-GCM

LazyRoot не шифрует данные, но **отлично дружит с шифрованием**.

Вы можете зашифровать каждый блок отдельно с помощью **AES-256-GCM**, используя уникальный nonce (например, из индексов матрицы). Это даёт:

- Стойкость к атакам (аутентификация и шифрование)
- Возможность расшифровывать только нужные блоки (частичное чтение)
- Более высокую производительность благодаря крупным блокам (меньше вызовов шифрования)

LazyRoot становится идеальным **контейнером** для зашифрованных данных, сохраняя кэш-дружелюбную структуру.

### Установка

```bash
pip install numpy psutil pycryptodome
```

Требуется Python 3.8+.

Пример использования

```python
from lazyroot_crypto import pack_data, unpack_data, encrypt_packed, decrypt_packed
import os

# Параметры (автоматически определяются из RAM)
max_block_bytes = 32   # для 32 ГБ
total_matrices = 10    # для примера

# Данные
data = b"Hello, LazyRoot with AES-GCM!"

# Упаковка
buffer, meta, sizes, created = pack_data(data, max_block_bytes, total_matrices)

# Шифрование (ключ 256 бит)
key = os.urandom(32)
encrypted_buffer, new_meta = encrypt_packed(buffer, meta, sizes, key, max_block_bytes)

# Расшифровка
decrypted_buffer, restored_meta, restored_sizes = decrypt_packed(
    encrypted_buffer, new_meta, sizes, key, max_block_bytes
)

# Распаковка
restored_data = unpack_data(decrypted_buffer, restored_meta, restored_sizes, max_block_bytes)

assert restored_data == data
print("✅ Данные успешно упакованы, зашифрованы и восстановлены!")
```

Лицензия

MIT License. Подробнее в файле LICENSE.

Автор

Yaroslav Ishkov — создатель LazyRoot.


🇬🇧 English Version

What is LazyRoot?

LazyRoot is a data packing protocol that adapts to the amount of RAM in your computer. It splits files into blocks whose size depends on the square root of RAM, and arranges them in 4×4 matrices in a snake-like pattern.

It is not a cipher. It is a way to prepare data so the CPU can process it efficiently: large, aligned blocks, no garbage leftovers, and predictable access patterns.

The Problem: Why 128 bits is bad?

AES and other standards use a fixed 128-bit (16-byte) block. This is mathematically convenient but unfriendly to modern CPUs:

· CPUs read data in 64-byte cache lines. Working with 16-byte blocks causes extra micro-operations and poor cache usage.
· Small blocks lead to fragmentation and tiny tails (<16 bytes).
· Block size does not depend on available RAM, even though more RAM could handle larger blocks at once.

LazyRoot fixes this by dynamically choosing the block size based on your hardware.

The Solution: Adaptive Block from √RAM

LazyRoot calculates the maximum block size as:

```
max_block_bits = round_up( sqrt( RAM_GB * 1024 ) )
```

Rounded to the nearest power of two: 256 bits (32 bytes) or 512 bits (64 bytes).

More RAM → larger blocks → lower overhead and better cache locality.

Minimum threshold: 32 GB, to avoid blocks smaller than 256 bits (which would create unwanted half‑blocks like 64/128).

Filling Rules (strict!)

There are only two types of blocks:

· Full — 256/256 or 512/512 (size equals maximum)
· Half — 128/256 or 256/512 (exactly half of maximum)

If the remaining data is less than half a block, it is padded with zeros to a half‑block. If it is more than half, it is padded to a full block.

This guarantees that no "garbage" sizes ever appear (e.g., 32/256 or 64/512), simplifying parsing and making the structure predictable.

Snake Filling and Lazy Matrices

Data is placed into 4×4 matrices (16 cells) using a snake pattern:

· Even rows → left to right (➔)
· Odd rows → right to left (◀)

Snake order (cell numbers):

```
 0  1  2  3
 7  6  5  4
 8  9 10 11
15 14 13 12
```

Matrices are created lazily: only when the previous one has no free cells. A new matrix is not created until the current one is completely filled. This prevents fragmentation at the matrix level.

Integration with AES-GCM

LazyRoot does not encrypt data, but plays nicely with encryption.

You can encrypt each block individually with AES-256-GCM, using a unique nonce (e.g., derived from matrix indices). This gives:

· Strong security (authentication + encryption)
· Ability to decrypt only needed blocks (partial read)
· Better performance thanks to larger blocks (fewer cipher calls)

LazyRoot becomes an ideal container for encrypted data, preserving cache‑friendly structure.

Installation

```bash
pip install numpy psutil pycryptodome
```

Requires Python 3.8+.

Usage Example

```python
from lazyroot_crypto import pack_data, unpack_data, encrypt_packed, decrypt_packed
import os

# Parameters (auto‑detected from RAM)
max_block_bytes = 32   # for 32 GB
total_matrices = 10    # example

# Data
data = b"Hello, LazyRoot with AES-GCM!"

# Packing
buffer, meta, sizes, created = pack_data(data, max_block_bytes, total_matrices)

# Encrypt (256‑bit key)
key = os.urandom(32)
encrypted_buffer, new_meta = encrypt_packed(buffer, meta, sizes, key, max_block_bytes)

# Decrypt
decrypted_buffer, restored_meta, restored_sizes = decrypt_packed(
    encrypted_buffer, new_meta, sizes, key, max_block_bytes
)

# Unpack
restored_data = unpack_data(decrypted_buffer, restored_meta, restored_sizes, max_block_bytes)

assert restored_data == data
print("✅ Data successfully packed, encrypted, and restored!")
```

License

MIT License. See LICENSE for details.

Author

Yaroslav Ishkov — creator of LazyRoot.


🌟 Support the Project

If you find LazyRoot useful or interesting, please give it a ⭐️ on GitHub and share it in your communities. Contributions and ideas are welcome!
```