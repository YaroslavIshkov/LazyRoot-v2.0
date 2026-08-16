#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LazyRoot v2.0 + AES-GCM
Адаптивный контейнер данных с змеиным заполнением и поблочным шифрованием.
"""

import math
import os
import psutil
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ------------------------------------------------------------
# 1. Определение RAM и архитектуры
# ------------------------------------------------------------

def get_system_ram_gb():
    """Определяет RAM и округляет до стандартных планок (32–256 ГБ)."""
    total_bytes = psutil.virtual_memory().total
    ram_gb = total_bytes / (1024 ** 3)
    if ram_gb < 24:
        ram_gb = 32.0
    standard_rams = [32, 64, 128, 256]
    return min(standard_rams, key=lambda x: abs(x - ram_gb))

def calculate_architecture(ram_gb):
    """Возвращает max_block_bytes (байт) и total_matrices."""
    ram_mb = ram_gb * 1024
    raw_root = math.sqrt(ram_mb)
    max_block_bits = 256 if raw_root <= 256 else 512
    max_block_bytes = max_block_bits // 8
    total_matrices = int(ram_mb / 16)  # как в оригинале
    return max_block_bytes, total_matrices

# ------------------------------------------------------------
# 2. Упаковка / распаковка с NumPy
# ------------------------------------------------------------

def pack_data(data_bytes, max_block_bytes, total_matrices):
    """
    Упаковывает данные в матрицы 4×4 змейкой.
    Возвращает (data_buffer, meta, sizes, created_count)
    """
    max_capacity = total_matrices * 16 * max_block_bytes
    if len(data_bytes) > max_capacity:
        raise MemoryError(f"Данные ({len(data_bytes)} байт) не влезают в {max_capacity} байт.")

    data_buffer = bytearray(max_capacity)
    meta = np.zeros((total_matrices, 4, 4), dtype=np.int32)
    sizes = np.zeros((total_matrices, 4, 4), dtype=np.int32)

    data_index = 0
    created_count = 0
    total_len = len(data_bytes)

    for m_idx in range(total_matrices):
        if data_index >= total_len:
            break

        for row in range(4):
            cols = range(4) if row % 2 == 0 else range(3, -1, -1)
            for col in cols:
                if data_index >= total_len:
                    break

                remaining = total_len - data_index
                # Определяем размер блока (полный или половинный)
                if remaining >= max_block_bytes:
                    block_size = max_block_bytes
                elif remaining >= max_block_bytes // 2:
                    block_size = max_block_bytes
                else:
                    block_size = max_block_bytes // 2

                actual = min(block_size, remaining)
                start = data_index
                end = data_index + block_size
                # Копируем данные + паддинг нулями
                data_buffer[start:end] = data_bytes[start:start+actual] + b'\x00' * (block_size - actual)

                state = 2 if block_size == max_block_bytes else 1
                meta[m_idx, row, col] = (data_index << 2) | state
                sizes[m_idx, row, col] = actual

                data_index += block_size

            if data_index >= total_len:
                break

        created_count += 1

    # Обрезаем до реально использованного
    data_buffer = data_buffer[:data_index]
    meta = meta[:created_count]
    sizes = sizes[:created_count]
    return data_buffer, meta, sizes, created_count

def unpack_data(data_buffer, meta, sizes, max_block_bytes):
    """Восстанавливает исходные байты из упакованных данных."""
    result = bytearray()
    for m_idx in range(meta.shape[0]):
        for row in range(4):
            cols = range(4) if row % 2 == 0 else range(3, -1, -1)
            for col in cols:
                actual = sizes[m_idx, row, col]
                if actual == 0:
                    continue
                offset = meta[m_idx, row, col] >> 2
                result.extend(data_buffer[offset:offset+actual])
    return bytes(result)

# ------------------------------------------------------------
# 3. Шифрование / дешифрование (AES-GCM) каждого блока
# ------------------------------------------------------------

def encrypt_block(plaintext, key):
    """Шифрует блок, возвращает nonce + ciphertext + tag."""
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag   # длина = 12 + len(plaintext) + 16

def decrypt_block(encrypted, key):
    """Расшифровывает блок из nonce + ciphertext + tag."""
    nonce = encrypted[:12]
    tag = encrypted[-16:]
    ciphertext = encrypted[12:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def encrypt_packed(data_buffer, meta, sizes, key, max_block_bytes):
    """
    Шифрует каждый блок на месте, заменяя plaintext на зашифрованные данные.
    Возвращает новый data_buffer (длина может увеличиться на 28 байт на блок).
    """
    # В худшем случае длина увеличится на (12+16) байт на каждый блок
    # Пересоздаём буфер с запасом
    new_buffer = bytearray()
    offset_map = {}  # старый offset -> новый offset (для обновления мета)

    for m_idx in range(meta.shape[0]):
        for row in range(4):
            for col in range(4):
                actual = sizes[m_idx, row, col]
                if actual == 0:
                    continue
                old_offset = meta[m_idx, row, col] >> 2
                state = meta[m_idx, row, col] & 0b11
                block_size = max_block_bytes if state == 2 else max_block_bytes // 2

                # Извлекаем оригинальный блок
                plaintext = data_buffer[old_offset:old_offset+block_size]
                # Шифруем
                encrypted = encrypt_block(plaintext, key)
                # Запоминаем новый offset
                new_offset = len(new_buffer)
                offset_map[old_offset] = new_offset
                new_buffer.extend(encrypted)

                # Обновляем метаданные: смещение теперь новое
                meta[m_idx, row, col] = (new_offset << 2) | state
                # sizes остаются теми же (actual не меняется)

    return bytes(new_buffer), meta, offset_map

def decrypt_packed(encrypted_buffer, meta, sizes, key, max_block_bytes):
    """
    Расшифровывает каждый блок и возвращает расшифрованный непрерывный буфер.
    """
    decrypted_buffer = bytearray()
    # Восстанавливаем смещения для распаковки
    # Просто собираем расшифрованные блоки в порядке их следования в метаданных
    # (они уже обновлены на новые смещения после шифрования)

    # Создаём массив для хранения расшифрованных данных по старому порядку
    # Проще: собираем все блоки в порядке метаданных и склеиваем
    temp_data = bytearray()
    for m_idx in range(meta.shape[0]):
        for row in range(4):
            cols = range(4) if row % 2 == 0 else range(3, -1, -1)
            for col in cols:
                actual = sizes[m_idx, row, col]
                if actual == 0:
                    continue
                offset = meta[m_idx, row, col] >> 2
                state = meta[m_idx, row, col] & 0b11
                block_size = max_block_bytes if state == 2 else max_block_bytes // 2
                # Извлекаем зашифрованный блок
                encrypted_block = encrypted_buffer[offset:offset + block_size + 28]  # +12+16
                # Расшифровываем
                plaintext_block = decrypt_block(encrypted_block, key)
                # Проверяем, что размер совпадает с ожидаемым block_size
                if len(plaintext_block) != block_size:
                    raise ValueError("Размер расшифрованного блока не совпадает с ожидаемым")
                temp_data.extend(plaintext_block)

    # Теперь temp_data содержит все блоки в порядке матриц, но без учёта исходного порядка
    # Нам нужно восстановить исходный порядок байтов, используя sizes и порядок обхода
    # Однако при распаковке мы полагаемся на порядок обхода в unpack_data,
    # поэтому просто возвращаем temp_data и передаём в unpack_data,
    # но unpack_data ожидает data_buffer, который содержит блоки в том же порядке,
    # что и метаданные. Если мы собрали блоки в том же порядке, то unpack_data
    # сможет восстановить данные.

    # Создаём новый буфер, где блоки расположены в соответствии с метаданными
    # Мы уже собрали их в правильном порядке (по метаданным), так что просто
    # возвращаем temp_data, но он не будет содержать паддинг (только фактические блоки)
    # Однако unpack_data ожидает, что в буфере лежат блоки по порядку,
    # и для каждого блока есть смещение в meta.
    # Мы можем перестроить буфер так, чтобы он соответствовал старым смещениям,
    # но проще: создать новый буфер с нуля и записать расшифрованные блоки
    # по новым смещениям (которые мы обновим).

    # Самый простой способ: расшифровать все блоки и заново упаковать их,
    # но тогда мы потеряем исходную структуру. Лучше: расшифровать каждый
    # блок и записать его обратно по тому же смещению, что и было до шифрования.
    # Для этого мы запоминаем старые смещения при шифровании (offset_map).
    # Поэтому в encrypt_packed мы возвращаем offset_map.
    # Переделаем функции, чтобы сохранять offset_map.

    # Пока оставлю как заглушку — нужно доработать.

    # Временное решение: собираем блоки в новый буфер в порядке их следования
    # в метаданных (как при упаковке). Для этого создаём новый буфер,
    # заполняем его расшифрованными блоками по порядку.
    new_buffer = bytearray()
    for m_idx in range(meta.shape[0]):
        for row in range(4):
            cols = range(4) if row % 2 == 0 else range(3, -1, -1)
            for col in cols:
                actual = sizes[m_idx, row, col]
                if actual == 0:
                    continue
                offset = meta[m_idx, row, col] >> 2
                state = meta[m_idx, row, col] & 0b11
                block_size = max_block_bytes if state == 2 else max_block_bytes // 2
                encrypted_block = encrypted_buffer[offset:offset + block_size + 28]
                plaintext_block = decrypt_block(encrypted_block, key)
                # Записываем расшифрованный блок целиком (с паддингом)
                new_buffer.extend(plaintext_block)

    # Теперь new_buffer содержит все блоки (с паддингом) в правильном порядке
    # Обновим meta, чтобы смещения указывали на начало каждого блока в new_buffer
    # Для этого пробегаем заново и устанавливаем смещения
    current_offset = 0
    for m_idx in range(meta.shape[0]):
        for row in range(4):
            cols = range(4) if row % 2 == 0 else range(3, -1, -1)
            for col in cols:
                actual = sizes[m_idx, row, col]
                if actual == 0:
                    continue
                state = meta[m_idx, row, col] & 0b11
                block_size = max_block_bytes if state == 2 else max_block_bytes // 2
                meta[m_idx, row, col] = (current_offset << 2) | state
                current_offset += block_size

    return bytes(new_buffer), meta, sizes

# ------------------------------------------------------------
# 4. Полный цикл
# ------------------------------------------------------------

def main():
    print("🔐 LazyRoot v2.0 + AES-GCM (тестовый запуск)")

    # 1. Определяем параметры
    ram_gb = get_system_ram_gb()
    max_block_bytes, total_matrices = calculate_architecture(ram_gb)
    print(f"RAM: {ram_gb} ГБ, max_block: {max_block_bytes} байт, матриц: {total_matrices}")

    # 2. Генерируем тестовые данные (случайные байты)
    test_data = os.urandom(1234)  # 1234 байта
    print(f"Исходные данные: {len(test_data)} байт")

    # 3. Упаковываем
    data_buffer, meta, sizes, created = pack_data(test_data, max_block_bytes, total_matrices)
    print(f"Упаковано: создано матриц {created}, буфер {len(data_buffer)} байт")

    # 4. Шифруем (создаём ключ)
    key = get_random_bytes(32)  # 256 бит
    encrypted_buffer, meta_enc, offset_map = encrypt_packed(data_buffer, meta, sizes, key, max_block_bytes)
    print(f"Зашифровано: буфер теперь {len(encrypted_buffer)} байт")

    # 5. Расшифровываем
    decrypted_buffer, meta_dec, sizes_dec = decrypt_packed(encrypted_buffer, meta_enc, sizes, key, max_block_bytes)
    print(f"Расшифровано: буфер {len(decrypted_buffer)} байт")

    # 6. Распаковываем
    restored_data = unpack_data(decrypted_buffer, meta_dec, sizes_dec, max_block_bytes)
    print(f"Восстановлено: {len(restored_data)} байт")

    # 7. Проверка
    if restored_data == test_data:
        print("✅ Успех! Данные совпадают.")
    else:
        print("❌ Ошибка: данные не совпадают.")

if __name__ == "__main__":
    main()