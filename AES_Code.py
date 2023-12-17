import AES_Constants as aesc
import tkinter as tk
from tkinter import ttk
from tkinter.messagebox import showinfo
import AES_HelpfulFunctions as aesf


def AddRoundKey(state, keySchedule, rnd=0):
    # Трансформация производит побитовый XOR каждого элемента из State
    # с соответствующим элементом из RoundKey (KeySchedule)

    for row in range(4):
        for column in range(aesc.nb):
            state[row][column] = state[row][column] ^ keySchedule[row][aesc.nb * rnd + column]

    return state


def SubBytes(state, inv=False):
    # Преобразование представляет собой замену каждого байта из State на соответствующий ему из константной таблицы Sbox
    # При дешифровании из InvSbox

    if not inv:
        box = aesc.sbox
    else:
        box = aesc.inv_sbox

    for i in range(len(state)):
        for j in range(len(state[i])):
            row = state[i][j] // 0x10
            col = state[i][j] % 0x10

            box_elem = box[16 * row + col]
            state[i][j] = box_elem

    return state


def ShiftRows(state, inv=False):
    # Простая трансформация. Она выполняет циклический сдвиг влево на 1 элемент для первой строки,
    # на 2 для второй и на 3 для третьей. Нулевая строка не сдвигается.
    # А при дешифрации выполняется циклический сдвиг вправо по тем же правилам

    count = 1

    if not inv:
        for i in range(1, aesc.nb):
            state[i] = aesf.left_shift(state[i], count)
            count += 1
    else:
        for i in range(1, aesc.nb):
            state[i] = aesf.right_shift(state[i], count)
            count += 1

    return state


def MixColumns(state, inv=False):
    # В рамках этой трансформации каждая колонка в State представляется в виде многочлена и перемножается в поле GF(256)
    # при шифровании по модулю x^4 + 1 с фиксированным многочленом 3x^3 + x^2 + x + 2.
    # при дешифровании по модулю x^4 + 1 с фиксированным многочленом {0b}x^3 + {0d}x^2 + {09}x + {0e}.

    for col in range(aesc.nb):

        if not inv:  # encryption
            s0 = aesf.mul_by_02(state[0][col]) ^ aesf.mul_by_03(state[1][col]) ^ state[2][col] ^ state[3][col]
            s1 = state[0][col] ^ aesf.mul_by_02(state[1][col]) ^ aesf.mul_by_03(state[2][col]) ^ state[3][col]
            s2 = state[0][col] ^ state[1][col] ^ aesf.mul_by_02(state[2][col]) ^ aesf.mul_by_03(state[3][col])
            s3 = aesf.mul_by_03(state[0][col]) ^ state[1][col] ^ state[2][col] ^ aesf.mul_by_02(state[3][col])
        else:  # decryption
            s0 = aesf.mul_by_0e(state[0][col]) ^ aesf.mul_by_0b(state[1][col]) ^ aesf.mul_by_0d(
                state[2][col]) ^ aesf.mul_by_09(state[3][col])
            s1 = aesf.mul_by_09(state[0][col]) ^ aesf.mul_by_0e(state[1][col]) ^ aesf.mul_by_0b(
                state[2][col]) ^ aesf.mul_by_0d(state[3][col])
            s2 = aesf.mul_by_0d(state[0][col]) ^ aesf.mul_by_09(state[1][col]) ^ aesf.mul_by_0e(
                state[2][col]) ^ aesf.mul_by_0b(state[3][col])
            s3 = aesf.mul_by_0b(state[0][col]) ^ aesf.mul_by_0d(state[1][col]) ^ aesf.mul_by_09(
                state[2][col]) ^ aesf.mul_by_0e(state[3][col])

        state[0][col] = s0
        state[1][col] = s1
        state[2][col] = s2
        state[3][col] = s3

    return state


def KeyExpansion(key):
    # Эта вспомогательная трансформация формирует набор раундовых ключей — KeySchedule.
    # KeySchedule представляет собой длинную таблицу, состоящую из Nb*(Nr + 1) столбцов или (Nr + 1) блоков,
    # каждый из которых равен по размеру State.

    # Проверка на то, что размер ключа равен 128 бит, если нет, то добавляем до 128 бит
    if len(key) < 4 * aesc.nk:
        for i in range(4 * aesc.nk - len(key)):
            key.append(0x01)

    # Заполняем первый раундовый ключ на основе секретного ключа по формуле KeySchedule[r][c] = SecretKey[r + 4c]
    keySchedule = [[] for _ in range(4)]
    for row in range(4):
        for column in range(aesc.nk):
            keySchedule[row].append(key[row + 4 * column])

    # Заполняем оставшиеся nr таблиц раундовых ключей
    for column in range(aesc.nk, aesc.nb * (aesc.nr + 1)):

        # Если номер колонки кратен nk
        if column % aesc.nk == 0:
            # берем колонку с номером column - 1 и делаем циклический сдвиг влево на 1 элемент
            tmp = [keySchedule[row][column - 1] for row in range(1, 4)]
            tmp.append(keySchedule[0][column - 1])

            # Затем заменяем все байты колонки на соответствующие из Sbox
            for j in range(len(tmp)):
                sbox_row = tmp[j] // 0x10
                sbox_col = tmp[j] % 0x10
                sbox_elem = aesc.sbox[16 * sbox_row + sbox_col]
                tmp[j] = sbox_elem

            # И выполняем XOR между колонкой column - nk, измененной column - 1 и колонкой rcon[column / nk-1]
            # Результат записываем в колонку с номером column
            for row in range(4):
                s = (keySchedule[row][column - 4]) ^ (tmp[row]) ^ (aesc.rcon[row][int(column / aesc.nk - 1)])
                keySchedule[row].append(s)

        else:
            # just make XOR of 2 columns
            for row in range(4):
                s = keySchedule[row][column - 4] ^ keySchedule[row][column - 1]
                keySchedule[row].append(s)

    return keySchedule


def encrypt(inputBytes, key):
    # Инициализируем и заполняем state. State[r][c] = input[r + 4c]
    state = [[] for _ in range(4)]
    for row in range(4):
        for column in range(aesc.nb):
            state[row].append(inputBytes[row + 4 * column])

    # Генерируем раундовые ключи, которые будут добавляться к ключу на каждом раунде
    keySchedule = KeyExpansion(key)

    # Применяем AddRoundKey к State. Инициализация
    state = AddRoundKey(state, keySchedule)

    # Выполняем nr - 1 раундов
    for rnd in range(1, aesc.nr):
        state = SubBytes(state)
        state = ShiftRows(state)
        state = MixColumns(state)
        state = AddRoundKey(state, keySchedule, rnd)

    # Последний раунд
    state = SubBytes(state)
    state = ShiftRows(state)
    state = AddRoundKey(state, keySchedule, aesc.nr)

    # Копируем state в output по правилу
    output = [None for _ in range(4 * aesc.nb)]

    for row in range(4):
        for column in range(aesc.nb):
            output[row + 4 * column] = state[row][column]

    return output


def decrypt(cipher, key):
    # Инициализируем и заполняем state. State[r][c] = input[r + 4c]
    state = [[] for _ in range(4)]
    for row in range(4):
        for column in range(aesc.nb):
            state[row].append(cipher[row + 4 * column])

    # Генерируем раундовые ключи, которые будут добавляться к ключу на каждом раунде
    keySchedule = KeyExpansion(key)

    # Применяем AddRoundKey к State. Инициализация
    state = AddRoundKey(state, keySchedule, aesc.nr)

    # Выполняем nr - 1 раундов
    rnd = aesc.nr - 1
    while rnd >= 1:
        state = ShiftRows(state, inv=True)
        state = SubBytes(state, inv=True)
        state = AddRoundKey(state, keySchedule, rnd)
        state = MixColumns(state, inv=True)
        rnd -= 1

    # Последний раунд
    state = ShiftRows(state, inv=True)
    state = SubBytes(state, inv=True)
    state = AddRoundKey(state, keySchedule, rnd)

    # Копируем state в output по правилу
    output = [None for _ in range(4 * aesc.nb)]

    for row in range(4):
        for column in range(aesc.nb):
            output[row + 4 * column] = state[row][column]

    return output


def encryptString():
    if textToCryptEntry.get() and keyToCryptEntry.get():
        inputText = textToCryptEntry.get()
        inputKey = keyToCryptEntry.get()

        encryptedTextBlocks = getInputBlocksBytes(inputText)
        encryptedKey = [ord(i) for i in inputKey]

        # print(encryptedTextBlocks)
        # print(encryptedKey)

        encryptedText = []
        for block in encryptedTextBlocks:
            encryptedText.append(encrypt(block, encryptedKey))

        print(f"Исходная строка: {inputText}")
        print(f"Исходный ключ: {inputKey}")
        print(f"Зашифрованная строка: {encryptedText}\n")


def decryptString():
    if textToCryptEntry.get() and keyToCryptEntry.get():
        inputText = textToCryptEntry.get()
        inputKey = keyToCryptEntry.get()

        # Парсим входную строку
        clean_str = inputText.replace('[', '').replace(']', '').replace(' ', '')
        flat_list = [int(num) for num in clean_str.split(',')]

        encryptedText = [flat_list[i:i + 16] for i in range(0, len(flat_list), 16)]
        encryptedKey = [ord(i) for i in inputKey]

        decryptedTextBlocks = []
        for block in encryptedText:
            decryptedTextBlocks.append(decrypt(block, encryptedKey))

        decryptedText = getBlocksBytesToText(decryptedTextBlocks)

        print(f"Исходная строка: {inputText}")
        print(f"Исходный ключ: {inputKey}")
        print(f"Дешифрованная строка: {decryptedText}\n")


def update_label(entry):
    keyCountLabel['text'] = "Количество символов: " + str(len(entry.get()))


def getInputBlocksBytes(inputText):
    utf8_bytes = [ord(i) for i in inputText]
    block_size = 16

    blocks = [list(utf8_bytes[i:i + block_size]) for i in range(0, len(utf8_bytes), block_size)]

    # Если последний блок меньше 128 бит, добавим нулевые байты для заполнения
    last_block_length = len(blocks[-1])
    if last_block_length < block_size:
        padding_length = block_size - last_block_length
        blocks[-1] += [0] * padding_length

    return blocks


def getBlocksBytesToText(blocks):
    utf8_bytes = [bytes(block) for block in blocks]
    text = "".join([chr(j) for i in utf8_bytes for j in bytes(i)])
    return text


if __name__ == "__main__":
    root = tk.Tk()
    root.title("Криптографический алгоритм. AES-128. Овинкин Кирилл")
    root.geometry("500x300")

    chooseToCrypt = ttk.Frame(root)
    chooseToCrypt.pack(padx=50, fill='x', expand=True)

    textToCryptLabel = ttk.Label(chooseToCrypt, text="Введите текст (Латиницей)")
    textToCryptLabel.pack(fill='x', pady=10, expand=True)

    textToCryptEntry = ttk.Entry(chooseToCrypt, textvariable=tk.StringVar())
    textToCryptEntry.pack(fill='x', expand=True)

    keyToCryptLabel = ttk.Label(chooseToCrypt, text="Введите ключ. (Латиницей) (Длина 16 символов (байт))")
    keyToCryptLabel.pack(fill='x', pady=10, expand=True)

    keyToCryptEntry = ttk.Entry(chooseToCrypt, textvariable=tk.StringVar())
    keyToCryptEntry.pack(fill='x', expand=True)

    keyCountLabel = ttk.Label(chooseToCrypt, text="")
    keyCountLabel.pack(fill='x', pady=10, expand=True)

    update_label(keyToCryptEntry)
    keyToCryptEntry.bind('<KeyRelease>', lambda e: update_label(e.widget))

    textToCryptSubmit = ttk.Button(chooseToCrypt, text="Шифровать",
                                   command=encryptString)
    textToCryptSubmit.pack(pady=10, expand=True)

    textToDecryptSubmit = ttk.Button(chooseToCrypt, text="Дешифровать",
                                     command=decryptString)
    textToDecryptSubmit.pack(pady=10, expand=True)

    root.mainloop()
