def text_to_blocks(text):
    utf8_bytes = [ord(i) for i in text]
    block_size = 16

    blocks = [list(utf8_bytes[i:i + block_size]) for i in range(0, len(utf8_bytes), block_size)]

    # Если последний блок меньше 128 бит, добавим нулевые байты для заполнения
    last_block_length = len(blocks[-1])
    if last_block_length < block_size:
        padding_length = block_size - last_block_length
        blocks[-1] += [0] * padding_length

    return blocks


def blocks_to_text(blocks):
    utf8_bytes = [bytes(block) for block in blocks]
    text = "".join([chr(j) for i in utf8_bytes for j in bytes(i)])
    return text


# text = "wddwad"
# encoded_blocks = text_to_blocks(text)
# print(encoded_blocks)
#
# decoded_text = blocks_to_text(encoded_blocks)
# print(decoded_text)  # Выведет исходный текст

def parse_string_to_2d_array(input_str):
    # Удаляем лишние символы, такие как '[', ']', и пробелы
    clean_str = input_str.replace('[', '').replace(']', '').replace(' ', '')

    # Разбиваем строку по запятым и преобразуем каждый элемент в int
    flat_list = [int(num) for num in clean_str.split(',')]

    # Создаем двумерный массив с использованием list comprehension
    # В данном случае, мы используем одну строку и задаем количество столбцов (в данном случае, 4)
    # Можно адаптировать это значение в зависимости от вашего конкретного случая
    columns = 16
    two_d_array = [flat_list[i:i + columns] for i in range(0, len(flat_list), columns)]

    return two_d_array


# Пример использования
input_str = "[[193, 127, 224, 152, 237, 249, 49, 252, 132, 152, 237, 10, 162, 146, 29, 75], [193, 127, 224, 152, 237, 249, 49, 252, 132, 152, 237, 10, 162, 146, 29, 75], [193, 127, 224, 152, 237, 249, 49, 252, 132, 152, 237, 10, 162, 146, 29, 75]]"
result_array = parse_string_to_2d_array(input_str)
print(result_array)