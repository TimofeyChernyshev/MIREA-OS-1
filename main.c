#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

int main(int argc, char* argv[]) {
    if (argc != 5) {
        printf("Использование: %s <lib_path> <key> <src_file> <dst_file>\n", argv[0]);
        return 1;
    }
    
    char* lib_path = argv[1];
    char* key = argv[2];
    char* src_file = argv[3];
    char* dst_file = argv[4];
    
    // Загрузка библиотеки
    void* handle = dlopen(lib_path, RTLD_LAZY);
    if (!handle) {
        printf("Ошибка загрузки библиотеки: %s\n", dlerror());
        return 1;
    }

    // Получение функций из библиотеки
    void (*caesar)(void*, void*, int) = (void(*)(void*,void*,int))dlsym(handle, "caesar");
    void (*caesar_key)(char) = (void(*)(char))dlsym(handle, "caesar_key");
    
    if (!caesar || !caesar_key) {
        printf("Ошибка получения функций из библиотеки\n");
        dlclose(handle);
        return 1;
    }

    // Установка ключа
    caesar_key(key[0]);

    // Чтение исходного файла
    FILE* src = fopen(src_file, "rb");
    if (!src) {
        printf("Ошибка открытия файла %s\n", src_file);
        dlclose(handle);
        return 1;
    }

    // Определение размера файла
    fseek(src, 0, SEEK_END);
    long size = ftell(src);
    fseek(src, 0, SEEK_SET);

    // Выделение памяти
    void* data = malloc(size);
    void* result = malloc(size);
    
    fread(data, 1, size, src);
    fclose(src);

    // Шифрование через библиотеку
    caesar(data, result, size);

    // Запись результата
    FILE* dst = fopen(dst_file, "wb");
    fwrite(result, 1, size, dst);
    fclose(dst);

    // Очистка
    free(data);
    free(result);
    dlclose(handle);
    
    return 0;
}