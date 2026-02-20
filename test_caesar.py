#!/usr/bin/env python3
import ctypes
import os
import sys

class CaesarTester:
    def __init__(self, lib_path="./libcaesar.so"):
        try:
            self.lib = ctypes.CDLL(lib_path)
            print(f"Библиотека {lib_path} загружена")
        except Exception as e:
            print(f"Ошибка загрузки библиотеки: {e}")
            sys.exit(1)
        
        self.lib.caesar.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
        self.lib.caesar.restype = None
        
        self.lib.caesar_key.argtypes = [ctypes.c_char]
        self.lib.caesar_key.restype = None
    
    def test_key_setting(self):
        print("\nУстановка ключа")
        try:
            self.lib.caesar_key(b'A')
            self.lib.caesar_key(b'X')
            self.lib.caesar_key(b'\x42')
            print("Установка ключа работает")
            return True
        except Exception as e:
            print(f"Ошибка: {e}")
            return False
    
    def test_xor_basic(self):
        print("\nXOR шифрование")
        tests = [
            (b'\x00', b"Test", b"Test"),
            (b'\xFF', bytes([0x01, 0x02, 0x03]), bytes([0xFE, 0xFD, 0xFC])),
        ]
        
        for key, input_data, expected in tests:
            self.lib.caesar_key(key)
            
            src = ctypes.create_string_buffer(input_data)
            dst = ctypes.create_string_buffer(len(input_data))
            
            self.lib.caesar(ctypes.byref(src), ctypes.byref(dst), len(input_data))
            
            result = dst.raw[:len(input_data)]
            if result == expected:
                print(f"Ключ {key}: {input_data} -> {result.hex()}")
            else:
                print(f"Ключ {key}: ожидалось {expected.hex()}, получено {result.hex()}")
                return False
        return True
    
    def test_reversibility(self):
        print("\nОбратимость XOR")
        key = ord('K')
        input_data = b"Testing reversibility"
        
        self.lib.caesar_key(key)
        
        # Первый раз - шифрование
        src1 = ctypes.create_string_buffer(input_data)
        dst1 = ctypes.create_string_buffer(len(input_data))
        self.lib.caesar(ctypes.byref(src1), ctypes.byref(dst1), len(input_data))
        encrypted = dst1.raw[:len(input_data)]
        
        # Второй раз с тем же ключом - дешифрование
        src2 = ctypes.create_string_buffer(encrypted)
        dst2 = ctypes.create_string_buffer(len(encrypted))
        self.lib.caesar(ctypes.byref(src2), ctypes.byref(dst2), len(encrypted))
        decrypted = dst2.raw[:len(encrypted)]
        
        if decrypted == input_data:
            print(f"Обратимость работает: {input_data} -> {encrypted.hex()} -> {decrypted}")
            return True
        else:
            print(f"Ошибка обратимости")
            return False
    
    def test_different_keys(self):
        print("\nРазные ключи")
        input_data = b"Same input"
        
        self.lib.caesar_key(ord('A'))
        srcA = ctypes.create_string_buffer(input_data)
        dstA = ctypes.create_string_buffer(len(input_data))
        self.lib.caesar(ctypes.byref(srcA), ctypes.byref(dstA), len(input_data))
        resultA = dstA.raw[:len(input_data)]
        
        self.lib.caesar_key(ord('B'))
        srcB = ctypes.create_string_buffer(input_data)
        dstB = ctypes.create_string_buffer(len(input_data))
        self.lib.caesar(ctypes.byref(srcB), ctypes.byref(dstB), len(input_data))
        resultB = dstB.raw[:len(input_data)]
        
        if resultA != resultB:
            print(f"Ключи A и B дают разные результаты")
            print(f"A: {resultA.hex()}")
            print(f"B: {resultB.hex()}")
            return True
        else:
            print(f"Ключи дают одинаковый результат")
            return False
    
    def run_all_tests(self):
        tests = [
            ("Установка ключа", self.test_key_setting),
            ("Базовое XOR", self.test_xor_basic),
            ("Обратимость", self.test_reversibility),
            ("Разные ключи", self.test_different_keys),
        ]
        
        passed = 0
        for name, test_func in tests:
            if test_func():
                passed += 1
            else:
                print(f"Тест '{name}' не пройден")
        
        print("\n" + "="*50)
        print(f"ИТОГ: {passed}/{len(tests)} тестов пройдено")
        print("="*50)
        
        # Очистка
        for f in ["test_input.txt", "test_encrypted.bin", "test_decrypted.txt"]:
            if os.path.exists(f):
                os.remove(f)
        
        return passed == len(tests)

if __name__ == "__main__":
    lib_path = sys.argv[1] if len(sys.argv) > 1 else "./libcaesar.so"
    
    tester = CaesarTester(lib_path)
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)