from __future__ import annotations

import os
import tempfile
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional

# Імпорт криптосистем з лабораторних робіт
from pr1.cipher import CaesarCipher, BinaryCaesarCipher, CaesarBruteForce
from pr2.cipher import (
    KeyType,
    TrithemiusKey,
    TrithemiusCipher,
    BinaryTrithemiusCipher,
    TrithemiusKnownPlaintextAttack,
    AttackResult,
)
from pr3.cipher import (
    PoemKey,
    PoemCipher,
    BealeCipher,
    OttendorfCipher,
    BookCipherBase,
    POEM_PRESETS,
    BOOK_SAMPLE,
    UK_ALPHABET,
    RU_ALPHABET,
)
from pr5.cipher import (
    CIPHERS,
    KEY_FORMATS,
    MODES,
    OUTPUT_FORMATS,
    PADDINGS,
    NetSymmetricCipher,
    create_cipher,
    decode_input,
    encode_output,
    text_to_bytes,
    to_hex,
)
from pr7.cipher import (
    NET_KEY_SIZES,
    RSA_FACTORING_LIMITS,
    RSA_PADDINGS,
    TEXT_FORMATS,
    TEXTBOOK_MAX_BITS,
    TEXTBOOK_MIN_BITS,
    MAX_XML_LENGTH,
    WIKI_E,
    WIKI_M,
    WIKI_P,
    WIKI_Q,
    NetRSACipher,
    RSAError,
    RSAFactorAttack,
    RSAKey,
    TextbookRSA,
    parse_int,
    parse_numbers,
)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Комп'ютерні практикуми з безпеки ПЗ; ТВ-31 Гогуля Максим")
        self.geometry("1600x800")
        self.minsize(800, 580)

        self._init_ciphers()
        self._create_menu()
        self._create_widgets()

    def _init_ciphers(self):
        """Ініціалізація криптографічних модулів з усіх лабораторних робіт."""
        # --- ПР1: Шифр Цезаря ---
        self.caesar_cipher = CaesarCipher()
        self.caesar_binary_cipher = BinaryCaesarCipher()
        self.caesar_brute_force = CaesarBruteForce(self.caesar_cipher)

        # --- ПР2: Шифр Тритеміуса ---
        self.trithemius_cipher = TrithemiusCipher()
        self.trithemius_binary_cipher = BinaryTrithemiusCipher()
        self.trithemius_attack = TrithemiusKnownPlaintextAttack(self.trithemius_cipher)
        self._trithemius_last_attack_result: Optional[AttackResult] = None

        # --- ПР3: Книжковий шифр ---
        self.poem_cipher = PoemCipher()
        self.book_ciphers: dict[str, BookCipherBase] = {
            "beale": BealeCipher(),
            "ottendorf": OttendorfCipher(),
        }

        # --- ПР7: RSA ---
        self.rsa_textbook = TextbookRSA()
        self.rsa_key: RSAKey = TextbookRSA.make_key(WIKI_P, WIKI_Q, WIKI_E)
        self.rsa_net = NetRSACipher(1024)
        # None означає, що шифруємо власним відкритим ключем, інакше - імпортованим ключем отримувача
        self.rsa_net_public_xml: Optional[str] = None
        self.rsa_attack = RSAFactorAttack()

        # Спільні поля та аліаси для зворотної сумісності
        self.cipher = self.trithemius_cipher
        self.binary_cipher = self.trithemius_binary_cipher
        self.selected_bin_path: Optional[str] = None

    def _create_menu(self):
        """Створення головного системного меню."""
        menubar = tk.Menu(self)

        # Меню Файл
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="📄 Створити новий", command=self.file_new)
        file_menu.add_command(label="📂 Відкрити файл...", command=self.file_open)
        file_menu.add_command(label="💾 Зберегти результат...", command=self.file_save)
        file_menu.add_separator()
        file_menu.add_command(label="🖨️ Друкувати...", command=self.file_print)
        file_menu.add_separator()
        file_menu.add_command(label="🚪 Вихід з системи", command=self.file_exit)
        menubar.add_cascade(label="Файл", menu=file_menu)

        # Меню Довідка
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="ℹ️ Про розробника", command=self.show_about)
        menubar.add_cascade(label="Довідка", menu=help_menu)

        self.config(menu=menubar)

    def _create_widgets(self):
        """Створення вкладок застосунку з розділенням по практичним роботам."""
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # 1. ПР1: Шифр Цезаря (Текст)
        self.tab_caesar = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_caesar, text="🏛️ ПР1: Шифр Цезаря")
        self._caesar_build_tab()

        # 2. ПР1: Brute-Force (Злам)
        self.tab_caesar_bf = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_caesar_bf, text="🔍 ПР1: Brute-Force (Цезар)")
        self._caesar_build_bf_tab()

        # 3. ПР2: Шифр Тритеміуса (Текст)
        self.tab_trithemius = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_trithemius, text="📜 ПР2: Шифр Тритеміуса")
        self._trithemius_build_tab()

        # 4. ПР2: Активна атака на Тритеміуса (KPA)
        self.tab_trithemius_attack = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_trithemius_attack, text="🎯 ПР2: Активна атака (KPA)")
        self._trithemius_build_attack_tab()

        # 5. ПР3: Віршований шифр
        self.tab_poem = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_poem, text="📖 ПР3: Віршований шифр")
        self._poem_build_tab()

        # 6. ПР3: Ключова таблиця вірша
        self.tab_poem_table = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_poem_table, text="🔢 ПР3: Таблиця вірша")
        self._poem_build_table_tab()

        # 7. ПР3: Інші книжкові шифри (додаткове завдання)
        self.tab_book = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_book, text="📚 ПР3: Біл / Оттендорф")
        self._book_build_tab()

        # 8. ПР5: DES / TripleDES / AES (криптопровайдери .NET)
        self.tab_sym = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sym, text="🔐 ПР5: DES / 3DES / AES")
        self._sym_build_tab()

        # 9. ПР5: Шифрування файлів через CryptoStream
        self.tab_sym_file = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sym_file, text="📁 ПР5: CryptoStream (файли)")
        self._sym_build_file_tab()

        # 10-12. ПР7: RSA
        self.tab_rsa = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_rsa, text="🔑 ПР7: RSA (числовий приклад)")
        self._rsa_build_tab()

        self.tab_rsa_net = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_rsa_net, text="🔐 ПР7: RSA (.NET)")
        self._rsa_net_build_tab()

        self.tab_rsa_attack = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_rsa_attack, text="🔍 ПР7: Атака факторизацією")
        self._rsa_build_attack_tab()

        # 13. Двійкове шифрування файлів (Binary) для всіх алгоритмів
        self.tab_binary = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_binary, text="📁 Шифрування файлів (Binary)")
        self._binary_build_tab()

        # Посилання для зворотної сумісності тестів
        self.tab_text = self.tab_trithemius
        self.tab_bf = self.tab_caesar_bf
        self.tab_attack = self.tab_trithemius_attack
        self.key_entry = self.trithemius_key_entry
        self.txt_input = self.trithemius_txt_input
        self.txt_output = self.trithemius_txt_output
        self.bin_key_entry = self.binary_key_entry
        self.lang_var = self.trithemius_lang_var

    def _get_active_text_widgets(self) -> tuple[tk.Text, tk.Text]:
        """Повертає пару текстових полів (вхід/вихід) поточної активної вкладки."""
        current_tab = self.notebook.select()
        if current_tab == str(self.tab_caesar):
            return self.caesar_txt_input, self.caesar_txt_output
        if current_tab == str(self.tab_poem):
            return self.poem_txt_input, self.poem_txt_output
        if current_tab == str(self.tab_book):
            return self.book_txt_input, self.book_txt_output
        if current_tab == str(self.tab_sym):
            return self.sym_txt_input, self.sym_txt_output
        if current_tab == str(self.tab_rsa):
            return self.rsa_txt_input, self.rsa_txt_output
        if current_tab == str(self.tab_rsa_net):
            return self.rsa_net_txt_input, self.rsa_net_txt_output
        if current_tab == str(self.tab_rsa_attack):
            return self.rsa_attack_txt_input, self.rsa_attack_txt_output
        return self.trithemius_txt_input, self.trithemius_txt_output

    def file_new(self):
        in_txt, out_txt = self._get_active_text_widgets()
        in_txt.delete("1.0", tk.END)
        out_txt.delete("1.0", tk.END)

    def file_open(self):
        in_txt, _ = self._get_active_text_widgets()
        path = filedialog.askopenfilename(
            title="Відкрити текстовий файл",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")],
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                in_txt.delete("1.0", tk.END)
                in_txt.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("Помилка відкриття", f"Не вдалося прочитати файл:\n{e}")

    def file_save(self):
        in_txt, out_txt = self._get_active_text_widgets()
        content = out_txt.get("1.0", tk.END).rstrip("\n")
        if not content:
            content = in_txt.get("1.0", tk.END).rstrip("\n")

        path = filedialog.asksaveasfilename(
            title="Зберегти файл як...",
            defaultextension=".txt",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")],
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Збережено", f"Файл збережено в:\n{path}")
            except Exception as e:
                messagebox.showerror("Помилка збереження", f"Не вдалося записати файл:\n{e}")

    def file_print(self):
        in_txt, out_txt = self._get_active_text_widgets()
        content = out_txt.get("1.0", tk.END).strip() or in_txt.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Друк", "Немає тексту для друку.")
            return

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(content)
            temp_path = f.name

        try:
            os.startfile(temp_path, "print")
        except Exception as e:
            messagebox.showinfo("Друк", f"Файл підготовлено до друку:\n{temp_path}\n({e})")

    def file_exit(self):
        self.destroy()

    def show_about(self):
        messagebox.showinfo(
            "Про розробника",
            "Розробник: ТВ-31 Гогуля Максим\n\n"
            "Дисципліна: Безпека програмного забезпечення\n"
            "Комп'ютерні практикуми:\n"
            "• ПР1: «Шифр Цезаря» (Текстовий шифр, Brute-Force, Binary)\n"
            "• ПР2: «Шифр Тритеміуса» (2D/3D векторні ключі, Гасло, KPA-атака, Binary)\n"
            "• ПР3: «Книжковий шифр» (Віршований шифр, ключова таблиця, шифри Біла та Оттендорфа)\n"
            "• ПР5: «Шифр DES» (криптопровайдери .NET через pythonnet: DES, TripleDES, AES;\n"
            "   режими ECB / CBC / CFB, доповнення, CryptoStream для тексту та файлів)\n"
            "• ПР7: «Шифрування RSA» (числовий приклад, RSACryptoServiceProvider .NET, OAEP / PKCS#1,\n"
            "   діалог формування відкритого ключа, атака факторизацією модуля n)\n\n"
            "Архітектура системи побудована на єдиному модульному класі APP,\n"
            "що автоматично розширюється при додаванні нових практичних робіт.\n",
        )

    def _caesar_build_tab(self):
        """Побудова вкладки текстового шифру Цезаря."""
        toolbar = ttk.Frame(self.tab_caesar)
        toolbar.pack(fill=tk.X, padx=5, pady=4)

        ttk.Button(toolbar, text="📄 Новий", command=self.file_new).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📂 Відкрити", command=self.file_open).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="💾 Зберегти", command=self.file_save).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🖨️ Друк", command=self.file_print).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🔄 Поміняти місцями", command=self._caesar_swap_text).pack(side=tk.LEFT, padx=6)

        params_frame = ttk.LabelFrame(self.tab_caesar, text="Параметри шифру Цезаря (ПР1)", padding=8)
        params_frame.pack(fill=tk.X, padx=5, pady=4)

        ttk.Label(params_frame, text="Мова:").pack(side=tk.LEFT, padx=4)
        self.caesar_lang_var = tk.StringVar(value="auto")
        ttk.Combobox(
            params_frame,
            textvariable=self.caesar_lang_var,
            values=["auto", "uk", "en"],
            state="readonly",
            width=10,
        ).pack(side=tk.LEFT, padx=4)

        ttk.Label(params_frame, text="Ключ (k ціле число):").pack(side=tk.LEFT, padx=6)
        self.caesar_key_entry = ttk.Entry(params_frame, width=8)
        self.caesar_key_entry.insert(0, "3")
        self.caesar_key_entry.pack(side=tk.LEFT, padx=4)

        ttk.Button(params_frame, text="🔒 Зашифрувати", command=lambda: self._caesar_process_text(True)).pack(side=tk.LEFT, padx=8)
        ttk.Button(params_frame, text="🔓 Розшифрувати", command=lambda: self._caesar_process_text(False)).pack(side=tk.LEFT, padx=4)

        content_frame = ttk.Frame(self.tab_caesar)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=4)

        f_left = ttk.LabelFrame(content_frame, text="Вхідний текст", padding=5)
        f_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)
        self.caesar_txt_input = tk.Text(f_left, wrap=tk.WORD, font=("Consolas", 10))
        self.caesar_txt_input.insert("1.0", "Привіт Світ! Hello World! 2026. Гогуля Максим ТВ-31 (Шифр Цезаря)")
        self.caesar_txt_input.pack(fill=tk.BOTH, expand=True)

        f_right = ttk.LabelFrame(content_frame, text="Результат", padding=5)
        f_right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=3)
        self.caesar_txt_output = tk.Text(f_right, wrap=tk.WORD, font=("Consolas", 10))
        self.caesar_txt_output.pack(fill=tk.BOTH, expand=True)

    def _caesar_process_text(self, is_encrypt: bool):
        """Обробка шифрування/розшифрування шифром Цезаря."""
        raw_key = self.caesar_key_entry.get().strip()
        if not self.caesar_cipher.validate_key(raw_key):
            messagebox.showerror("Помилка", "Ключ Цезаря повинен бути цілим числом!")
            return

        text = self.caesar_txt_input.get("1.0", tk.END).rstrip("\n")
        lang = self.caesar_lang_var.get()

        try:
            if is_encrypt:
                res = self.caesar_cipher.encrypt(text, raw_key, lang=lang)
            else:
                res = self.caesar_cipher.decrypt(text, raw_key, lang=lang)

            self.caesar_txt_output.delete("1.0", tk.END)
            self.caesar_txt_output.insert("1.0", res)
        except Exception as e:
            messagebox.showerror("Помилка обробки", str(e))

    def _caesar_swap_text(self):
        in_t = self.caesar_txt_input.get("1.0", tk.END).rstrip("\n")
        out_t = self.caesar_txt_output.get("1.0", tk.END).rstrip("\n")
        self.caesar_txt_input.delete("1.0", tk.END)
        self.caesar_txt_input.insert("1.0", out_t)
        self.caesar_txt_output.delete("1.0", tk.END)
        self.caesar_txt_output.insert("1.0", in_t)

    def _caesar_build_bf_tab(self):
        """Побудова вкладки атаки Brute-Force для шифру Цезаря."""
        f = ttk.Frame(self.tab_caesar_bf, padding=8)
        f.pack(fill=tk.BOTH, expand=True)

        top_bar = ttk.Frame(f)
        top_bar.pack(fill=tk.X, pady=4)

        ttk.Label(top_bar, text="Мова шифротексту:").pack(side=tk.LEFT, padx=4)
        self.caesar_bf_lang_var = tk.StringVar(value="uk")
        ttk.Combobox(
            top_bar,
            textvariable=self.caesar_bf_lang_var,
            values=["uk", "en", "auto"],
            state="readonly",
            width=10,
        ).pack(side=tk.LEFT, padx=4)

        ttk.Button(top_bar, text="💥 Запустити Brute-Force", command=self._caesar_run_brute_force).pack(side=tk.LEFT, padx=10)

        ttk.Label(f, text="Зашифрований текст Цезаря:").pack(anchor=tk.W, pady=2)
        self.caesar_bf_input = tk.Text(f, height=5, wrap=tk.WORD, font=("Consolas", 10))
        self.caesar_bf_input.insert("1.0", "Фхлєле, Фєлўз! 123 (з ґ, є, і, ї)")
        self.caesar_bf_input.pack(fill=tk.X, pady=4)

        ttk.Label(f, text="Результати перебору (ранжовані):").pack(anchor=tk.W, pady=2)

        tree_frame = ttk.Frame(f)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.caesar_tree = ttk.Treeview(
            tree_frame,
            columns=("key", "score", "text"),
            show="headings",
            selectmode="browse",
        )
        self.caesar_tree.heading("key", text="Ключ (k)")
        self.caesar_tree.heading("score", text="Оцінка (Score)")
        self.caesar_tree.heading("text", text="Розшифрований текст")

        self.caesar_tree.column("key", width=70, anchor=tk.CENTER)
        self.caesar_tree.column("score", width=90, anchor=tk.CENTER)
        self.caesar_tree.column("text", width=600, anchor=tk.W)

        scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.caesar_tree.yview)
        self.caesar_tree.configure(yscrollcommand=scroll.set)

        self.caesar_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _caesar_run_brute_force(self):
        text = self.caesar_bf_input.get("1.0", tk.END).rstrip("\n")
        if not text.strip():
            messagebox.showwarning("Увага", "Введіть шифротекст для зламу.")
            return

        lang = self.caesar_bf_lang_var.get()
        for row in self.caesar_tree.get_children():
            self.caesar_tree.delete(row)

        try:
            results = self.caesar_brute_force.attack(text, lang=lang)
            for key, dec_text, score in results:
                self.caesar_tree.insert("", tk.END, values=(key, f"{score:.3f}", dec_text))
            if results:
                messagebox.showinfo(
                    "Готово",
                    f"Перебір завершено! Знайдено варіантів: {len(results)}.\nНайбільш імовірний ключ: k = {results[0][0]}",
                )
        except Exception as e:
            messagebox.showerror("Помилка Brute-Force", str(e))

    def _trithemius_build_tab(self):
        """Побудова вкладки текстового шифру Тритеміуса (ПР2)."""
        toolbar = ttk.Frame(self.tab_trithemius)
        toolbar.pack(fill=tk.X, padx=5, pady=4)

        ttk.Button(toolbar, text="📄 Новий", command=self.file_new).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📂 Відкрити", command=self.file_open).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="💾 Зберегти", command=self.file_save).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🖨️ Друк", command=self.file_print).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🔄 Поміняти місцями", command=self._trithemius_swap_text).pack(side=tk.LEFT, padx=6)

        params_box = ttk.LabelFrame(self.tab_trithemius, text="Параметри закону зміщення шифру Тритеміуса (ПР2)", padding=8)
        params_box.pack(fill=tk.X, padx=5, pady=4)

        row1 = ttk.Frame(params_box)
        row1.pack(fill=tk.X, pady=2)

        ttk.Label(row1, text="Мова:").pack(side=tk.LEFT, padx=4)
        self.trithemius_lang_var = tk.StringVar(value="auto")
        ttk.Combobox(
            row1,
            textvariable=self.trithemius_lang_var,
            values=["auto", "uk", "en"],
            state="readonly",
            width=10,
        ).pack(side=tk.LEFT, padx=4)

        ttk.Label(row1, text="Ключ:").pack(side=tk.LEFT, padx=8)
        self.trithemius_key_entry = ttk.Entry(row1, width=20)
        self.trithemius_key_entry.insert(0, "2, 3")
        self.trithemius_key_entry.pack(side=tk.LEFT, padx=4)

        # Швидкі кнопки підстановки шаблону ключа
        ttk.Button(row1, text="Лінійний (2, 3)", command=lambda: self._trithemius_set_key("2, 3")).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="3D (1, 2, 5)", command=lambda: self._trithemius_set_key("1, 2, 5")).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="Гасло", command=lambda: self._trithemius_set_key("БЕЗПЕКА")).pack(side=tk.LEFT, padx=2)

        ttk.Button(row1, text="🔒 Зашифрувати", command=lambda: self._trithemius_process_text(True)).pack(side=tk.LEFT, padx=10)
        ttk.Button(row1, text="🔓 Розшифрувати", command=lambda: self._trithemius_process_text(False)).pack(side=tk.LEFT, padx=2)

        ttk.Label(
            params_box,
            text="Формати ключа: 2D вектор (A, B) → k = Ap + B | 3D вектор (A, B, C) → k = Ap² + Bp + C | Текстове гасло",
            font=("Arial", 8, "italic"),
        ).pack(anchor=tk.W, pady=2)

        content_frame = ttk.Frame(self.tab_trithemius)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=4)

        f_left = ttk.LabelFrame(content_frame, text="Вхідний текст", padding=5)
        f_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)
        self.trithemius_txt_input = tk.Text(f_left, wrap=tk.WORD, font=("Consolas", 10))
        self.trithemius_txt_input.insert(
            "1.0",
            "Шифр Тритеміуса — вдосконалений шифр Цезаря зі змінним кроком зміщення.\n"
            "ТВ-31 Гогуля Максим, КПІ 2026.",
        )
        self.trithemius_txt_input.pack(fill=tk.BOTH, expand=True)

        f_right = ttk.LabelFrame(content_frame, text="Результат Тритеміуса", padding=5)
        f_right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=3)
        self.trithemius_txt_output = tk.Text(f_right, wrap=tk.WORD, font=("Consolas", 10))
        self.trithemius_txt_output.pack(fill=tk.BOTH, expand=True)

    def _trithemius_set_key(self, key_text: str):
        self.trithemius_key_entry.delete(0, tk.END)
        self.trithemius_key_entry.insert(0, key_text)

    def _trithemius_process_text(self, is_encrypt: bool):
        """Шифрування/розшифрування Тритеміусом."""
        raw_key = self.trithemius_key_entry.get().strip()
        if not self.trithemius_cipher.validate_key(raw_key):
            messagebox.showerror(
                "Помилка ключа",
                "Невалідний ключ Тритеміуса!\n\n"
                "Допустимі варіанти:\n"
                "• 2-вимірний вектор (A, B): наприклад '2, 3'\n"
                "• 3-вимірний вектор (A, B, C): наприклад '1, 2, 5'\n"
                "• Текстове гасло: наприклад 'СЕКРЕТ'",
            )
            return

        text = self.trithemius_txt_input.get("1.0", tk.END).rstrip("\n")
        lang = self.trithemius_lang_var.get()

        try:
            if is_encrypt:
                res = self.trithemius_cipher.encrypt(text, raw_key, lang=lang)
            else:
                res = self.trithemius_cipher.decrypt(text, raw_key, lang=lang)

            self.trithemius_txt_output.delete("1.0", tk.END)
            self.trithemius_txt_output.insert("1.0", res)
        except Exception as e:
            messagebox.showerror("Помилка обробки", str(e))

    def _trithemius_swap_text(self):
        in_t = self.trithemius_txt_input.get("1.0", tk.END).rstrip("\n")
        out_t = self.trithemius_txt_output.get("1.0", tk.END).rstrip("\n")
        self.trithemius_txt_input.delete("1.0", tk.END)
        self.trithemius_txt_input.insert("1.0", out_t)
        self.trithemius_txt_output.delete("1.0", tk.END)
        self.trithemius_txt_output.insert("1.0", in_t)

    def _trithemius_build_attack_tab(self):
        """Побудова вкладки активної атаки на шифр Тритеміуса (KPA)."""
        f = ttk.Frame(self.tab_trithemius_attack, padding=8)
        f.pack(fill=tk.BOTH, expand=True)

        info_box = ttk.LabelFrame(f, text="Активна атака на шифр Тритеміуса (Known-Plaintext Attack)", padding=6)
        info_box.pack(fill=tk.X, pady=2)
        ttk.Label(
            info_box,
            text="Знаходження ключа за перехопленою парою «незашифроване (P) — зашифроване (C)».\n"
                 "Знаходить коефіцієнти лінійного закону (A, B), квадратичного (A, B, C) або текстове гасло.",
            font=("Arial", 9),
        ).pack(anchor=tk.W)

        top_ctrl = ttk.Frame(f)
        top_ctrl.pack(fill=tk.X, pady=6)

        ttk.Label(top_ctrl, text="Мова аналізу:").pack(side=tk.LEFT, padx=4)
        self.trithemius_attack_lang_var = tk.StringVar(value="auto")
        ttk.Combobox(
            top_ctrl,
            textvariable=self.trithemius_attack_lang_var,
            values=["auto", "uk", "en"],
            state="readonly",
            width=10,
        ).pack(side=tk.LEFT, padx=4)

        ttk.Button(top_ctrl, text="🚀 Знайти ключ (Провести атаку)", command=self._trithemius_run_attack).pack(side=tk.LEFT, padx=8)
        ttk.Button(top_ctrl, text="📥 Завантажити приклад", command=self._trithemius_load_attack_example).pack(side=tk.LEFT, padx=4)
        ttk.Button(top_ctrl, text="📋 Застосувати ключ до шифратора", command=self._trithemius_apply_attack_key).pack(side=tk.LEFT, padx=8)

        texts_box = ttk.Frame(f)
        texts_box.pack(fill=tk.BOTH, expand=True, pady=4)

        p_frame = ttk.LabelFrame(texts_box, text="Відкритий текст (P - незашифроване)", padding=4)
        p_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2)
        self.trithemius_attack_plain = tk.Text(p_frame, height=8, wrap=tk.WORD, font=("Consolas", 10))
        self.trithemius_attack_plain.insert("1.0", "Шифр Тритеміуса є важливим кроком розвитку криптографії")
        self.trithemius_attack_plain.pack(fill=tk.BOTH, expand=True)

        c_frame = ttk.LabelFrame(texts_box, text="Шифротекст (C - зашифроване)", padding=4)
        c_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=2)
        self.trithemius_attack_cipher = tk.Text(c_frame, height=8, wrap=tk.WORD, font=("Consolas", 10))
        init_enc = self.trithemius_cipher.encrypt("Шифр Тритеміуса є важливим кроком розвитку криптографії", (3, 7), lang="uk")
        self.trithemius_attack_cipher.insert("1.0", init_enc)
        self.trithemius_attack_cipher.pack(fill=tk.BOTH, expand=True)

        res_frame = ttk.LabelFrame(f, text="Результати атаки", padding=6)
        res_frame.pack(fill=tk.X, pady=4)

        self.trithemius_lbl_attack_result = ttk.Label(
            res_frame,
            text="Натисніть 'Знайти ключ' для виконання атаки.",
            font=("Arial", 9, "bold"),
            foreground="darkblue",
        )
        self.trithemius_lbl_attack_result.pack(anchor=tk.W, pady=2)

        self.trithemius_txt_attack_details = tk.Text(res_frame, height=4, wrap=tk.WORD, font=("Consolas", 9), state=tk.DISABLED)
        self.trithemius_txt_attack_details.pack(fill=tk.X, pady=2)

    def _trithemius_load_attack_example(self):
        plain = "Шифр Тритеміуса є важливим кроком розвитку криптографії"
        key = (3, 7)
        ciph = self.trithemius_cipher.encrypt(plain, key, lang="uk")

        self.trithemius_attack_plain.delete("1.0", tk.END)
        self.trithemius_attack_plain.insert("1.0", plain)
        self.trithemius_attack_cipher.delete("1.0", tk.END)
        self.trithemius_attack_cipher.insert("1.0", ciph)
        messagebox.showinfo("Приклад завантажено", "Завантажено приклад з лінійним ключем (3, 7).")

    def _trithemius_run_attack(self):
        plain = self.trithemius_attack_plain.get("1.0", tk.END).rstrip("\n")
        ciph = self.trithemius_attack_cipher.get("1.0", tk.END).rstrip("\n")

        if not plain.strip() or not ciph.strip():
            messagebox.showwarning("Увага", "Введіть відкритий та зашифрований текст.")
            return

        lang = self.trithemius_attack_lang_var.get()
        try:
            res = self.trithemius_attack.attack(plain, ciph, lang=lang)
            self._trithemius_last_attack_result = res

            self.trithemius_txt_attack_details.config(state=tk.NORMAL)
            self.trithemius_txt_attack_details.delete("1.0", tk.END)

            if res.success and res.primary_candidate:
                primary = res.primary_candidate
                self.trithemius_lbl_attack_result.config(
                    text=f"✅ Успіх! Відновлено ключ: {primary.key.formula_display()} (Впевненість: {primary.confidence * 100:.0f}%)",
                    foreground="green",
                )
                details = f"{res.explanation}\nГіпотези:\n"
                for cand in res.all_candidates:
                    details += f" • [{cand.key_type.value}] {cand.description} | верифіковано: {cand.verified}\n"
                self.trithemius_txt_attack_details.insert("1.0", details)
                messagebox.showinfo("Атаку завершено", f"Ключ успішно знайдено:\n{primary.key.formula_display()}")
            else:
                self.trithemius_lbl_attack_result.config(text="❌ Ключ не знайдено.", foreground="red")
                self.trithemius_txt_attack_details.insert("1.0", res.explanation)
            self.trithemius_txt_attack_details.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Помилка атаки", str(e))

    def _trithemius_apply_attack_key(self):
        if not self._trithemius_last_attack_result or not self._trithemius_last_attack_result.primary_candidate:
            messagebox.showwarning("Увага", "Спочатку проведіть атаку для знаходження ключа.")
            return

        cand = self._trithemius_last_attack_result.primary_candidate
        key = cand.key
        key_str = ""
        if key.key_type == KeyType.LINEAR:
            a, b = key.linear_coeffs  # type: ignore
            key_str = f"{a}, {b}"
        elif key.key_type == KeyType.NON_LINEAR:
            a, b, c = key.nonlinear_coeffs  # type: ignore
            key_str = f"{a}, {b}, {c}"
        elif key.key_type == KeyType.MOTTO:
            key_str = key.motto or ""

        self.trithemius_key_entry.delete(0, tk.END)
        self.trithemius_key_entry.insert(0, key_str)
        self.notebook.select(self.tab_trithemius)
        messagebox.showinfo("Ключ перенесено", f"Ключ '{key_str}' встановлено у шифратор Тритеміуса!")

    def _binary_build_tab(self):
        """Побудова вкладки двійкового шифрування файлів (Цезар / Тритеміус mod 256)."""
        f = ttk.Frame(self.tab_binary, padding=12)
        f.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            f,
            text="Шифрування двійкових файлів будь-якого формату (зображення, PDF, архіви тощо).\n"
                 "Операції виконуються в кільці лишків mod 256.",
            font=("Arial", 10),
        ).pack(anchor=tk.W, pady=6)

        btn_box = ttk.Frame(f)
        btn_box.pack(fill=tk.X, pady=8)
        ttk.Button(btn_box, text="📂 Обрати файл...", command=self._binary_choose_file).pack(side=tk.LEFT, padx=4)
        self.lbl_binary_file = ttk.Label(btn_box, text="Файл не обрано", foreground="gray")
        self.lbl_binary_file.pack(side=tk.LEFT, padx=8)

        key_box = ttk.LabelFrame(f, text="Параметри алгоритму та ключа", padding=8)
        key_box.pack(fill=tk.X, pady=8)

        row_algo = ttk.Frame(key_box)
        row_algo.pack(fill=tk.X, pady=2)
        ttk.Label(row_algo, text="Алгоритм:").pack(side=tk.LEFT, padx=4)
        self.binary_algo_var = tk.StringVar(value="trithemius")
        ttk.Radiobutton(row_algo, text="Шифр Тритеміуса (ПР2)", variable=self.binary_algo_var, value="trithemius").pack(side=tk.LEFT, padx=6)
        ttk.Radiobutton(row_algo, text="Шифр Цезаря (ПР1)", variable=self.binary_algo_var, value="caesar").pack(side=tk.LEFT, padx=6)

        row_key = ttk.Frame(key_box)
        row_key.pack(fill=tk.X, pady=4)
        ttk.Label(row_key, text="Ключ:").pack(side=tk.LEFT, padx=4)
        self.binary_key_entry = ttk.Entry(row_key, width=24)
        self.binary_key_entry.insert(0, "2, 3")
        self.binary_key_entry.pack(side=tk.LEFT, padx=4)
        ttk.Label(row_key, text="(Для Тритеміуса: 'A, B' або 'A, B, C' або Гасло; Для Цезаря: число)", font=("Arial", 8, "italic")).pack(side=tk.LEFT, padx=6)

        act_box = ttk.Frame(f)
        act_box.pack(fill=tk.X, pady=12)
        ttk.Button(act_box, text="🔒 Зашифрувати файл", command=lambda: self._binary_process(True)).pack(side=tk.LEFT, padx=6)
        ttk.Button(act_box, text="🔓 Розшифрувати файл", command=lambda: self._binary_process(False)).pack(side=tk.LEFT, padx=6)

    def _binary_choose_file(self):
        file_path = filedialog.askopenfilename(title="Оберіть файл для обробки")
        if file_path:
            self.selected_bin_path = file_path
            size = os.path.getsize(file_path)
            self.lbl_binary_file.config(text=f"{os.path.basename(file_path)} ({size} байт)", foreground="black")

    def _binary_process(self, is_encrypt: bool):
        if not self.selected_bin_path:
            messagebox.showwarning("Увага", "Будь ласка, спочатку оберіть файл.")
            return

        algo = self.binary_algo_var.get()
        raw_key = self.binary_key_entry.get().strip()

        cipher_obj = self.trithemius_binary_cipher if algo == "trithemius" else self.caesar_binary_cipher
        if not cipher_obj.validate_key(raw_key):
            messagebox.showerror("Помилка", f"Невалідний ключ для обраного двійкового шифру ({algo}): {raw_key}")
            return

        prefix = "enc_" if is_encrypt else "dec_"
        save_path = filedialog.asksaveasfilename(
            title="Зберегти оброблений файл як...",
            initialfile=prefix + os.path.basename(self.selected_bin_path),
        )
        if not save_path:
            return

        try:
            with open(self.selected_bin_path, "rb") as fin:
                data = fin.read()

            if is_encrypt:
                res_data = cipher_obj.encrypt(data, raw_key)
            else:
                res_data = cipher_obj.decrypt(data, raw_key)

            with open(save_path, "wb") as fout:
                fout.write(res_data)

            messagebox.showinfo("Успіх", f"Файл успішно збережено в:\n{save_path}\nРозмір: {len(res_data)} байт.")
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося обробити файл:\n{e}")

    @staticmethod
    def _set_text(widget: tk.Text, value: str):
        widget.delete("1.0", tk.END)
        widget.insert("1.0", value)

    @staticmethod
    def _get_text(widget: tk.Text) -> str:
        return widget.get("1.0", tk.END).rstrip("\n")

    def _poem_build_tab(self):
        toolbar = ttk.Frame(self.tab_poem)
        toolbar.pack(fill=tk.X, padx=5, pady=4)

        ttk.Button(toolbar, text="📄 Новий", command=self.file_new).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📂 Відкрити", command=self.file_open).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="💾 Зберегти", command=self.file_save).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🖨️ Друк", command=self.file_print).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🔄 Поміняти місцями", command=self._poem_swap_text).pack(side=tk.LEFT, padx=6)

        params_box = ttk.LabelFrame(self.tab_poem, text="Параметри віршованого шифру (ПР3)", padding=8)
        params_box.pack(fill=tk.X, padx=5, pady=4)

        row1 = ttk.Frame(params_box)
        row1.pack(fill=tk.X, pady=2)

        ttk.Label(row1, text="Вірш-ключ:").pack(side=tk.LEFT, padx=4)
        self.poem_preset_var = tk.StringVar(value=next(iter(POEM_PRESETS)))
        preset_box = ttk.Combobox(
            row1,
            textvariable=self.poem_preset_var,
            values=list(POEM_PRESETS),
            state="readonly",
            width=40,
        )
        preset_box.pack(side=tk.LEFT, padx=4)
        preset_box.bind("<<ComboboxSelected>>", lambda _e: self._poem_load_preset())

        ttk.Label(row1, text="Рядків:").pack(side=tk.LEFT, padx=6)
        self.poem_rows_var = tk.StringVar(value="10")
        ttk.Spinbox(row1, from_=1, to=PoemKey.MAX_DIM, textvariable=self.poem_rows_var, width=4).pack(side=tk.LEFT)
        ttk.Label(row1, text="Стовпців:").pack(side=tk.LEFT, padx=6)
        self.poem_cols_var = tk.StringVar(value="10")
        ttk.Spinbox(row1, from_=1, to=PoemKey.MAX_DIM, textvariable=self.poem_cols_var, width=4).pack(side=tk.LEFT)

        ttk.Button(row1, text="🔒 Зашифрувати", command=lambda: self._poem_process_text(True)).pack(side=tk.LEFT, padx=10)
        ttk.Button(row1, text="🔓 Розшифрувати", command=lambda: self._poem_process_text(False)).pack(side=tk.LEFT, padx=2)

        row2 = ttk.Frame(params_box)
        row2.pack(fill=tk.X, pady=2)
        self.poem_substitute_var = tk.BooleanVar(value=True)
        self.poem_keep_spaces_var = tk.BooleanVar(value=True)
        self.poem_strict_var = tk.BooleanVar(value=False)
        self.poem_avoid_repeats_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="Заміна відсутніх літер (Щ→Ш, Ґ→Г …)", variable=self.poem_substitute_var).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(row2, text="Кодувати пробіли (00/00)", variable=self.poem_keep_spaces_var).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(row2, text="Не повторювати координати", variable=self.poem_avoid_repeats_var).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(row2, text="Строгий режим (без втрат)", variable=self.poem_strict_var).pack(side=tk.LEFT, padx=4)

        ttk.Label(
            params_box,
            text="Кожна літера → код РР/СС (рядок/стовпчик) випадково обраного входження цієї літери у вірші; коди розділяються комами.",
            font=("Arial", 8, "italic"),
        ).pack(anchor=tk.W, pady=2)

        content_frame = ttk.Frame(self.tab_poem)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=4)

        f_key = ttk.LabelFrame(content_frame, text="Вірш-ключ (рядок вірша = рядок таблиці)", padding=5)
        f_key.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)
        self.poem_txt_key = tk.Text(f_key, wrap=tk.NONE, width=34, font=("Consolas", 10))
        self.poem_txt_key.pack(fill=tk.BOTH, expand=True)

        f_left = ttk.LabelFrame(content_frame, text="Вхідний текст", padding=5)
        f_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)
        self.poem_txt_input = tk.Text(f_left, wrap=tk.WORD, width=34, font=("Consolas", 10))
        self.poem_txt_input.insert("1.0", "Сообщите товарищу")
        self.poem_txt_input.pack(fill=tk.BOTH, expand=True)

        f_right = ttk.LabelFrame(content_frame, text="Результат", padding=5)
        f_right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)
        self.poem_txt_output = tk.Text(f_right, wrap=tk.WORD, width=34, font=("Consolas", 10))
        self.poem_txt_output.pack(fill=tk.BOTH, expand=True)

        self.poem_lbl_status = ttk.Label(self.tab_poem, text="", font=("Arial", 9, "bold"), foreground="darkblue")
        self.poem_lbl_status.pack(anchor=tk.W, padx=8, pady=(0, 6))

        self._poem_load_preset()

    def _poem_load_preset(self):
        self._set_text(self.poem_txt_key, POEM_PRESETS[self.poem_preset_var.get()])

    def _poem_get_key(self) -> Optional[PoemKey]:
        """Ключ з полів вкладки; при помилці показує повідомлення і повертає None."""
        try:
            rows = int(self.poem_rows_var.get())
            cols = int(self.poem_cols_var.get())
        except ValueError:
            messagebox.showerror("Помилка ключа", "Розміри таблиці повинні бути цілими числами 1..99.")
            return None
        try:
            return PoemKey(self._get_text(self.poem_txt_key), rows, cols)
        except (TypeError, ValueError) as e:
            messagebox.showerror("Помилка ключа", str(e))
            return None

    def _poem_process_text(self, is_encrypt: bool):
        key = self._poem_get_key()
        if key is None:
            return
        text = self._get_text(self.poem_txt_input)

        try:
            if is_encrypt:
                options = dict(
                    substitute=self.poem_substitute_var.get(),
                    keep_spaces=self.poem_keep_spaces_var.get(),
                )
                report = self.poem_cipher.analyze(text, key, **options)
                res = self.poem_cipher.encrypt(
                    text,
                    key,
                    strict=self.poem_strict_var.get(),
                    avoid_repeats=self.poem_avoid_repeats_var.get(),
                    **options,
                )
                status = ("" if report.lossless else "Увага! ") + report.summary()
            else:
                res = self.poem_cipher.decrypt(text, key)
                status = f"Розшифровано символів: {len(res)}"
            self._set_text(self.poem_txt_output, res)
            self.poem_lbl_status.config(text=status, foreground="darkorange" if status.startswith("Увага!") else "darkblue")
        except Exception as e:
            self.poem_lbl_status.config(text=f"{e}", foreground="red")
            messagebox.showerror("Помилка обробки", str(e))

    def _poem_swap_text(self):
        in_t = self._get_text(self.poem_txt_input)
        self._set_text(self.poem_txt_input, self._get_text(self.poem_txt_output))
        self._set_text(self.poem_txt_output, in_t)

    def _poem_build_table_tab(self):
        f = ttk.Frame(self.tab_poem_table, padding=8)
        f.pack(fill=tk.BOTH, expand=True)

        top_bar = ttk.Frame(f)
        top_bar.pack(fill=tk.X, pady=4)
        ttk.Button(top_bar, text="🔄 Побудувати таблицю з вірша (вкладка ПР3)", command=self._poem_refresh_table).pack(side=tk.LEFT, padx=4)
        ttk.Label(top_bar, text="Літера:").pack(side=tk.LEFT, padx=(16, 4))
        self.poem_find_entry = ttk.Entry(top_bar, width=4)
        self.poem_find_entry.insert(0, "О")
        self.poem_find_entry.pack(side=tk.LEFT)
        ttk.Button(top_bar, text="🔍 Координати літери", command=self._poem_find_letter).pack(side=tk.LEFT, padx=4)

        self.poem_lbl_find = ttk.Label(f, text="", font=("Consolas", 9), foreground="darkblue", wraplength=1100)
        self.poem_lbl_find.pack(anchor=tk.W, pady=2)

        body = ttk.Frame(f)
        body.pack(fill=tk.BOTH, expand=True)

        grid_box = ttk.LabelFrame(body, text="Ключова сторінка: рядки (РР) × стовпчики (СС)", padding=4)
        grid_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2)
        self.poem_grid_tree = ttk.Treeview(grid_box, show="headings", selectmode="none")
        grid_scroll_x = ttk.Scrollbar(grid_box, orient=tk.HORIZONTAL, command=self.poem_grid_tree.xview)
        self.poem_grid_tree.configure(xscrollcommand=grid_scroll_x.set)
        grid_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.poem_grid_tree.pack(fill=tk.BOTH, expand=True)

        freq_box = ttk.LabelFrame(body, text="Частоти літер у ключі", padding=4)
        freq_box.pack(side=tk.RIGHT, fill=tk.Y, padx=2)
        self.poem_freq_tree = ttk.Treeview(freq_box, columns=("letter", "count", "share"), show="headings", height=18)
        self.poem_freq_tree.heading("letter", text="Літера")
        self.poem_freq_tree.heading("count", text="Входжень")
        self.poem_freq_tree.heading("share", text="Частка")
        for col, width in (("letter", 60), ("count", 75), ("share", 70)):
            self.poem_freq_tree.column(col, width=width, anchor=tk.CENTER)
        freq_scroll = ttk.Scrollbar(freq_box, orient=tk.VERTICAL, command=self.poem_freq_tree.yview)
        self.poem_freq_tree.configure(yscrollcommand=freq_scroll.set)
        self.poem_freq_tree.pack(side=tk.LEFT, fill=tk.Y)
        freq_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.poem_lbl_missing = ttk.Label(f, text="", font=("Arial", 9), foreground="darkred", wraplength=1100)
        self.poem_lbl_missing.pack(anchor=tk.W, pady=4)

        self._poem_refresh_table(silent=True)

    def _poem_refresh_table(self, silent: bool = False):
        key = self._poem_get_key()
        if key is None:
            return

        tree = self.poem_grid_tree
        tree.delete(*tree.get_children())
        columns = ["row"] + [f"{c:02d}" for c in range(1, key.cols + 1)]
        tree["columns"] = columns
        tree.heading("row", text="РР \\ СС")
        tree.column("row", width=60, anchor=tk.CENTER, stretch=False)
        for col in columns[1:]:
            tree.heading(col, text=col)
            tree.column(col, width=34, anchor=tk.CENTER, stretch=False)
        tree.configure(height=min(key.rows, 20))
        for r, row in enumerate(key.grid, start=1):
            tree.insert("", tk.END, values=[f"{r:02d}"] + row)

        self.poem_freq_tree.delete(*self.poem_freq_tree.get_children())
        counts = key.letter_counts()
        total = sum(counts.values())
        for ch, cnt in counts.items():
            self.poem_freq_tree.insert("", tk.END, values=(ch, cnt, f"{cnt / total:.1%}"))

        self.poem_lbl_missing.config(
            text=f"Заповнено клітинок: {total} з {key.rows * key.cols}.   "
                 f"Відсутні літери (укр.): {' '.join(key.missing_letters(UK_ALPHABET)) or '—'}   |   "
                 f"(рос.): {' '.join(key.missing_letters(RU_ALPHABET)) or '—'}"
        )
        self._poem_find_letter()
        if not silent:
            self.notebook.select(self.tab_poem_table)

    def _poem_find_letter(self):
        key = self._poem_get_key()
        raw = self.poem_find_entry.get().strip()
        if key is None or not raw:
            return
        ch = raw[0].upper()
        coords = key.positions(ch)
        if coords:
            codes = ", ".join(self.poem_cipher.format_coord(c) for c in coords)
            self.poem_lbl_find.config(text=f"«{ch}» — {len(coords)} входжень: {codes}", foreground="darkblue")
        else:
            self.poem_lbl_find.config(text=f"«{ch}» відсутня в ключовій таблиці.", foreground="red")

    BOOK_DESCRIPTIONS = {
        "beale": "Шифр Біла: літера → номер слова тексту-книги, яке починається з цієї літери (0 — пробіл). "
                 "Слова нумеруються з 1 підряд по всьому тексту.",
        "ottendorf": "Шифр Оттендорфа: літера → «рядок-слово-літера» у тексті-книзі (0-0-0 — пробіл). "
                     "Рядки без слів не нумеруються.",
    }

    def _book_build_tab(self):
        toolbar = ttk.Frame(self.tab_book)
        toolbar.pack(fill=tk.X, padx=5, pady=4)

        ttk.Button(toolbar, text="📄 Новий", command=self.file_new).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📂 Відкрити", command=self.file_open).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="💾 Зберегти", command=self.file_save).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🖨️ Друк", command=self.file_print).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🔄 Поміняти місцями", command=self._book_swap_text).pack(side=tk.LEFT, padx=6)
        ttk.Button(toolbar, text="📂 Відкрити книгу-ключ...", command=self._book_open_key).pack(side=tk.LEFT, padx=6)

        params_box = ttk.LabelFrame(self.tab_book, text="Різновиди книжкового шифру (додаткове завдання ПР3)", padding=8)
        params_box.pack(fill=tk.X, padx=5, pady=4)

        row1 = ttk.Frame(params_box)
        row1.pack(fill=tk.X, pady=2)
        ttk.Label(row1, text="Шифр:").pack(side=tk.LEFT, padx=4)
        self.book_algo_var = tk.StringVar(value="beale")
        ttk.Radiobutton(row1, text="Шифр Біла (номер слова)", variable=self.book_algo_var, value="beale",
                        command=self._book_update_description).pack(side=tk.LEFT, padx=6)
        ttk.Radiobutton(row1, text="Шифр Оттендорфа (рядок-слово-літера)", variable=self.book_algo_var, value="ottendorf",
                        command=self._book_update_description).pack(side=tk.LEFT, padx=6)

        ttk.Button(row1, text="🔒 Зашифрувати", command=lambda: self._book_process_text(True)).pack(side=tk.LEFT, padx=10)
        ttk.Button(row1, text="🔓 Розшифрувати", command=lambda: self._book_process_text(False)).pack(side=tk.LEFT, padx=2)

        row2 = ttk.Frame(params_box)
        row2.pack(fill=tk.X, pady=2)
        self.book_substitute_var = tk.BooleanVar(value=True)
        self.book_keep_spaces_var = tk.BooleanVar(value=True)
        self.book_strict_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="Заміна відсутніх літер", variable=self.book_substitute_var).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(row2, text="Кодувати пробіли", variable=self.book_keep_spaces_var).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(row2, text="Строгий режим (без втрат)", variable=self.book_strict_var).pack(side=tk.LEFT, padx=4)

        self.book_lbl_description = ttk.Label(params_box, text="", font=("Arial", 8, "italic"))
        self.book_lbl_description.pack(anchor=tk.W, pady=2)

        content_frame = ttk.Frame(self.tab_book)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=4)

        f_key = ttk.LabelFrame(content_frame, text="Текст-книга (ключ)", padding=5)
        f_key.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)
        self.book_txt_key = tk.Text(f_key, wrap=tk.WORD, width=40, font=("Consolas", 9))
        self.book_txt_key.insert("1.0", BOOK_SAMPLE)
        self.book_txt_key.pack(fill=tk.BOTH, expand=True)

        f_left = ttk.LabelFrame(content_frame, text="Вхідний текст", padding=5)
        f_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)
        self.book_txt_input = tk.Text(f_left, wrap=tk.WORD, width=30, font=("Consolas", 10))
        self.book_txt_input.insert("1.0", "Безпека інформаційних систем")
        self.book_txt_input.pack(fill=tk.BOTH, expand=True)

        f_right = ttk.LabelFrame(content_frame, text="Результат", padding=5)
        f_right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)
        self.book_txt_output = tk.Text(f_right, wrap=tk.WORD, width=30, font=("Consolas", 10))
        self.book_txt_output.pack(fill=tk.BOTH, expand=True)

        self.book_lbl_status = ttk.Label(self.tab_book, text="", font=("Arial", 9, "bold"), foreground="darkblue")
        self.book_lbl_status.pack(anchor=tk.W, padx=8, pady=(0, 6))

        self._book_update_description()

    def _book_update_description(self):
        self.book_lbl_description.config(text=self.BOOK_DESCRIPTIONS[self.book_algo_var.get()])

    def _book_open_key(self):
        path = filedialog.askopenfilename(
            title="Відкрити текст-книгу (ключ)",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")],
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self._set_text(self.book_txt_key, f.read())
            except Exception as e:
                messagebox.showerror("Помилка відкриття", f"Не вдалося прочитати файл:\n{e}")

    def _book_process_text(self, is_encrypt: bool):
        cipher_obj = self.book_ciphers[self.book_algo_var.get()]
        try:
            key = cipher_obj.build_key(self._get_text(self.book_txt_key))
        except (TypeError, ValueError) as e:
            messagebox.showerror("Помилка ключа", str(e))
            return
        text = self._get_text(self.book_txt_input)

        try:
            if is_encrypt:
                options = dict(substitute=self.book_substitute_var.get(), keep_spaces=self.book_keep_spaces_var.get())
                report = cipher_obj.analyze(text, key, **options)
                res = cipher_obj.encrypt(text, key, strict=self.book_strict_var.get(), **options)
                status = ("" if report.lossless else "Увага! ") + report.summary()
            else:
                res = cipher_obj.decrypt(text, key)
                status = f"Розшифровано символів: {len(res)}"
            self._set_text(self.book_txt_output, res)
            self.book_lbl_status.config(text=status, foreground="darkorange" if status.startswith("Увага!") else "darkblue")
        except Exception as e:
            self.book_lbl_status.config(text=f"{e}", foreground="red")
            messagebox.showerror("Помилка обробки", str(e))

    def _book_swap_text(self):
        in_t = self._get_text(self.book_txt_input)
        self._set_text(self.book_txt_input, self._get_text(self.book_txt_output))
        self._set_text(self.book_txt_output, in_t)

    SYM_DEFAULT_KEYS = {"DES": "ABCDEFGH", "TripleDES": "ABCDEFGHIJKLMNOP", "AES": "ABCDEFGHIJKLMNOP"}

    def _sym_build_params(self, parent: ttk.Frame, title: str) -> dict:
        ctl: dict = {}
        box = ttk.LabelFrame(parent, text=title, padding=8)
        box.pack(fill=tk.X, padx=5, pady=4)

        row1 = ttk.Frame(box)
        row1.pack(fill=tk.X, pady=2)
        for label, name, values, default, width in (
            ("Шифр:", "algo", list(CIPHERS), "DES", 11),
            ("Режим:", "mode", list(MODES), "CBC", 6),
            ("Доповнення:", "padding", list(PADDINGS), "PKCS7", 10),
        ):
            ttk.Label(row1, text=label).pack(side=tk.LEFT, padx=(8, 4))
            ctl[name] = tk.StringVar(value=default)
            combo = ttk.Combobox(row1, textvariable=ctl[name], values=values, state="readonly", width=width)
            combo.pack(side=tk.LEFT, padx=2)
            combo.bind("<<ComboboxSelected>>", lambda _e, c=ctl, n=name: self._sym_on_change(c, n))
        ctl["row1"] = row1

        for name, label, gen_text in (("key", "Ключ:", "🔑 Новий ключ"), ("iv", "IV:", "🔑 Новий IV")):
            row = ttk.Frame(box)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=label, width=6).pack(side=tk.LEFT, padx=(8, 4))
            ctl[name] = ttk.Entry(row, width=72, font=("Consolas", 10))
            ctl[name].pack(side=tk.LEFT, padx=2)
            ctl[f"{name}_fmt"] = tk.StringVar(value="ASCII")
            ctl[f"{name}_fmt_box"] = ttk.Combobox(row, textvariable=ctl[f"{name}_fmt"], values=list(KEY_FORMATS),
                                                 state="readonly", width=7)
            ctl[f"{name}_fmt_box"].pack(side=tk.LEFT, padx=4)
            ctl[f"{name}_gen"] = ttk.Button(row, text=gen_text, command=lambda c=ctl, n=name: self._sym_generate(c, n))
            ctl[f"{name}_gen"].pack(side=tk.LEFT, padx=4)
            ctl[f"{name}_row"] = row

        ctl["embed"] = tk.BooleanVar(value=False)
        ctl["embed_box"] = ttk.Checkbutton(ctl["iv_row"], text="IV на початку шифротексту", variable=ctl["embed"])
        ctl["embed_box"].pack(side=tk.LEFT, padx=8)

        ctl["info"] = ttk.Label(box, text="", font=("Arial", 8, "italic"))
        ctl["info"].pack(anchor=tk.W, padx=8, pady=2)
        self._sym_on_change(ctl, "algo")
        return ctl

    def _sym_on_change(self, ctl: dict, changed: str):
        cipher = create_cipher(ctl["algo"].get(), ctl["mode"].get(), ctl["padding"].get())
        if changed == "algo":
            self._sym_set_entry(ctl["key"], self.SYM_DEFAULT_KEYS[cipher.NAME])
            ctl["key_fmt"].set("ASCII")
            self._sym_set_entry(ctl["iv"], "ABCDEFGHIJKLMNOP"[:cipher.block_size])
            ctl["iv_fmt"].set("ASCII")

        iv_state = "normal" if cipher.needs_iv else "disabled"
        ctl["iv"].config(state=iv_state)
        ctl["iv_gen"].config(state=iv_state)
        ctl["iv_fmt_box"].config(state="readonly" if cipher.needs_iv else "disabled")
        ctl["embed_box"].config(state=iv_state)

        sizes = " / ".join(map(str, cipher.key_sizes))
        iv_note = f"IV {cipher.block_size} байт" if cipher.needs_iv else "IV не використовується (ECB)"
        ctl["info"].config(
            text=f"{cipher.PROVIDER.__name__}: ключ {sizes} байт, блок {cipher.block_size} байт, {iv_note}. "
                 f"Режими .NET Framework: ECB, CBC, CFB (8 біт); OFB та CTS провайдер відхиляє."
        )

    @staticmethod
    def _sym_set_entry(entry: ttk.Entry, value: str):
        state = str(entry.cget("state"))
        entry.config(state="normal")
        entry.delete(0, tk.END)
        entry.insert(0, value)
        entry.config(state=state)

    def _sym_generate(self, ctl: dict, name: str):
        cipher = create_cipher(ctl["algo"].get(), ctl["mode"].get(), ctl["padding"].get())
        value = cipher.generate_key() if name == "key" else cipher.generate_iv()
        ctl[f"{name}_fmt"].set("HEX")
        self._sym_set_entry(ctl[name], to_hex(value))

    def _sym_read_params(self, ctl: dict, is_encrypt: bool) -> tuple[NetSymmetricCipher, bytes, Optional[bytes], bool]:
        cipher = create_cipher(ctl["algo"].get(), ctl["mode"].get(), ctl["padding"].get())
        key = text_to_bytes(ctl["key"].get(), ctl["key_fmt"].get(), "Ключ")
        embed = ctl["embed"].get() and cipher.needs_iv
        iv = None
        # При розшифруванні з вбудованим IV він береться з шифротексту
        if cipher.needs_iv and not (embed and not is_encrypt):
            iv_text = ctl["iv"].get()
            if iv_text.strip():
                iv = text_to_bytes(iv_text, ctl["iv_fmt"].get(), "IV")
            elif embed:
                iv = cipher.generate_iv()
                ctl["iv_fmt"].set("HEX")
                self._sym_set_entry(ctl["iv"], to_hex(iv))
        return cipher, key, iv, embed

    def _sym_build_tab(self):
        toolbar = ttk.Frame(self.tab_sym)
        toolbar.pack(fill=tk.X, padx=5, pady=4)

        ttk.Button(toolbar, text="📄 Новий", command=self.file_new).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📂 Відкрити", command=self.file_open).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="💾 Зберегти", command=self.file_save).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🖨️ Друк", command=self.file_print).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🔄 Поміняти місцями", command=self._sym_swap_text).pack(side=tk.LEFT, padx=6)

        self.sym_ctl = self._sym_build_params(self.tab_sym, "Параметри криптопровайдера .NET (ПР5)")
        row1 = self.sym_ctl["row1"]
        ttk.Label(row1, text="Шифротекст:").pack(side=tk.LEFT, padx=(8, 4))
        self.sym_out_fmt_var = tk.StringVar(value="Base64")
        ttk.Combobox(row1, textvariable=self.sym_out_fmt_var, values=list(OUTPUT_FORMATS),
                     state="readonly", width=7).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="🔒 Зашифрувати", command=lambda: self._sym_process_text(True)).pack(side=tk.LEFT, padx=10)
        ttk.Button(row1, text="🔓 Розшифрувати", command=lambda: self._sym_process_text(False)).pack(side=tk.LEFT, padx=2)

        content_frame = ttk.Frame(self.tab_sym)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=4)

        f_left = ttk.LabelFrame(content_frame, text="Вхідний текст", padding=5)
        f_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)
        self.sym_txt_input = tk.Text(f_left, wrap=tk.WORD, font=("Consolas", 10))
        self.sym_txt_input.insert("1.0", "Hello World! Безпека інформаційних систем, ТВ-31")
        self.sym_txt_input.pack(fill=tk.BOTH, expand=True)

        f_right = ttk.LabelFrame(content_frame, text="Результат", padding=5)
        f_right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)
        self.sym_txt_output = tk.Text(f_right, wrap=tk.WORD, font=("Consolas", 10))
        self.sym_txt_output.pack(fill=tk.BOTH, expand=True)

        self.sym_lbl_status = ttk.Label(self.tab_sym, text="", font=("Arial", 9, "bold"), foreground="darkblue")
        self.sym_lbl_status.pack(anchor=tk.W, padx=8, pady=(0, 6))

    def _sym_process_text(self, is_encrypt: bool):
        text = self._get_text(self.sym_txt_input)
        fmt = self.sym_out_fmt_var.get()
        try:
            cipher, key, iv, embed = self._sym_read_params(self.sym_ctl, is_encrypt)
            title = f"{cipher.NAME}-{cipher.mode}/{cipher.padding}"
            if is_encrypt:
                data = cipher.encrypt(text, key, iv)
                if embed:
                    data = iv + data
                res = encode_output(data, fmt)
                status = f"{title}: зашифровано, {len(data)} байт шифротексту" + (" (з IV на початку)" if embed else "")
            else:
                data = decode_input(text, fmt)
                if embed:
                    iv, data = cipher.split_iv(data)
                res = cipher.decrypt(data, key, iv)
                status = f"{title}: розшифровано {len(res)} символів" + (f", IV з шифротексту: {to_hex(iv)}" if embed else "")
            self._set_text(self.sym_txt_output, res)
            self.sym_lbl_status.config(text=status, foreground="darkblue")
        except Exception as e:
            self._set_text(self.sym_txt_output, "")
            self.sym_lbl_status.config(text=str(e), foreground="red")
            messagebox.showerror("Помилка обробки", str(e))

    def _sym_swap_text(self):
        in_t = self._get_text(self.sym_txt_input)
        self._set_text(self.sym_txt_input, self._get_text(self.sym_txt_output))
        self._set_text(self.sym_txt_output, in_t)

    def _sym_build_file_tab(self):
        f = ttk.Frame(self.tab_sym_file, padding=8)
        f.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            f,
            text="Шифрування файлів будь-якого формату за схемою FileStream → CryptoStream → FileStream (.NET).",
            font=("Arial", 10),
        ).pack(anchor=tk.W, padx=5, pady=6)

        btn_box = ttk.Frame(f)
        btn_box.pack(fill=tk.X, padx=5, pady=4)
        ttk.Button(btn_box, text="📂 Обрати файл...", command=self._sym_choose_file).pack(side=tk.LEFT, padx=4)
        self.sym_file_path: Optional[str] = None
        self.sym_lbl_file = ttk.Label(btn_box, text="Файл не обрано", foreground="gray")
        self.sym_lbl_file.pack(side=tk.LEFT, padx=8)

        self.sym_file_ctl = self._sym_build_params(f, "Параметри криптопровайдера .NET (ПР5)")

        act_box = ttk.Frame(f)
        act_box.pack(fill=tk.X, padx=5, pady=8)
        ttk.Button(act_box, text="🔒 Зашифрувати файл", command=lambda: self._sym_process_file(True)).pack(side=tk.LEFT, padx=6)
        ttk.Button(act_box, text="🔓 Розшифрувати файл", command=lambda: self._sym_process_file(False)).pack(side=tk.LEFT, padx=6)

        self.sym_lbl_file_status = ttk.Label(f, text="", font=("Arial", 9, "bold"), foreground="darkblue", wraplength=1100)
        self.sym_lbl_file_status.pack(anchor=tk.W, padx=8, pady=4)

    def _sym_choose_file(self):
        path = filedialog.askopenfilename(title="Оберіть файл для обробки")
        if path:
            self.sym_file_path = path
            self.sym_lbl_file.config(text=f"{os.path.basename(path)} ({os.path.getsize(path)} байт)", foreground="black")

    def _sym_process_file(self, is_encrypt: bool):
        if not self.sym_file_path:
            messagebox.showwarning("Увага", "Будь ласка, спочатку оберіть файл.")
            return
        try:
            cipher, key, iv, embed = self._sym_read_params(self.sym_file_ctl, is_encrypt)
        except Exception as e:
            messagebox.showerror("Помилка параметрів", str(e))
            return

        base = os.path.basename(self.sym_file_path)
        if is_encrypt:
            initial = base + ".enc"
        else:
            initial = "dec_" + (base[:-4] if base.endswith(".enc") else base)
        save_path = filedialog.asksaveasfilename(title="Зберегти оброблений файл як...", initialfile=initial)
        if not save_path:
            return

        try:
            process = cipher.encrypt_file if is_encrypt else cipher.decrypt_file
            size = process(self.sym_file_path, save_path, key, iv, embed_iv=embed)
            action = "Зашифровано" if is_encrypt else "Розшифровано"
            status = f"{action} ({cipher.NAME}-{cipher.mode}/{cipher.padding}): {save_path} ({size} байт)"
            self.sym_lbl_file_status.config(text=status, foreground="darkblue")
            messagebox.showinfo("Успіх", f"Файл успішно збережено в:\n{save_path}\nРозмір: {size} байт.")
        except Exception as e:
            self.sym_lbl_file_status.config(text=str(e), foreground="red")
            messagebox.showerror("Помилка", f"Не вдалося обробити файл:\n{e}")

    @staticmethod
    def _rsa_short(value: int, limit: int = 48) -> str:
        text = str(value)
        return text if len(text) <= limit else f"{text[:20]}…{text[-20:]} ({len(text)} цифр)"

    def _rsa_toolbar(self, parent: ttk.Frame, swap) -> ttk.Frame:
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill=tk.X, padx=5, pady=4)
        ttk.Button(toolbar, text="📄 Новий", command=self.file_new).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📂 Відкрити", command=self.file_open).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="💾 Зберегти", command=self.file_save).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🖨️ Друк", command=self.file_print).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🔄 Поміняти місцями", command=swap).pack(side=tk.LEFT, padx=6)
        return toolbar

    def _rsa_text_pair(self, parent: ttk.Frame, sample: str, left: str = "Вхідний текст",
                       right: str = "Результат") -> tuple[tk.Text, tk.Text]:
        content = ttk.Frame(parent)
        content.pack(fill=tk.BOTH, expand=True, padx=5, pady=4)
        boxes = []
        for title in (left, right):
            frame = ttk.LabelFrame(content, text=title, padding=5)
            frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)
            text = tk.Text(frame, wrap=tk.WORD, font=("Consolas", 10), height=8)
            text.pack(fill=tk.BOTH, expand=True)
            boxes.append(text)
        boxes[0].insert("1.0", sample)
        return boxes[0], boxes[1]

    def _rsa_swap(self, a: tk.Text, b: tk.Text):
        first = self._get_text(a)
        self._set_text(a, self._get_text(b))
        self._set_text(b, first)

    def _rsa_fail(self, label: ttk.Label, output: Optional[tk.Text], error: Exception, title: str = "Помилка обробки"):
        if output is not None:
            self._set_text(output, "")
        label.config(text=str(error), foreground="red")
        messagebox.showerror(title, str(error))

    def _rsa_build_tab(self):
        self._rsa_toolbar(self.tab_rsa, lambda: self._rsa_swap(self.rsa_txt_input, self.rsa_txt_output))

        params = ttk.LabelFrame(self.tab_rsa, text="Параметри RSA на цілих числах (ПР7)", padding=8)
        params.pack(fill=tk.X, padx=5, pady=4)
        row = ttk.Frame(params)
        row.pack(fill=tk.X, pady=2)
        ttk.Button(row, text="🔑 Відкритий ключ...", command=lambda: self._rsa_open_key_dialog("textbook")).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="📖 Приклад з Вікіпедії", command=self._rsa_load_wiki_example).pack(side=tk.LEFT, padx=4)
        ttk.Label(row, text="Дані:").pack(side=tk.LEFT, padx=(12, 4))
        self.rsa_fmt_var = tk.StringVar(value=TEXT_FORMATS[0])
        ttk.Combobox(row, textvariable=self.rsa_fmt_var, values=list(TEXT_FORMATS), state="readonly",
                     width=13).pack(side=tk.LEFT, padx=2)
        ttk.Button(row, text="🔒 Зашифрувати", command=lambda: self._rsa_process_text(True)).pack(side=tk.LEFT, padx=10)
        ttk.Button(row, text="🔓 Розшифрувати", command=lambda: self._rsa_process_text(False)).pack(side=tk.LEFT, padx=2)

        self.rsa_key_entries: dict[str, ttk.Entry] = {}
        keys_row = ttk.Frame(params)
        keys_row.pack(fill=tk.X, pady=2)
        for name, width in (("n", 46), ("e", 10), ("d", 46)):
            ttk.Label(keys_row, text=f"{name} =").pack(side=tk.LEFT, padx=(8, 2))
            entry = ttk.Entry(keys_row, width=width, font=("Consolas", 10), state="readonly")
            entry.pack(side=tk.LEFT, padx=2)
            self.rsa_key_entries[name] = entry

        self.rsa_txt_input, self.rsa_txt_output = self._rsa_text_pair(
            self.tab_rsa, str(WIKI_M), "Вхідні дані (числа m < n або текст)", "Результат")

        calc = ttk.LabelFrame(self.tab_rsa, text="Покроковий розрахунок", padding=5)
        calc.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        self.rsa_txt_calc = tk.Text(calc, wrap=tk.NONE, font=("Consolas", 10), height=10)
        self.rsa_txt_calc.pack(fill=tk.BOTH, expand=True)

        self.rsa_lbl_status = ttk.Label(self.tab_rsa, text="", font=("Arial", 9, "bold"), foreground="darkblue")
        self.rsa_lbl_status.pack(anchor=tk.W, padx=8, pady=(0, 6))
        self._rsa_set_key(self.rsa_key)

    def _rsa_set_key(self, key: RSAKey):
        self.rsa_key = key
        for name, entry in self.rsa_key_entries.items():
            value = getattr(key, name)
            self._sym_set_entry(entry, "" if value is None else str(value))
        self._set_text(self.rsa_txt_calc, TextbookRSA.describe(key))
        self.rsa_lbl_status.config(text=f"Ключ RSA: n має {key.bits} біт", foreground="darkblue")

    def _rsa_load_wiki_example(self):
        self._rsa_set_key(TextbookRSA.make_key(WIKI_P, WIKI_Q, WIKI_E))
        self.rsa_fmt_var.set(TEXT_FORMATS[0])
        self._set_text(self.rsa_txt_input, str(WIKI_M))
        self._set_text(self.rsa_txt_output, "")

    def _rsa_process_text(self, is_encrypt: bool):
        key, text = self.rsa_key, self._get_text(self.rsa_txt_input)
        as_text = self.rsa_fmt_var.get() != TEXT_FORMATS[0]
        try:
            if is_encrypt:
                if as_text:
                    result = self.rsa_textbook.encrypt_text(text, key)
                    source = self.rsa_textbook.text_to_blocks(text, key)
                else:
                    source = parse_numbers(text, "Повідомлення")
                    result = self.rsa_textbook.encrypt(source, key)
                lines = [f"c{i} = m^e mod n = {self._rsa_short(m)}^{key.e} mod {self._rsa_short(key.n)} = {self._rsa_short(c)}"
                         for i, (m, c) in enumerate(zip(source, result), 1)]
                output = " ".join(map(str, result))
                status = f"Зашифровано {len(result)} блок(ів) відкритим ключем (e, n)"
            else:
                blocks = parse_numbers(text)
                plain = self.rsa_textbook.decrypt(blocks, key)
                lines = [f"m{i} = c^d mod n = {self._rsa_short(c)}^{self._rsa_short(key.d)} mod {self._rsa_short(key.n)} = {self._rsa_short(m)}"
                         for i, (c, m) in enumerate(zip(blocks, plain), 1)]
                output = self.rsa_textbook.decrypt_text(blocks, key) if as_text else " ".join(map(str, plain))
                status = f"Розшифровано {len(blocks)} блок(ів) закритим ключем (d, n)"
            if len(lines) > 12:
                lines = lines[:12] + [f"... ще {len(lines) - 12} блок(ів)"]
            self._set_text(self.rsa_txt_output, output)
            self._set_text(self.rsa_txt_calc, TextbookRSA.describe(key) + "\n\n" + "\n".join(lines))
            self.rsa_lbl_status.config(text=status, foreground="darkblue")
        except Exception as e:
            self._rsa_fail(self.rsa_lbl_status, self.rsa_txt_output, e)

    def _rsa_net_build_tab(self):
        self._rsa_toolbar(self.tab_rsa_net, lambda: self._rsa_swap(self.rsa_net_txt_input, self.rsa_net_txt_output))

        params = ttk.LabelFrame(self.tab_rsa_net, text="Криптопровайдер .NET RSACryptoServiceProvider (ПР7)", padding=8)
        params.pack(fill=tk.X, padx=5, pady=4)
        row = ttk.Frame(params)
        row.pack(fill=tk.X, pady=2)
        ttk.Button(row, text="🔑 Відкритий ключ...", command=lambda: self._rsa_open_key_dialog("net")).pack(side=tk.LEFT, padx=4)
        ttk.Label(row, text="Доповнення:").pack(side=tk.LEFT, padx=(12, 4))
        self.rsa_net_padding_var = tk.StringVar(value="OAEP")
        padding_box = ttk.Combobox(row, textvariable=self.rsa_net_padding_var, values=list(RSA_PADDINGS),
                                   state="readonly", width=7)
        padding_box.pack(side=tk.LEFT, padx=2)
        padding_box.bind("<<ComboboxSelected>>", lambda _e: self._rsa_net_refresh_info())
        ttk.Label(row, text="Шифротекст:").pack(side=tk.LEFT, padx=(12, 4))
        self.rsa_net_fmt_var = tk.StringVar(value="Base64")
        ttk.Combobox(row, textvariable=self.rsa_net_fmt_var, values=list(OUTPUT_FORMATS), state="readonly",
                     width=7).pack(side=tk.LEFT, padx=2)
        ttk.Button(row, text="🔒 Зашифрувати", command=lambda: self._rsa_net_process_text(True)).pack(side=tk.LEFT, padx=10)
        ttk.Button(row, text="🔓 Розшифрувати", command=lambda: self._rsa_net_process_text(False)).pack(side=tk.LEFT, padx=2)
        self.rsa_net_lbl_info = ttk.Label(params, text="", font=("Arial", 8, "italic"))
        self.rsa_net_lbl_info.pack(anchor=tk.W, padx=8, pady=2)

        self.rsa_net_txt_input, self.rsa_net_txt_output = self._rsa_text_pair(
            self.tab_rsa_net, "Data to encrypt. Безпека інформаційних систем, ТВ-31")

        self.rsa_net_lbl_status = ttk.Label(self.tab_rsa_net, text="", font=("Arial", 9, "bold"), foreground="darkblue")
        self.rsa_net_lbl_status.pack(anchor=tk.W, padx=8, pady=(0, 6))
        self._rsa_net_refresh_info()

    def _rsa_net_recipient(self) -> NetRSACipher:
        if self.rsa_net_public_xml is None:
            return self.rsa_net
        return NetRSACipher(None, self.rsa_net_public_xml)

    def _rsa_net_refresh_info(self):
        try:
            recipient = self._rsa_net_recipient()
            padding = self.rsa_net_padding_var.get()
            whose = "власний відкритий ключ" if self.rsa_net_public_xml is None else "імпортований відкритий ключ отримувача"
            self.rsa_net_lbl_info.config(
                text=f"Шифрування: {whose}, {recipient.key_size} біт, до {recipient.max_message_size(padding)} байт "
                     f"з доповненням {padding}.   Розшифрування: власний закритий ключ, {self.rsa_net.key_size} біт."
            )
        except Exception as e:
            self.rsa_net_lbl_info.config(text=str(e))

    def _rsa_net_process_text(self, is_encrypt: bool):
        text = self._get_text(self.rsa_net_txt_input)
        padding, fmt = self.rsa_net_padding_var.get(), self.rsa_net_fmt_var.get()
        try:
            if is_encrypt:
                result = self.rsa_net.encrypt_text(text, padding, self.rsa_net_public_xml, fmt)
                status = f"RSA-{padding}: зашифровано відкритим ключем, {len(decode_input(result, fmt))} байт шифротексту"
            else:
                result = self.rsa_net.decrypt_text(text, padding, fmt)
                status = f"RSA-{padding}: розшифровано закритим ключем, {len(result)} символів"
            self._set_text(self.rsa_net_txt_output, result)
            self.rsa_net_lbl_status.config(text=status, foreground="darkblue")
        except Exception as e:
            self._rsa_fail(self.rsa_net_lbl_status, self.rsa_net_txt_output, e)

    def _rsa_open_key_dialog(self, page: str = "net"):
        dlg = tk.Toplevel(self)
        dlg.title("Формування відкритого ключа RSA")
        dlg.geometry("980x680")
        dlg.transient(self)
        dlg.grab_set()
        self.rsa_dialog = dlg

        book = ttk.Notebook(dlg)
        book.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        net_page = ttk.Frame(book, padding=8)
        tb_page = ttk.Frame(book, padding=8)
        book.add(net_page, text="🔐 .NET RSACryptoServiceProvider")
        book.add(tb_page, text="🔑 Числовий RSA (p, q, e)")
        self._rsa_build_net_key_page(net_page, dlg)
        self._rsa_build_textbook_key_page(tb_page, dlg)
        book.select(tb_page if page == "textbook" else net_page)

        ttk.Button(dlg, text="Закрити", command=dlg.destroy).pack(anchor=tk.E, padx=10, pady=(0, 8))
        return dlg

    def _rsa_build_net_key_page(self, page: ttk.Frame, dlg: tk.Toplevel):
        row = ttk.Frame(page)
        row.pack(fill=tk.X, pady=4)
        ttk.Label(row, text="Розмір ключа (біт):").pack(side=tk.LEFT, padx=4)
        size_var = tk.StringVar(value=str(self.rsa_net.key_size))
        ttk.Combobox(row, textvariable=size_var, values=[str(s) for s in NET_KEY_SIZES], width=8).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="🔑 Згенерувати пару ключів",
                   command=lambda: generate()).pack(side=tk.LEFT, padx=8)
        info = ttk.Label(page, text="", font=("Arial", 9, "bold"), foreground="darkblue", wraplength=920)
        info.pack(anchor=tk.W, padx=4, pady=4)

        pub_frame = ttk.LabelFrame(page, text="Відкритий ключ для шифрування: ToXmlString(false)", padding=5)
        pub_frame.pack(fill=tk.BOTH, expand=True, pady=4)
        pub_text = tk.Text(pub_frame, wrap=tk.CHAR, font=("Consolas", 9), height=7)
        pub_text.pack(fill=tk.BOTH, expand=True)
        pub_row = ttk.Frame(page)
        pub_row.pack(fill=tk.X, pady=2)
        ttk.Button(pub_row, text="📥 Імпортувати ключ з поля", command=lambda: import_key()).pack(side=tk.LEFT, padx=4)
        ttk.Button(pub_row, text="📂 Завантажити .xml", command=lambda: load_key()).pack(side=tk.LEFT, padx=4)
        ttk.Button(pub_row, text="💾 Зберегти відкритий ключ", command=lambda: save_key()).pack(side=tk.LEFT, padx=4)
        ttk.Button(pub_row, text="🔄 Власний відкритий ключ", command=lambda: use_own()).pack(side=tk.LEFT, padx=4)

        show_private = tk.BooleanVar(value=False)
        ttk.Checkbutton(page, text="Показати закритий ключ ToXmlString(true) (зберігається лише в пам'яті провайдера)",
                        variable=show_private, command=lambda: refresh()).pack(anchor=tk.W, pady=(8, 2))
        priv_text = tk.Text(page, wrap=tk.CHAR, font=("Consolas", 9), height=7)
        priv_text.pack(fill=tk.BOTH, expand=True)

        def refresh(message: str = ""):
            recipient = self._rsa_net_recipient()
            n, e = recipient.public_numbers()
            whose = "власний" if self.rsa_net_public_xml is None else "імпортований"
            self._set_text(pub_text, recipient.export_xml(False))
            priv_text.config(state="normal")
            self._set_text(priv_text, self.rsa_net.export_xml(True) if show_private.get() else "")
            priv_text.config(state="disabled")
            info.config(text=(message + "\n" if message else "") +
                        f"Відкритий ключ ({whose}): {recipient.key_size} біт, e = {e}, n = {self._rsa_short(n, 60)}",
                        foreground="darkblue")
            self._rsa_net_refresh_info()

        def fail(error: Exception):
            info.config(text=str(error), foreground="red")
            messagebox.showerror("Помилка ключа", str(error), parent=dlg)

        def generate():
            try:
                size = NetRSACipher.check_key_size(size_var.get())
                dlg.config(cursor="watch")
                dlg.update_idletasks()
                self.rsa_net.generate(size)
                self.rsa_net_public_xml = None
                refresh(f"Згенеровано нову пару ключів {size} біт.")
            except Exception as e:
                fail(e)
            finally:
                dlg.config(cursor="")

        def import_key(xml: Optional[str] = None):
            try:
                xml = self._get_text(pub_text) if xml is None else xml
                imported = NetRSACipher(None, xml)
                if imported.has_private:
                    raise RSAError("У полі закритий ключ: для шифрування імпортуйте лише відкритий ключ ToXmlString(false).")
                own = self.rsa_net.export_xml(False)
                self.rsa_net_public_xml = None if imported.export_xml(False) == own else imported.export_xml(False)
                refresh("Відкритий ключ імпортовано через FromXmlString.")
            except Exception as e:
                fail(e)

        def load_key():
            path = filedialog.askopenfilename(parent=dlg, title="Відкрити відкритий ключ",
                                              filetypes=[("XML", "*.xml"), ("Усі файли", "*.*")])
            if not path:
                return
            try:
                if os.path.getsize(path) > MAX_XML_LENGTH:
                    raise RSAError("Файл занадто великий для ключа RSA.")
                with open(path, "r", encoding="utf-8") as f:
                    import_key(f.read())
            except (OSError, UnicodeDecodeError, RSAError) as e:
                fail(RSAError(f"Не вдалося прочитати ключ: {e}"))

        def save_key():
            path = filedialog.asksaveasfilename(parent=dlg, title="Зберегти відкритий ключ", defaultextension=".xml",
                                                filetypes=[("XML", "*.xml")])
            if not path:
                return
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self._rsa_net_recipient().export_xml(False))
                refresh(f"Відкритий ключ збережено: {path}")
            except Exception as e:
                fail(e)

        def use_own():
            self.rsa_net_public_xml = None
            refresh("Для шифрування використовується власний відкритий ключ.")

        refresh()
        self.rsa_dialog_net = {"size": size_var, "generate": generate, "pub": pub_text, "import": import_key,
                               "show_private": show_private, "refresh": refresh}

    def _rsa_build_textbook_key_page(self, page: ttk.Frame, dlg: tk.Toplevel):
        entries: dict[str, ttk.Entry] = {}
        for name, title in (("p", "Просте p:"), ("q", "Просте q:"), ("e", "Відкрита експонента e:")):
            row = ttk.Frame(page)
            row.pack(fill=tk.X, pady=3)
            ttk.Label(row, text=title, width=22).pack(side=tk.LEFT, padx=4)
            entries[name] = ttk.Entry(row, width=90, font=("Consolas", 10))
            entries[name].pack(side=tk.LEFT, padx=4)
            value = getattr(self.rsa_key, name)
            entries[name].insert(0, "" if value is None else str(value))

        row = ttk.Frame(page)
        row.pack(fill=tk.X, pady=6)
        ttk.Button(row, text="🔑 Сформувати ключ", command=lambda: build()).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="📖 Приклад з Вікіпедії", command=lambda: wiki()).pack(side=tk.LEFT, padx=4)
        ttk.Label(row, text="Розрядність n (біт):").pack(side=tk.LEFT, padx=(16, 4))
        bits_var = tk.StringVar(value="64")
        ttk.Spinbox(row, from_=TEXTBOOK_MIN_BITS, to=TEXTBOOK_MAX_BITS, increment=8, textvariable=bits_var,
                    width=7).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="🔄 Згенерувати p, q", command=lambda: generate()).pack(side=tk.LEFT, padx=4)

        info = ttk.Label(page, text="", font=("Arial", 9, "bold"), foreground="darkblue", wraplength=920)
        info.pack(anchor=tk.W, padx=4, pady=4)
        result = tk.Text(page, wrap=tk.CHAR, font=("Consolas", 10), height=14)
        result.pack(fill=tk.BOTH, expand=True)

        def apply(key: RSAKey, message: str):
            for name in ("p", "q", "e"):
                entries[name].delete(0, tk.END)
                entries[name].insert(0, str(getattr(key, name)))
            self._rsa_set_key(key)
            self._set_text(result, TextbookRSA.describe(key))
            info.config(text=message, foreground="darkblue")

        def fail(error: Exception):
            self._set_text(result, "")
            info.config(text=str(error), foreground="red")
            messagebox.showerror("Помилка ключа", str(error), parent=dlg)

        def build():
            try:
                key = TextbookRSA.make_key(entries["p"].get(), entries["q"].get(), entries["e"].get())
                apply(key, f"Ключ сформовано: n має {key.bits} біт.")
            except Exception as e:
                fail(e)

        def wiki():
            apply(TextbookRSA.make_key(WIKI_P, WIKI_Q, WIKI_E), "Ключ з прикладу Вікіпедії: p = 61, q = 53, e = 17.")

        def generate():
            try:
                e_text = entries["e"].get().strip()
                key = TextbookRSA.generate_key(bits_var.get(), e_text or None)
                apply(key, f"Згенеровано випадкові прості p і q, n має {key.bits} біт.")
            except Exception as e:
                fail(e)

        self._set_text(result, TextbookRSA.describe(self.rsa_key))
        self.rsa_dialog_tb = {"entries": entries, "build": build, "wiki": wiki, "bits": bits_var, "generate": generate}

    def _rsa_build_attack_tab(self):
        tab = self.tab_rsa_attack
        self._rsa_toolbar(tab, lambda: self._rsa_swap(self.rsa_attack_txt_input, self.rsa_attack_txt_output))

        params = ttk.LabelFrame(tab, text="Атака на RSA розкладанням модуля n на прості множники (ПР7)", padding=8)
        params.pack(fill=tk.X, padx=5, pady=4)
        row = ttk.Frame(params)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="n =").pack(side=tk.LEFT, padx=(4, 2))
        self.rsa_attack_n = ttk.Entry(row, width=70, font=("Consolas", 10))
        self.rsa_attack_n.pack(side=tk.LEFT, padx=2)
        ttk.Label(row, text="e =").pack(side=tk.LEFT, padx=(10, 2))
        self.rsa_attack_e = ttk.Entry(row, width=10, font=("Consolas", 10))
        self.rsa_attack_e.pack(side=tk.LEFT, padx=2)
        ttk.Label(row, text="Ліміт, с:").pack(side=tk.LEFT, padx=(10, 2))
        self.rsa_attack_limit = tk.StringVar(value="30")
        ttk.Spinbox(row, from_=1, to=600, textvariable=self.rsa_attack_limit, width=5).pack(side=tk.LEFT, padx=2)

        row2 = ttk.Frame(params)
        row2.pack(fill=tk.X, pady=4)
        ttk.Button(row2, text="📥 Взяти з вкладки RSA", command=self._rsa_attack_take_from_tab).pack(side=tk.LEFT, padx=4)
        ttk.Button(row2, text="🔍 Розкласти n і зламати", command=self._rsa_run_attack).pack(side=tk.LEFT, padx=4)
        ttk.Label(row2, text="Розшифрувати як:").pack(side=tk.LEFT, padx=(12, 4))
        self.rsa_attack_fmt = tk.StringVar(value=TEXT_FORMATS[1])
        ttk.Combobox(row2, textvariable=self.rsa_attack_fmt, values=list(TEXT_FORMATS), state="readonly",
                     width=13).pack(side=tk.LEFT, padx=2)

        self.rsa_attack_txt_input, self.rsa_attack_txt_output = self._rsa_text_pair(
            tab, "", "Перехоплений шифротекст (числа)", "Результат атаки")
        self.rsa_attack_lbl_status = ttk.Label(tab, text="", font=("Arial", 9, "bold"), foreground="darkblue")
        self.rsa_attack_lbl_status.pack(anchor=tk.W, padx=8)

        bench = ttk.LabelFrame(tab, text="Область значень параметрів, за яких атака реальна", padding=6)
        bench.pack(fill=tk.BOTH, expand=True, padx=5, pady=4)
        brow = ttk.Frame(bench)
        brow.pack(fill=tk.X, pady=2)
        ttk.Label(brow, text="Розрядності n (біт):").pack(side=tk.LEFT, padx=4)
        self.rsa_bench_bits = ttk.Entry(brow, width=44)
        self.rsa_bench_bits.insert(0, "16 24 32 40 48 56 64 72 80 88 96")
        self.rsa_bench_bits.pack(side=tk.LEFT, padx=4)
        ttk.Label(brow, text="Ліміт на ключ, с:").pack(side=tk.LEFT, padx=(10, 2))
        self.rsa_bench_limit = tk.StringVar(value="10")
        ttk.Spinbox(brow, from_=1, to=120, textvariable=self.rsa_bench_limit, width=5).pack(side=tk.LEFT, padx=2)
        self.rsa_bench_btn = ttk.Button(brow, text="📊 Дослідити межу", command=self._rsa_run_benchmark)
        self.rsa_bench_btn.pack(side=tk.LEFT, padx=8)

        tables = ttk.Frame(bench)
        tables.pack(fill=tk.BOTH, expand=True)
        columns = (("bits", "Біт", 50), ("n", "n", 260), ("p", "p", 170), ("q", "q", 170), ("time", "Час, с", 80),
                   ("ok", "Результат", 90))
        self.rsa_bench_tree = ttk.Treeview(tables, columns=[c[0] for c in columns], show="headings", height=8)
        for cid, title, width in columns:
            self.rsa_bench_tree.heading(cid, text=title)
            self.rsa_bench_tree.column(cid, width=width, anchor=tk.CENTER if cid in ("bits", "time", "ok") else tk.W)
        self.rsa_bench_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)

        known = ttk.Treeview(tables, columns=("bits", "who", "cost"), show="headings", height=10)
        for cid, title, width in (("bits", "Розмір n", 120), ("who", "Чим розкладається", 260), ("cost", "Час", 190)):
            known.heading(cid, text=title)
            known.column(cid, width=width)
        for row_values in RSA_FACTORING_LIMITS:
            known.insert("", tk.END, values=row_values)
        known.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)

    def _rsa_attack_take_from_tab(self):
        self._sym_set_entry(self.rsa_attack_n, str(self.rsa_key.n))
        self._sym_set_entry(self.rsa_attack_e, str(self.rsa_key.e))
        self._set_text(self.rsa_attack_txt_input, self._get_text(self.rsa_txt_output))
        self.rsa_attack_fmt.set(self.rsa_fmt_var.get())
        self.rsa_attack_lbl_status.config(text="Взято відкритий ключ (n, e) і шифротекст з вкладки RSA", foreground="darkblue")

    def _rsa_run_attack(self):
        try:
            limit = parse_int(self.rsa_attack_limit.get(), "Ліміт часу", 1)
            self.config(cursor="watch")
            self.update_idletasks()
            res = self.rsa_attack.attack(self.rsa_attack_n.get(), self.rsa_attack_e.get(), float(limit))
            key = res.key
            lines = [f"Метод: {res.method}, час: {res.elapsed:.4f} с", TextbookRSA.describe(key)]
            cipher_text = self._get_text(self.rsa_attack_txt_input)
            if cipher_text.strip():
                blocks = parse_numbers(cipher_text)
                if self.rsa_attack_fmt.get() == TEXT_FORMATS[0]:
                    plain = " ".join(map(str, self.rsa_textbook.decrypt(blocks, key)))
                else:
                    plain = self.rsa_textbook.decrypt_text(blocks, key)
                lines.append(f"\nРозшифроване повідомлення:\n{plain}")
            self._set_text(self.rsa_attack_txt_output, "\n".join(lines))
            self.rsa_attack_lbl_status.config(
                text=f"Ключ зламано: n = p·q розкладено за {res.elapsed:.4f} с ({res.method}), d = {self._rsa_short(key.d)}",
                foreground="darkblue")
        except Exception as e:
            self._rsa_fail(self.rsa_attack_lbl_status, self.rsa_attack_txt_output, e, "Атака не вдалася")
        finally:
            self.config(cursor="")

    def _rsa_run_benchmark(self):
        try:
            bits = parse_numbers(self.rsa_bench_bits.get(), "Розрядності")
            for b in bits:
                if not TEXTBOOK_MIN_BITS <= b <= 256:
                    raise RSAError(f"Розрядність {b} поза межами {TEXTBOOK_MIN_BITS}..256 біт.")
            limit = parse_int(self.rsa_bench_limit.get(), "Ліміт часу", 1)
        except Exception as e:
            self._rsa_fail(self.rsa_attack_lbl_status, None, e)
            return

        self.rsa_bench_tree.delete(*self.rsa_bench_tree.get_children())
        self.rsa_bench_btn.config(state="disabled")

        def add_row(row):
            self.rsa_bench_tree.insert("", tk.END, values=(
                row.bits, self._rsa_short(row.n, 36), row.p or "-", row.q or "-", f"{row.elapsed:.4f}",
                "зламано" if row.success else "не вдалося"))
            self.update()

        try:
            rows = self.rsa_attack.benchmark(bits, float(limit), add_row)
            broken = [r.bits for r in rows if r.success]
            self.rsa_attack_lbl_status.config(
                text=f"Зламано {len(broken)} з {len(rows)} ключів; найбільший зламаний n має {max(broken, default=0)} біт",
                foreground="darkblue")
        except Exception as e:
            self._rsa_fail(self.rsa_attack_lbl_status, None, e)
        finally:
            self.rsa_bench_btn.config(state="normal")

    def process_text(self, is_encrypt: bool):
        """Аліас для універсального виклику шифрування активної вкладки."""
        current_tab = self.notebook.select()
        if current_tab == str(self.tab_caesar):
            self._caesar_process_text(is_encrypt)
        elif current_tab == str(self.tab_poem):
            self._poem_process_text(is_encrypt)
        elif current_tab == str(self.tab_book):
            self._book_process_text(is_encrypt)
        elif current_tab == str(self.tab_sym):
            self._sym_process_text(is_encrypt)
        elif current_tab == str(self.tab_rsa):
            self._rsa_process_text(is_encrypt)
        elif current_tab == str(self.tab_rsa_net):
            self._rsa_net_process_text(is_encrypt)
        elif current_tab == str(self.tab_rsa_attack):
            self._rsa_run_attack()
        else:
            self._trithemius_process_text(is_encrypt)

    def load_attack_example(self):
        self._trithemius_load_attack_example()

    def run_active_attack(self):
        self._trithemius_run_attack()

    def apply_attack_key_to_cipher(self):
        self._trithemius_apply_attack_key()


# Аліас імені для повної сумісності
APP = App


if __name__ == "__main__":
    app = App()
    app.mainloop()
