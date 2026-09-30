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


class App(tk.Tk):
    """
    Головний застосунок криптографічної системи (Software Security Practical Tasks).
    Уніфікований клас APP, який розширюється при додаванні нових лабораторних робіт:
      • ПР1: Шифр Цезаря (текст, двійкові файли, Brute-Force злам)
      • ПР2: Шифр Тритеміуса (2D/3D вектори, гасло, двійкові файли, активна атака KPA)
      • Наступні ПР (легко додаються окремими секціями методів)
    """

    # =========================================================================
    # СЕКЦІЯ 0: ІНІЦІАЛІЗАЦІЯ ТА ГОЛОВНИЙ ІНТЕРФЕЙС
    # =========================================================================
    def __init__(self):
        super().__init__()
        self.title("Комп'ютерні практикуми з безпеки ПЗ; ТВ-31 Гогуля Максим")
        self.geometry("960x730")
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

        # 5. Двійкове шифрування файлів (Binary) для всіх алгоритмів
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

    # =========================================================================
    # СЕКЦІЯ 1: СПІЛЬНІ СИСТЕМНІ ТА ФАЙЛОВІ МЕТОДИ (COMMON)
    # =========================================================================
    def _get_active_text_widgets(self) -> tuple[tk.Text, tk.Text]:
        """Повертає пару текстових полів (вхід/вихід) поточної активної вкладки."""
        current_tab = self.notebook.select()
        if current_tab == str(self.tab_caesar):
            return self.caesar_txt_input, self.caesar_txt_output
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
            "• ПР2: «Шифр Тритеміуса» (2D/3D векторні ключі, Гасло, KPA-атака, Binary)\n\n"
            "Архітектура системи побудована на єдиному модульному класі APP,\n"
            "що автоматично розширюється при додаванні нових практичних робіт.\n",
        )

    # =========================================================================
    # СЕКЦІЯ 2: СПЕЦИФІЧНІ МЕТОДИ ПР1 — ШИФР ЦЕЗАРЯ (_caesar_...)
    # =========================================================================
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

    # =========================================================================
    # СЕКЦІЯ 3: СПЕЦИФІЧНІ МЕТОДИ ПР2 — ШИФР ТРИТЕМІУСА (_trithemius_...)
    # =========================================================================
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

    # =========================================================================
    # СЕКЦІЯ 4: СПЕЦИФІЧНІ МЕТОДИ ДВІЙКОВОГО ШИФРУВАННЯ ФАЙЛІВ (_binary_...)
    # =========================================================================
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

    # =========================================================================
    # АЛІАСИ ДЛЯ ЗВОРОТНОЇ СУМІСНОСТІ
    # =========================================================================
    def process_text(self, is_encrypt: bool):
        """Аліас для універсального виклику шифрування активної вкладки."""
        current_tab = self.notebook.select()
        if current_tab == str(self.tab_caesar):
            self._caesar_process_text(is_encrypt)
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
