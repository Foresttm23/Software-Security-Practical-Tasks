import os
import tempfile
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from pr1.cipher import CaesarCipher, BinaryCaesarCipher, CaesarBruteForce

class CaesarApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ПР1 - Шифр Цезаря; ТВ-31 Гогуля Максим")
        self.geometry("820x650")
        self.minsize(700, 500)

        self.cipher = CaesarCipher()
        self.binary_cipher = BinaryCaesarCipher()
        self.brute_force = CaesarBruteForce(self.cipher)

        self._create_menu()
        self._create_widgets()

    def _create_menu(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="📄 Створити новий", command=self.file_new)
        file_menu.add_command(label="📂 Відкрити файл...", command=self.file_open)
        file_menu.add_command(label="💾 Зберегти результат...", command=self.file_save)
        file_menu.add_separator()
        file_menu.add_command(label="🖨️ Друкувати...", command=self.file_print)
        file_menu.add_separator()
        file_menu.add_command(label="🚪 Вихід з системи", command=self.file_exit)
        menubar.add_cascade(label="Файл", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="ℹ️ Про розробника", command=self.show_about)
        menubar.add_cascade(label="Довідка", menu=help_menu)

        self.config(menu=menubar)

    def _create_widgets(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.tab_text = ttk.Frame(notebook)
        notebook.add(self.tab_text, text="📝 Текстовий шифр")
        self._build_text_tab()

        self.tab_binary = ttk.Frame(notebook)
        notebook.add(self.tab_binary, text="📁 Шифрування файлів (Binary)")
        self._build_binary_tab()

        self.tab_bf = ttk.Frame(notebook)
        notebook.add(self.tab_bf, text="🔍 Brute-Force (Злам)")
        self._build_bf_tab()

    def _build_text_tab(self):
        toolbar = ttk.Frame(self.tab_text)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(toolbar, text="📄 Новий", command=self.file_new).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📂 Відкрити", command=self.file_open).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="💾 Зберегти", command=self.file_save).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🖨️ Друк", command=self.file_print).pack(side=tk.LEFT, padx=2)

        params_frame = ttk.LabelFrame(self.tab_text, text="Параметри шифрування", padding=8)
        params_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(params_frame, text="Мова:").pack(side=tk.LEFT, padx=4)
        self.lang_var = tk.StringVar(value="auto")
        lang_combo = ttk.Combobox(
            params_frame,
            textvariable=self.lang_var,
            values=["auto", "uk", "en"],
            state="readonly",
            width=12,
        )
        lang_combo.pack(side=tk.LEFT, padx=4)

        ttk.Label(params_frame, text="Ключ (k):").pack(side=tk.LEFT, padx=6)
        self.key_entry = ttk.Entry(params_frame, width=8)
        self.key_entry.insert(0, "3")
        self.key_entry.pack(side=tk.LEFT, padx=4)

        ttk.Button(params_frame, text="🔒 Зашифрувати", command=lambda: self.process_text(True)).pack(side=tk.LEFT, padx=8)
        ttk.Button(params_frame, text="🔓 Розшифрувати", command=lambda: self.process_text(False)).pack(side=tk.LEFT, padx=4)

        content_frame = ttk.Frame(self.tab_text)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        f_left = ttk.LabelFrame(content_frame, text="Вхідний текст", padding=5)
        f_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)
        self.txt_input = tk.Text(f_left, wrap=tk.WORD, font=("Consolas", 10))
        self.txt_input.insert("1.0", "Привіт Світ! Hello World! 2026. Гогуля Максим ТВ-31")
        self.txt_input.pack(fill=tk.BOTH, expand=True)

        f_right = ttk.LabelFrame(content_frame, text="Результат", padding=5)
        f_right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=3)
        self.txt_output = tk.Text(f_right, wrap=tk.WORD, font=("Consolas", 10))
        self.txt_output.pack(fill=tk.BOTH, expand=True)

    def process_text(self, is_encrypt: bool):
        raw_key = self.key_entry.get().strip()
        if not self.cipher.validate_key(raw_key):
            messagebox.showerror("Помилка", "Ключ повинен бути цілим числом!")
            return

        text = self.txt_input.get("1.0", tk.END).rstrip("\n")
        lang = self.lang_var.get()

        try:
            if is_encrypt:
                res = self.cipher.encrypt(text, raw_key, lang=lang)
            else:
                res = self.cipher.decrypt(text, raw_key, lang=lang)

            self.txt_output.delete("1.0", tk.END)
            self.txt_output.insert("1.0", res)
        except Exception as e:
            messagebox.showerror("Помилка обробки", str(e))

    def _build_binary_tab(self):
        f = ttk.Frame(self.tab_binary, padding=12)
        f.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            f,
            text="Шифрування будь-яких двійкових файлів (зображення, pdf, zip, тощо)\n"
                 "y = (b + k) mod 256.",
            font=("Arial", 10),
        ).pack(anchor=tk.W, pady=8)

        btn_box = ttk.Frame(f)
        btn_box.pack(fill=tk.X, pady=8)

        ttk.Button(btn_box, text="📂 Обрати вхідний файл...", command=self.bin_choose_file).pack(side=tk.LEFT, padx=4)
        self.lbl_bin_file = ttk.Label(btn_box, text="Файл не обрано", foreground="gray")
        self.lbl_bin_file.pack(side=tk.LEFT, padx=8)

        key_box = ttk.Frame(f)
        key_box.pack(fill=tk.X, pady=8)
        ttk.Label(key_box, text="Ключ зсуву байтів (0-255):").pack(side=tk.LEFT, padx=4)
        self.bin_key_entry = ttk.Entry(key_box, width=8)
        self.bin_key_entry.insert(0, "42")
        self.bin_key_entry.pack(side=tk.LEFT, padx=4)

        act_box = ttk.Frame(f)
        act_box.pack(fill=tk.X, pady=12)
        ttk.Button(act_box, text="🔒 Зашифрувати файл", command=lambda: self.bin_process(True)).pack(side=tk.LEFT, padx=6)
        ttk.Button(act_box, text="🔓 Розшифрувати файл", command=lambda: self.bin_process(False)).pack(side=tk.LEFT, padx=6)

        self.selected_bin_path = None

    def bin_choose_file(self):
        file_path = filedialog.askopenfilename(title="Оберіть файл для шифрування")
        if file_path:
            self.selected_bin_path = file_path
            self.lbl_bin_file.config(text=f"{os.path.basename(file_path)} ({os.path.getsize(file_path)} байт)", foreground="black")

    def bin_process(self, is_encrypt: bool):
        if not self.selected_bin_path:
            messagebox.showwarning("Увага", "Будь ласка, спочатку оберіть файл.")
            return

        raw_key = self.bin_key_entry.get().strip()
        if not self.binary_cipher.validate_key(raw_key):
            messagebox.showerror("Помилка", "Ключ має бути цілим числом.")
            return

        save_path = filedialog.asksaveasfilename(
            title="Зберегти оброблений файл як...",
            initialfile=("enc_" if is_encrypt else "dec_") + os.path.basename(self.selected_bin_path),
        )
        if not save_path:
            return

        try:
            with open(self.selected_bin_path, "rb") as fin:
                data = fin.read()

            if is_encrypt:
                res_data = self.binary_cipher.encrypt(data, raw_key)
            else:
                res_data = self.binary_cipher.decrypt(data, raw_key)

            with open(save_path, "wb") as fout:
                fout.write(res_data)

            messagebox.showinfo("Успіх", f"Файл успішно збережено в:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося обробити файл:\n{e}")

    def _build_bf_tab(self):
        f = ttk.Frame(self.tab_bf, padding=8)
        f.pack(fill=tk.BOTH, expand=True)

        top_bar = ttk.Frame(f)
        top_bar.pack(fill=tk.X, pady=4)

        ttk.Label(top_bar, text="Мова шифротексту:").pack(side=tk.LEFT, padx=4)
        self.bf_lang_var = tk.StringVar(value="uk")
        ttk.Combobox(
            top_bar,
            textvariable=self.bf_lang_var,
            values=["uk", "en", "auto"],
            state="readonly",
            width=10,
        ).pack(side=tk.LEFT, padx=4)

        ttk.Button(top_bar, text="💥 Запустити Brute-Force", command=self.run_brute_force).pack(side=tk.LEFT, padx=10)

        ttk.Label(f, text="Зашифрований текст:").pack(anchor=tk.W, pady=2)
        self.bf_input = tk.Text(f, height=5, wrap=tk.WORD, font=("Consolas", 10))
        self.bf_input.insert("1.0", "Фхлєле, Фєлўз! 123 (з ґ, є, і, ї)")
        self.bf_input.pack(fill=tk.X, pady=4)

        ttk.Label(f, text="Результати перебору (ранжовані):").pack(anchor=tk.W, pady=2)

        tree_frame = ttk.Frame(f)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("key", "score", "text"),
            show="headings",
            selectmode="browse",
        )
        self.tree.heading("key", text="Ключ (k)")
        self.tree.heading("score", text="Оцінка (Score)")
        self.tree.heading("text", text="Розшифрований текст")

        self.tree.column("key", width=70, anchor=tk.CENTER)
        self.tree.column("score", width=90, anchor=tk.CENTER)
        self.tree.column("text", width=600, anchor=tk.W)

        scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def run_brute_force(self):
        text = self.bf_input.get("1.0", tk.END).rstrip("\n")
        if not text.strip():
            messagebox.showwarning("Увага", "Введіть шифротекст для зламу.")
            return

        lang = self.bf_lang_var.get()
        for row in self.tree.get_children():
            self.tree.delete(row)

        try:
            results = self.brute_force.attack(text, lang=lang)
            for key, dec_text, score in results:
                self.tree.insert("", tk.END, values=(key, f"{score:.3f}", dec_text))
            if results:
                messagebox.showinfo("Готово", f"Перебір завершено! Знайдено варіантів: {len(results)}.\nНайбільш імовірний ключ: k = {results[0][0]}")
        except Exception as e:
            messagebox.showerror("Помилка Brute-Force", str(e))

    def file_new(self):
        self.txt_input.delete("1.0", tk.END)
        self.txt_output.delete("1.0", tk.END)

    def file_open(self):
        path = filedialog.askopenfilename(
            title="Відкрити текстовий файл",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")],
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.txt_input.delete("1.0", tk.END)
                self.txt_input.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("Помилка відкриття", f"Не вдалося прочитати файл:\n{e}")

    def file_save(self):
        content = self.txt_output.get("1.0", tk.END).rstrip("\n")
        if not content:
            content = self.txt_input.get("1.0", tk.END).rstrip("\n")

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
        content = self.txt_output.get("1.0", tk.END).strip() or self.txt_input.get("1.0", tk.END).strip()
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
            "Комп'ютерний практикум №1: «Шифр Цезаря»\n"
            "Дисципліна: Безпека програмного забезпечення\n\n"
            "Функції системи:\n"
            "• Шифрування та розшифрування тексту (UA, EN)\n"
            "• Операції з файлами: створення, відкривання, збереження, друк\n"
            "• Шифрування двійкових файлів будь-якого формату (mod 256)\n"
            "• Модуль атаки методом грубої сили (Brute-Force)\n\n"
        )


if __name__ == "__main__":
    app = CaesarApp()
    app.mainloop()
