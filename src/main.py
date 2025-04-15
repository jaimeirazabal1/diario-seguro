import os
import sys
import hashlib
import json
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import tkinter as tk
from tkinter import ttk, messagebox, Text, scrolledtext

class DiarioSeguro:
    def __init__(self, root):
        self.root = root
        self.root.title("Diario Seguro")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Detectar si estamos en modo portable (PyInstaller) o en modo desarrollo
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            # Estamos en una aplicación empaquetada
            base_path = os.path.dirname(sys.executable)
            self.data_dir = os.path.join(base_path, "data")
        else:
            # Estamos en modo desarrollo
            self.data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
        
        os.makedirs(self.data_dir, exist_ok=True)
        
        self.config_file = os.path.join(self.data_dir, "config.json")
        self.diary_file = os.path.join(self.data_dir, "diario.enc")
        
        self.key = None
        self.entries = {}
        
        self.setup_ui()
        
        # Verificar si el usuario ya se ha registrado
        if os.path.exists(self.config_file):
            self.show_login_frame()
        else:
            self.show_register_frame()
    
    def setup_ui(self):
        # Frame para registro
        self.register_frame = ttk.Frame(self.root, padding="20")
        ttk.Label(self.register_frame, text="Crear Contraseña Nueva", font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=10)
        ttk.Label(self.register_frame, text="Contraseña:").grid(row=1, column=0, sticky="w", pady=5)
        self.reg_password = ttk.Entry(self.register_frame, show="*", width=30)
        self.reg_password.grid(row=1, column=1, pady=5)
        
        ttk.Label(self.register_frame, text="Confirmar Contraseña:").grid(row=2, column=0, sticky="w", pady=5)
        self.reg_confirm = ttk.Entry(self.register_frame, show="*", width=30)
        self.reg_confirm.grid(row=2, column=1, pady=5)
        
        ttk.Button(self.register_frame, text="Registrar", command=self.register).grid(row=3, column=0, columnspan=2, pady=20)
        
        # Frame para login
        self.login_frame = ttk.Frame(self.root, padding="20")
        ttk.Label(self.login_frame, text="Iniciar Sesión", font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=10)
        ttk.Label(self.login_frame, text="Contraseña:").grid(row=1, column=0, sticky="w", pady=5)
        self.login_password = ttk.Entry(self.login_frame, show="*", width=30)
        self.login_password.grid(row=1, column=1, pady=5)
        
        ttk.Button(self.login_frame, text="Entrar", command=self.login).grid(row=2, column=0, columnspan=2, pady=20)
        
        # Frame para el diario
        self.diary_frame = ttk.Frame(self.root, padding="20")
        
        # Sección superior - Títulos y fechas
        top_frame = ttk.Frame(self.diary_frame)
        top_frame.pack(fill="x", pady=10)
        
        ttk.Label(top_frame, text="Mi Diario Seguro", font=("Arial", 16, "bold")).pack(side="left")
        ttk.Button(top_frame, text="Cerrar Sesión", command=self.logout).pack(side="right")
        ttk.Button(top_frame, text="Guardar", command=self.save_entry).pack(side="right", padx=10)
        
        # Sección media - Lista de entradas
        mid_frame = ttk.Frame(self.diary_frame)
        mid_frame.pack(fill="both", expand=True, pady=10)
        
        list_frame = ttk.Frame(mid_frame, width=200)
        list_frame.pack(side="left", fill="y", padx=(0, 10))
        
        ttk.Label(list_frame, text="Mis Entradas", font=("Arial", 12, "bold")).pack(anchor="w", pady=(0, 5))
        
        self.entries_listbox = tk.Listbox(list_frame, width=25, height=20)
        self.entries_listbox.pack(fill="both", expand=True)
        self.entries_listbox.bind("<<ListboxSelect>>", self.load_selected_entry)
        
        ttk.Button(list_frame, text="Nueva Entrada", command=self.new_entry).pack(fill="x", pady=(10, 0))
        
        # Sección de edición
        edit_frame = ttk.Frame(mid_frame)
        edit_frame.pack(side="right", fill="both", expand=True)
        
        ttk.Label(edit_frame, text="Título:").pack(anchor="w")
        self.entry_title = ttk.Entry(edit_frame, width=50)
        self.entry_title.pack(fill="x", pady=(0, 10))
        
        ttk.Label(edit_frame, text="Contenido:").pack(anchor="w")
        self.entry_content = scrolledtext.ScrolledText(edit_frame, height=15, wrap=tk.WORD)
        self.entry_content.pack(fill="both", expand=True)
        
        self.current_date = None
    
    def show_register_frame(self):
        self.login_frame.grid_forget() if hasattr(self, 'login_frame') else None
        self.diary_frame.pack_forget() if hasattr(self, 'diary_frame') else None
        self.register_frame.grid(row=0, column=0, padx=50, pady=50)
    
    def show_login_frame(self):
        self.register_frame.grid_forget() if hasattr(self, 'register_frame') else None
        self.diary_frame.pack_forget() if hasattr(self, 'diary_frame') else None
        self.login_frame.grid(row=0, column=0, padx=50, pady=50)
        self.login_password.focus()
    
    def show_diary_frame(self):
        self.register_frame.grid_forget() if hasattr(self, 'register_frame') else None
        self.login_frame.grid_forget() if hasattr(self, 'login_frame') else None
        self.diary_frame.pack(fill="both", expand=True)
        self.load_entries()
    
    def derive_key(self, password, salt=None):
        if not salt:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def register(self):
        password = self.reg_password.get()
        confirm = self.reg_confirm.get()
        
        if not password:
            messagebox.showerror("Error", "La contraseña no puede estar vacía")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return
        
        # Generar salt y key
        salt = os.urandom(16)
        key, _ = self.derive_key(password, salt)
        
        # Guardar configuración
        config = {
            "salt": base64.b64encode(salt).decode(),
            "password_hash": hashlib.sha256(password.encode()).hexdigest()
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(config, f)
        
        self.key = key
        self.show_diary_frame()
        messagebox.showinfo("Éxito", "Usuario registrado correctamente")
    
    def login(self):
        password = self.login_password.get()
        
        if not os.path.exists(self.config_file):
            messagebox.showerror("Error", "No se ha configurado ningún usuario")
            return
        
        with open(self.config_file, 'r') as f:
            config = json.load(f)
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if password_hash != config["password_hash"]:
            messagebox.showerror("Error", "Contraseña incorrecta")
            return
        
        salt = base64.b64decode(config["salt"])
        key, _ = self.derive_key(password, salt)
        self.key = key
        
        self.show_diary_frame()
    
    def logout(self):
        self.key = None
        self.entries = {}
        self.show_login_frame()
    
    def encrypt_data(self, data):
        cipher = Fernet(self.key)
        return cipher.encrypt(data.encode())
    
    def decrypt_data(self, data):
        cipher = Fernet(self.key)
        return cipher.decrypt(data).decode()
    
    def load_entries(self):
        self.entries_listbox.delete(0, tk.END)
        
        if not os.path.exists(self.diary_file):
            return
        
        try:
            with open(self.diary_file, 'rb') as f:
                encrypted_data = f.read()
                
            if encrypted_data:
                decrypted_data = self.decrypt_data(encrypted_data)
                self.entries = json.loads(decrypted_data)
                
                # Ordenar entradas por fecha (más reciente primero)
                sorted_dates = sorted(self.entries.keys(), reverse=True)
                
                for date in sorted_dates:
                    entry = self.entries[date]
                    self.entries_listbox.insert(tk.END, f"{date} - {entry['title']}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudieron cargar las entradas: {str(e)}")
    
    def load_selected_entry(self, event):
        selection = self.entries_listbox.curselection()
        if not selection:
            return
        
        index = selection[0]
        date_title = self.entries_listbox.get(index)
        date = date_title.split(" - ")[0]
        
        if date in self.entries:
            entry = self.entries[date]
            self.entry_title.delete(0, tk.END)
            self.entry_title.insert(0, entry["title"])
            
            self.entry_content.delete(1.0, tk.END)
            self.entry_content.insert(tk.END, entry["content"])
            
            self.current_date = date
    
    def new_entry(self):
        self.current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.entry_title.delete(0, tk.END)
        self.entry_content.delete(1.0, tk.END)
    
    def save_entry(self):
        title = self.entry_title.get()
        content = self.entry_content.get(1.0, tk.END).strip()
        
        if not title:
            messagebox.showerror("Error", "El título no puede estar vacío")
            return
        
        if not content:
            messagebox.showerror("Error", "El contenido no puede estar vacío")
            return
        
        if not self.current_date:
            self.current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        self.entries[self.current_date] = {
            "title": title,
            "content": content
        }
        
        # Guardar en archivo
        try:
            json_data = json.dumps(self.entries)
            encrypted_data = self.encrypt_data(json_data)
            
            with open(self.diary_file, 'wb') as f:
                f.write(encrypted_data)
            
            messagebox.showinfo("Éxito", "Entrada guardada correctamente")
            self.load_entries()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar la entrada: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = DiarioSeguro(root)
    root.mainloop() 