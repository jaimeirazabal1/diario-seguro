# DiarioSeguro / Secure Diary

[English](#english) | [Español](#español)

![DiarioSeguro Logo](https://via.placeholder.com/150)

---

<a name="english"></a>
## 🇬🇧 English

A secure personal diary application with encryption that protects your entries with a password.

### Features

- Password protection to access your diary
- Encryption of all entries using advanced cryptography
- Easy-to-use graphical interface
- Local storage (your data never leaves your computer)
- Chronological organization of entries

### Requirements

- Python 3.7 or higher
- Required packages:
  - cryptography
  - tkinter (included in most Python installations)

### Installation

1. Clone or download this repository
2. Install dependencies:

```
pip install cryptography
```

### Usage

1. Run the application:

```
python src/main.py
```

2. On first use, create a secure password
3. Log in with your password
4. Create and edit entries in your diary

### Security

- All entries are encrypted using Fernet (AES-128 implementation)
- The password is never stored directly, only its hash
- PBKDF2 with 100,000 iterations is used to derive the encryption key

### Warning

Don't forget your password. If you lose it, there is no way to recover your diary entries as they are encrypted.

---

<a name="español"></a>
## 🇪🇸 Español

Una aplicación de diario personal segura con cifrado que protege tus entradas con contraseña.

### Características

- Protección por contraseña para acceder a tu diario
- Cifrado de todas las entradas usando criptografía avanzada
- Interfaz gráfica fácil de usar
- Almacenamiento local (tus datos nunca salen de tu computadora)
- Organización cronológica de entradas

### Requisitos

- Python 3.7 o superior
- Paquetes requeridos:
  - cryptography
  - tkinter (incluido en la mayoría de instalaciones de Python)

### Instalación

1. Clona o descarga este repositorio
2. Instala las dependencias:

```
pip install cryptography
```

### Uso

1. Ejecuta la aplicación:

```
python src/main.py
```

2. En el primer uso, crea una contraseña segura
3. Inicia sesión con tu contraseña
4. Crea y edita entradas en tu diario

### Seguridad

- Todas las entradas se cifran usando Fernet (implementación de AES-128)
- La contraseña nunca se almacena directamente, solo su hash
- Se usa PBKDF2 con 100,000 iteraciones para derivar la clave de cifrado

### Advertencia

No olvides tu contraseña. Si la pierdes, no hay forma de recuperar tus entradas del diario ya que están cifradas. 