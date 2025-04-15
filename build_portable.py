#!/usr/bin/env python3
"""
Script para generar una versión portable de DiarioSeguro utilizando PyInstaller.
"""
import os
import platform
import subprocess
import shutil

def build_portable():
    # Asegurarse de que PyInstaller está instalado
    try:
        subprocess.run(["pip", "install", "pyinstaller"], check=True)
        print("PyInstaller instalado correctamente.")
    except subprocess.CalledProcessError:
        print("Error al instalar PyInstaller.")
        return

    # Determinar el sistema operativo
    sistema = platform.system()
    print(f"Construyendo para sistema: {sistema}")
    
    # Definir opciones específicas según el sistema operativo
    if sistema == "Windows":
        icono = "--icon=logo.ico"
        nombre_salida = "DiarioSeguro.exe"
    elif sistema == "Darwin":  # macOS
        icono = "--icon=logo.icns"
        nombre_salida = "DiarioSeguro"
    else:  # Linux
        icono = ""
        nombre_salida = "DiarioSeguro"
    
    # Crear directorio para archivos adicionales si no existe
    os.makedirs("dist/data", exist_ok=True)
    
    # Comando para PyInstaller
    comando = [
        "pyinstaller",
        "--onefile",
        "--windowed",
        f"--name={nombre_salida}",
        "--add-data=logo.png:.",
        "--hidden-import=tkinter",
        "--clean",
        "src/main.py"
    ]
    
    # Añadir el icono si está disponible
    if os.path.exists(icono.split("=")[1]):
        comando.append(icono)
    
    # Ejecutar PyInstaller
    try:
        subprocess.run(comando, check=True)
        print("Compilación completada con éxito.")
        
        # Crear archivo README para la versión portable
        with open("dist/LEEME.txt", "w", encoding="utf-8") as f:
            f.write("""DiarioSeguro - Versión Portable

Instrucciones de uso:
1. Ejecuta el archivo DiarioSeguro
2. Tus datos se guardarán en la carpeta 'data' junto al ejecutable
3. Para hacer copias de seguridad, guarda toda la carpeta

¡Disfruta de tu diario seguro!
""")
        
        print("Aplicación portable creada en la carpeta 'dist'")
    except subprocess.CalledProcessError:
        print("Error al generar el ejecutable.")

if __name__ == "__main__":
    build_portable() 