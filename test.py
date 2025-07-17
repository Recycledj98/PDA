# -*- coding: utf-8 -*-

# MIT License
#
# Copyright (c) 2025 Catalin Andrei Sonca Dobinciuc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import os
import sys
import ctypes
import ftplib
import subprocess
import requests
import shutil
import textwrap
import time

# --- CONFIGURACIÓN ---
FTP_SERVERS = ["192.168.2.10", "webconsulting.tvoipadsl.com"]
FTP_USER = "catalin"
FTP_PASS = "1024"
REMOTE_PROGRAMS_FTP_PATH = "/utilidades/Programas"

# Rutas locales (construidas con os.path.join para evitar errores)
LOCAL_TARGET_FOLDER = os.path.join("C:", os.sep, "POCKET")
UTILS_FOLDER = os.path.join("C:", os.sep, "Utils")
TEMP_DIR = os.environ.get('TEMP', os.path.join("C:", os.sep, "Windows", "Temp"))
TEMP_DOWNLOAD_FOLDER = os.path.join(TEMP_DIR, "POCKET_FTP_DOWNLOAD")

# URLs de respaldo y utilidades
TEAMVIEWER_URL = "https://download.teamviewer.com/download/version_11x/TeamViewer_Setup.exe"
ANYDESK_URL = "https://download.anydesk.com/AnyDesk.exe"
SEVENZIP_URL = "https://www.7-zip.org/a/7z2406-x64.exe"
DROPBOX_URL = "https://www.dropbox.com/download?plat=win&type=full"
WINGET_URL = "https://github.com/microsoft/winget-cli/releases/download/v1.7.11132/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
VCLIBS_URL = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"

# Rutas de instaladores temporales
TEAMVIEWER_INSTALLER_PATH = os.path.join(TEMP_DIR, "TeamViewer_11_Setup.exe")
ANYDESK_INSTALLER_PATH = os.path.join(TEMP_DIR, "AnyDesk_Setup.exe")
SEVENZIP_INSTALLER_PATH = os.path.join(TEMP_DIR, "7zip_Setup.exe")
WINGET_INSTALLER_PATH = os.path.join(TEMP_DIR, "Microsoft.DesktopAppInstaller.msixbundle")
VCLIBS_INSTALLER_PATH = os.path.join(TEMP_DIR, "Microsoft.VCLibs.appx")

# Contraseña y licencia
REMOTE_ACCESS_PASSWORD = "Megas_1024"
PDA_LICENSE_KEY = "*PDA*1024*"
# --- FIN DE LA CONFIGURACIÓN ---

progress_tracker = {'downloaded': 0, 'total': 0}

def is_admin():
    """Comprueba si el script se está ejecutando con privilegios de administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_command(command, message):
    """Ejecuta un comando en el shell y muestra un mensaje."""
    print(f"-> {message}")
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, startupinfo=startupinfo
        )
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            print(f"   [OK] {message} completado.")
            return True
        else:
            if "La regla ya existe" in stdout or "Rule already exists" in stderr:
                print(f"   [AVISO] La regla de firewall ya existe.")
                return True
            print(f"   [ERROR] Hubo un problema durante: {message}.")
            if stderr: print(f"   Detalles: {stderr.strip()}")
            return False
    except Exception as e:
        print(f"   [ERROR CRÍTICO] No se pudo ejecutar el comando para '{message}'. Razón: {e}")
        return False

def download_file(url, local_path, file_name):
    """Descarga un archivo desde una URL a una ruta local."""
    print(f"-> Descargando {file_name}...")
    try:
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"   [OK] {file_name} descargado con éxito.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"   [ERROR] No se pudo descargar {file_name}. Razón: {e}")
        return False

def ensure_winget_is_installed():
    """Verifica si Winget está instalado y, si no, lo descarga e instala de forma robusta."""
    print("-> Verificando si Winget está disponible...")
    if shutil.which("winget"):
        print("   [OK] Winget ya está instalado.")
        return True

    print("   [AVISO] Winget no encontrado. Intentando instalación manual...")

    # --- Paso 1: Descargar e instalar la dependencia VCLibs ---
    print("   -> Descargando la dependencia (Microsoft.VCLibs)...")
    if not download_file(VCLIBS_URL, VCLIBS_INSTALLER_PATH, "Microsoft.VCLibs"):
        print("   [ERROR CRÍTICO] No se pudo descargar la dependencia VCLibs. Se cancela la instalación de Winget.")
        return False

    print("   -> Instalando la dependencia (Microsoft.VCLibs)...")
    command_vclibs = f'powershell -Command "Add-AppxPackage -Path \\"{VCLIBS_INSTALLER_PATH}\\""'
    if not run_command(command_vclibs, "Ejecutando instalador de VCLibs..."):
        print("   [ERROR CRÍTICO] No se pudo instalar la dependencia VCLibs. Winget podría no funcionar.")
        # No retornamos False aquí para que intente instalar Winget de todas formas

    try:
        os.remove(VCLIBS_INSTALLER_PATH)
    except OSError:
        pass # El fichero podría no existir si la descarga falló
    print("   [OK] Dependencia VCLibs instalada correctamente.")


    # --- Paso 2: Descargar e instalar Winget ---
    print("\n   -> Descargando Winget (Microsoft.DesktopAppInstaller)...")
    if not download_file(WINGET_URL, WINGET_INSTALLER_PATH, "Winget"):
        print("   [ERROR CRÍTICO] No se pudo descargar Winget.")
        return False

    print("   -> Instalando Winget...")
    command_winget = f'powershell -Command "Add-AppxPackage -Path \\"{WINGET_INSTALLER_PATH}\\" -ForceApplicationShutdown"'
    if not run_command(command_winget, "Ejecutando instalador de Winget..."):
        print("   [ERROR CRÍTICO] Fallo en la instalación de Winget.")
        return False

    try:
        os.remove(WINGET_INSTALLER_PATH)
    except OSError:
        pass

    # --- Paso 3: Verificar la instalación ---
    print("   -> Verificando la instalación final de Winget...")
    time.sleep(5)
    if shutil.which("winget"):
        print("   [OK] Verificación completada. Winget está listo para usarse.")
        return True
    else:
        print("   [ERROR CRÍTICO] Winget se instaló pero no se encuentra en la ruta del sistema.")
        return False

def print_progress(downloaded, total):
    if total == 0: return
    bar_length = 50
    percent = downloaded / total
    filled_length = int(bar_length * percent)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    downloaded_mb = downloaded / (1024 * 1024)
    total_mb = total / (1024 * 1024)
    sys.stdout.write(f'\r   Descargando: |{bar}| {percent:.1%} ({downloaded_mb:.2f}/{total_mb:.2f} MB)')
    sys.stdout.flush()

def get_total_size(ftp, path):
    total_size = 0
    try:
        items = ftp.mlsd(path)
        for name, facts in items:
            if name in ['.', '..']: continue
            item_path = f"{path}/{name}"
            if facts['type'] == 'dir':
                total_size += get_total_size(ftp, item_path)
            elif facts['type'] == 'file':
                total_size += int(facts.get('size', 0))
    except Exception:
        # Fallback para servidores FTP que no soportan MLSD
        for item_name in ftp.nlst(path):
            item_path = f"{path}/{os.path.basename(item_name)}"
            try:
                ftp.cwd(item_path)
                total_size += get_total_size(ftp, item_path)
                ftp.cwd(path)
            except ftplib.error_perm:
                total_size += ftp.size(item_path)
    return total_size

def download_ftp_folder(ftp, remote_path, local_path):
    os.makedirs(local_path, exist_ok=True)
    items = ftp.mlsd(remote_path)
    for name, facts in items:
        if name in ['.', '..']: continue
        local_item_path = os.path.join(local_path, name)
        remote_item_path = f"{remote_path}/{name}"
        if facts['type'] == 'dir':
            download_ftp_folder(ftp, remote_item_path, local_item_path)
        elif facts['type'] == 'file':
            with open(local_item_path, 'wb') as f:
                def handle_chunk_and_write(chunk):
                    f.write(chunk)
                    progress_tracker['downloaded'] += len(chunk)
                    print_progress(progress_tracker['downloaded'], progress_tracker['total'])
                # Usamos un callback para la barra de progreso solo si tenemos el tamaño total
                callback = handle_chunk_and_write if progress_tracker.get('total', 0) > 0 else f.write
                ftp.retrbinary(f"RETR {remote_item_path}", callback)

def create_shortcut(shortcut_name, target_path, working_directory="", arguments=""):
    """Crea un acceso directo genérico en el escritorio."""
    print(f"-> Creando acceso directo '{shortcut_name}' en el escritorio...")
    try:
        desktop_path = os.path.join(os.environ['USERPROFILE'], 'Desktop')
        shortcut_path = os.path.join(desktop_path, f'{shortcut_name}.lnk')

        if not os.path.exists(target_path):
            print(f"   [ERROR] El objetivo '{target_path}' no existe. No se puede crear el acceso directo.")
            return

        target_path_vbs = os.path.abspath(target_path)
        working_directory_vbs = os.path.abspath(working_directory) if working_directory else os.path.dirname(target_path_vbs)

        vbs_script_path = os.path.join(TEMP_DIR, 'create_shortcut.vbs')
        vbs_script_content = textwrap.dedent(f"""
            Set oWS = WScript.CreateObject("WScript.Shell")
            sLinkFile = "{shortcut_path}"
            Set oLink = oWS.CreateShortcut(sLinkFile)
            oLink.TargetPath = "{target_path_vbs}"
            oLink.Arguments = "{arguments}"
            oLink.WorkingDirectory = "{working_directory_vbs}"
            oLink.Save
        """)
        with open(vbs_script_path, 'w', encoding='utf-8') as f: f.write(vbs_script_content)

        subprocess.run(['cscript', '//nologo', vbs_script_path], check=True, capture_output=True)
        os.remove(vbs_script_path)
        print(f"   [OK] Acceso directo '{shortcut_name}' creado con éxito.")
    except Exception as e:
        print(f"   [ERROR] No se pudo crear el acceso directo '{shortcut_name}'. Razón: {e}")

def add_firewall_rules():
    programs_to_allow = [
        ("Permitir FTP Client (Instalador)", os.path.join(os.environ['SystemRoot'], 'System32', 'ftp.exe')),
        ("Permitir POCKET GC_1", os.path.join(LOCAL_TARGET_FOLDER, "GC_1.EXE")),
        ("Permitir POCKET GCWUPDAT", os.path.join(LOCAL_TARGET_FOLDER, "GCWUPDAT.EXE"))
    ]
    for rule_name, program_path in programs_to_allow:
        if not os.path.exists(program_path):
            print(f"   [AVISO] No se encontró '{program_path}'. No se creará la regla de firewall.")
            continue
        command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=allow program="{program_path}" enable=yes profile=private,public'
        run_command(command, f"Añadiendo regla para {os.path.basename(program_path)}...")

def enter_license_key():
    print("-> Introduciendo la licencia en la aplicación PDA...")
    try:
        target_path = os.path.join(LOCAL_TARGET_FOLDER, "GC_1.EXE")
        if not os.path.exists(target_path):
            print(f"   [ERROR] No se encontró '{target_path}'. No se puede introducir la licencia.")
            return
        vbs_script_path = os.path.join(TEMP_DIR, 'enter_license.vbs')
        vbs_script_content = textwrap.dedent(f"""
            Set WshShell = WScript.CreateObject("WScript.Shell")
            WScript.Sleep 40000
            WshShell.SendKeys "{PDA_LICENSE_KEY}"
            WScript.Sleep 500
            WshShell.SendKeys "{{ENTER}}"
        """)
        with open(vbs_script_path, 'w', encoding='utf-8') as f: f.write(vbs_script_content)
        print("   Lanzando la aplicación...")
        subprocess.Popen([target_path, "PDA"], cwd=LOCAL_TARGET_FOLDER)
        print("   Enviando pulsaciones de teclas para la licencia (en segundo plano)...")
        subprocess.run(['cscript', '//nologo', vbs_script_path], check=True, capture_output=True)
        os.remove(vbs_script_path)
        print("   [OK] Proceso de introducción de licencia completado.")
    except Exception as e:
        print(f"   [ERROR] No se pudo completar el proceso de licencia. Razón: {e}")

def download_and_setup_utils(ftp):
    print("-> Creando directorio C:/Utils...")
    os.makedirs(UTILS_FOLDER, exist_ok=True)
    folders_to_download = ["Office24", "SM300"]
    for folder in folders_to_download:
        remote_path = f"{REMOTE_PROGRAMS_FTP_PATH}/{folder}"
        local_path = os.path.join(UTILS_FOLDER, folder)
        progress_tracker.update({'downloaded': 0, 'total': 0})
        try:
            progress_tracker['total'] = get_total_size(ftp, remote_path)
            print(f"-> Descargando '{folder}' ({progress_tracker['total'] / (1024*1024):.2f} MB)...")
            download_ftp_folder(ftp, remote_path, local_path)
            sys.stdout.write('\n')
            print(f"   [OK] Carpeta '{folder}' descargada.")
        except Exception as e:
            print(f"\n   [ERROR] No se pudo descargar la carpeta '{folder}'. Razón: {e}")
    bixolon_zip_path = os.path.join(UTILS_FOLDER, "BIXOLON.ZIP")
    remote_bixolon_path = f"{REMOTE_PROGRAMS_FTP_PATH}/BIXOLON.ZIP"
    try:
        print("-> Descargando BIXOLON.ZIP...")
        with open(bixolon_zip_path, 'wb') as f: ftp.retrbinary(f"RETR {remote_bixolon_path}", f.write)
        program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
        seven_zip_exe = os.path.join(program_files, "7-Zip", "7z.exe")
        if os.path.exists(seven_zip_exe):
            command = f'"{seven_zip_exe}" x "{bixolon_zip_path}" -o"{UTILS_FOLDER}" -y'
            if run_command(command, "Descomprimiendo BIXOLON.ZIP..."):
                os.remove(bixolon_zip_path)
        else:
            print(f"   [ERROR] No se encontró 7-Zip. No se pudo descomprimir BIXOLON.ZIP.")
    except Exception as e:
        print(f"   [ERROR] No se pudo procesar BIXOLON.ZIP. Razón: {e}")
    download_file(DROPBOX_URL, os.path.join(UTILS_FOLDER, "DropboxInstaller.exe"), "Instalador de Dropbox")

# --- CAMBIO DE IDIOMA (CORREGIDO) ---
def run_cambio_idioma():
    # El código del script de PowerShell ahora está correctamente indentado dentro de la función.
    script_powershell = r'''
# Comprobar permisos de administrador
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "ERROR: Se requieren permisos de administrador." -ForegroundColor Red
    Exit 1
}

# Definir etiqueta de idioma
$langTag = "es-ES"
$geoIdSpain = 217  # GeoID decimal para España (0xD9)

# Paso 1: Instalar paquete de idioma si no está instalado
Write-Host "Paso 1: Instalando paquete de idioma $langTag si es necesario..."
try {
    # Intentar usar Install-Language (Windows 10/11 modernos)
    $installed = Get-InstalledLanguage -ErrorAction Stop | Where-Object Language -EQ $langTag
    if (-not $installed) {
        Write-Host "-> Paquete $langTag no encontrado. Instalando con Install-Language..."
        Install-Language -Language $langTag -CopyToSettings -ErrorAction Stop
        Write-Host "-> Paquete de idioma $langTag instalado correctamente (requiere reinicio para aplicar cambios)."
    } else {
        Write-Host "-> Paquete de idioma $langTag ya está instalado."
    }
}
catch {
    Write-Host "-> No se pudo usar Install-Language (o no está disponible). Intentando DISM..." -ForegroundColor Yellow
    # Comprobar con DISM / Add-WindowsCapability
    $cap = Get-WindowsCapability -Online | Where-Object { $_.Name -like "*Language.Basic~~~$langTag*" }
    if ($cap -and $cap.State -ne "Installed") {
        Write-Host "-> Paquete $langTag no instalado. Instalando con DISM..."
        Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop
        Write-Host "-> Paquete de idioma $langTag instalado con DISM."
    } else {
        Write-Host "-> Paquete de idioma $langTag ya está instalado (Estado DISM: $($cap.State))."
    }
}

# Paso 2: Configurar idioma de usuario y sistema
Write-Host "Paso 2: Configurando idioma de usuario y del sistema a $langTag..."
# Idioma del usuario
$currList = Get-WinUserLanguageList
if ($currList.Count -eq 1 -and $currList[0].LanguageTag -eq $langTag) {
    Write-Host "-> El idioma de usuario ya es $langTag. Se omite Set-WinUserLanguageList."
} else {
    Write-Host "-> Estableciendo lista de idioma de usuario a $langTag..."
    $newList = New-WinUserLanguageList $langTag
    Set-WinUserLanguageList $newList -Force
    Write-Host "-> Idioma de usuario fijado a $langTag."
}
# Idioma de interfaz (UI) actual
Write-Host "-> Estableciendo idioma de interfaz de Windows a $langTag para el usuario actual..."
Set-WinUILanguageOverride -Language $langTag
# Configuración regional del sistema
Write-Host "-> Estableciendo configuración regional del sistema a $langTag..."
Set-WinSystemLocale $langTag

# Paso 3: Configurar cultura y ubicación geográfica
Write-Host "Paso 3: Configurando cultura y formato regional a $langTag..."
# Cultura del usuario (número, fecha, moneda, etc.)
Write-Host "-> Estableciendo cultura (formato regional) del usuario a $langTag..."
Set-Culture $langTag
# Ubicación geográfica del usuario
Write-Host "-> Estableciendo ubicación geográfica del usuario a GeoID $geoIdSpain (España)..."
Set-WinHomeLocation -GeoId $geoIdSpain

# Paso 4: Aplicar idioma a bienvenida y nuevas cuentas
Write-Host "Paso 4: Aplicando configuración al perfil predeterminado y pantalla de bienvenida..."
if (Get-Command Copy-UserInternationalSettingsToSystem -ErrorAction SilentlyContinue) {
    Write-Host "-> Cmdlet disponible. Copiando ajustes al welcome screen y nuevos usuarios..."
    Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true
    Write-Host "-> Configuración de idioma propagada al welcome screen y nuevos usuarios."
} else {
    Write-Host "-> Cmdlet no disponible. Actualizando registro para forzar idioma predeterminado..."
    # Establecer registros InstallLanguage y Default a 0c0a (LCID de es-ES)
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls" -Name "Language" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name "InstallLanguage" -Value "0c0a" -Type String
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name "Default"         -Value "0c0a" -Type String
    Write-Host "-> Registro del idioma predeterminado actualizado a es-ES (0c0a)."
}

Write-Host "\n\n¡Configuración de idioma y región completada correctamente!" -ForegroundColor Green
'''

    # Guardar script PowerShell temporalmente
    ps1_path = os.path.join(os.getenv("TEMP"), "cambiar_idioma_es.ps1")
    with open(ps1_path, "w", encoding="utf-8") as f:
        f.write(script_powershell)

    # Ejecutar el script
    print("Ejecutando cambio de idioma y configuración regional...")
    try:
        subprocess.run([
            "powershell.exe",
            "-ExecutionPolicy", "Bypass",
            "-File", ps1_path
        ], check=True)
        print("\nProceso completado. Puede que se requiera reiniciar el sistema.")
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] El script de PowerShell falló: {e}")
    finally:
        # Limpiar el fichero temporal
        if os.path.exists(ps1_path):
            os.remove(ps1_path)

def main():

    # CABECERA CMD

    print("\033[1;36m" + "="*60)
    print("             INSTALADOR DE MEGAS PDA DESATENDIDO VER 1.0.0.2")
    print("="*60 + "\033[0m")
    print("\033[1;33m© 2025 Catalin Andrei Sonca Dobinciuc\033[0m\n")


    total_steps = 10
    ftp_connection = None
    for server in FTP_SERVERS:
        try:
            print(f"-> Intentando conectar a: {server}...")
            ftp = ftplib.FTP(server, timeout=10)
            ftp.login(user=FTP_USER, passwd=FTP_PASS)
            ftp.set_pasv(True)
            print(f"   [OK] Conexión FTP establecida con {server}.")
            ftp_connection = ftp
            break
        except Exception as e:
            print(f"\n   [AVISO] Fallo al conectar a {server}. Razón: {e}")
    if not ftp_connection:
        print("[ERROR CRÍTICO] No se pudo conectar a ningún servidor FTP.")
        sys.exit(1)

    with ftp_connection as ftp:
        print(f"\n[Paso 1 de {total_steps}] Descargando carpeta 'POCKET'...")
        try:
            remote_pocket_path = f"{REMOTE_PROGRAMS_FTP_PATH}/POCKET"
            progress_tracker.update({'downloaded': 0, 'total': 0})
            progress_tracker['total'] = get_total_size(ftp, remote_pocket_path)
            print(f"   Tamaño total: {progress_tracker['total'] / (1024*1024):.2f} MB")
            if os.path.exists(TEMP_DOWNLOAD_FOLDER): shutil.rmtree(TEMP_DOWNLOAD_FOLDER)
            download_ftp_folder(ftp, remote_pocket_path, TEMP_DOWNLOAD_FOLDER)
            sys.stdout.write('\n')
            if os.path.exists(LOCAL_TARGET_FOLDER): shutil.rmtree(LOCAL_TARGET_FOLDER)
            shutil.move(TEMP_DOWNLOAD_FOLDER, LOCAL_TARGET_FOLDER)
            print(f"   [OK] Carpeta 'POCKET' descargada y movida a {LOCAL_TARGET_FOLDER}")
        except Exception as e:
            print(f"\n[ERROR CRÍTICO] No se pudo descargar la carpeta POCKET. Razón: {e}")
            sys.exit(1)

        print(f"\n[Paso 2 de {total_steps}] Comprobando y/o instalando Winget...")
        winget_available = ensure_winget_is_installed()

        print(f"\n[Paso 3 de {total_steps}] Instalando 7-Zip...")
        if winget_available:
            run_command(f"winget install --id=7zip.7zip -e --accept-source-agreements --accept-package-agreements", "Instalando 7-Zip (vía Winget)...")
        else:
            if download_file(SEVENZIP_URL, SEVENZIP_INSTALLER_PATH, "7-Zip"):
                if run_command(f'"{SEVENZIP_INSTALLER_PATH}" /S', "Ejecutando instalador de 7-Zip..."):
                    os.remove(SEVENZIP_INSTALLER_PATH)

        print(f"\n[Paso 4 de {total_steps}] Descargando y configurando utilidades adicionales...")
        download_and_setup_utils(ftp)

    print(f"\n[Paso 5 de {total_steps}] Instalando software de acceso remoto...")
    anydesk_installed = False
    program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
    anydesk_exe_path = os.path.join(program_files_x86, "AnyDesk", "AnyDesk.exe")
    if os.path.exists(anydesk_exe_path):
        print("   [AVISO] AnyDesk ya está instalado. Omitiendo la instalación.")
        anydesk_installed = True
    elif winget_available:
        if run_command(f"winget install --id=AnyDesk.AnyDesk -e --accept-source-agreements --accept-package-agreements", "Instalando AnyDesk (vía Winget)..."):
            anydesk_installed = True
    else:
        if download_file(ANYDESK_URL, ANYDESK_INSTALLER_PATH, "AnyDesk"):
            install_cmd = f'"{ANYDESK_INSTALLER_PATH}" --install "{program_files_x86}\\AnyDesk" --silent --start-with-win'
            if run_command(install_cmd, "Ejecutando instalador de AnyDesk..."):
                anydesk_installed = True
                os.remove(ANYDESK_INSTALLER_PATH)
    if anydesk_installed:
        create_shortcut(shortcut_name="AnyDesk", target_path=anydesk_exe_path)
    tv_installed = False
    if download_file(TEAMVIEWER_URL, TEAMVIEWER_INSTALLER_PATH, "TeamViewer 11"):
        if run_command(f'"{TEAMVIEWER_INSTALLER_PATH}" /S', "Ejecutando instalador de TeamViewer 11..."):
            os.remove(TEAMVIEWER_INSTALLER_PATH)
            tv_installed = True

    print(f"\n[Paso 6 de {total_steps}] Configurando contraseñas de acceso remoto...")
    print("   Esperando a que los servicios se inicien (10 segundos)...")
    time.sleep(10)
    if anydesk_installed and os.path.exists(anydesk_exe_path):
        print("   -> Configurando contraseña de AnyDesk...")
        run_command("taskkill /F /IM AnyDesk.exe /T > nul 2>&1", "Cerrando procesos de AnyDesk existentes...")
        time.sleep(2)
        password_command = f'echo {REMOTE_ACCESS_PASSWORD} | "{anydesk_exe_path}" --set-password'
        if not run_command(password_command, "Estableciendo contraseña para AnyDesk..."):
            print("   [AVISO] El primer intento falló. Reintentando en 5 segundos...")
            time.sleep(5)
            if not run_command(password_command, "Reintentando establecer contraseña..."):
                print("   [ERROR] No se pudo establecer la contraseña de AnyDesk.")
    if tv_installed:
        print("   -> Configurando contraseña de TeamViewer...")
        for path in ["HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer", "HKLM\\SOFTWARE\\TeamViewer"]:
            subprocess.run(f'reg add "{path}" /v SecurityPasswordAES /d "{REMOTE_ACCESS_PASSWORD}" /f', shell=True, capture_output=True)
        run_command("net stop TeamViewer", "Deteniendo servicio de TeamViewer...")
        time.sleep(3)
        run_command("net start TeamViewer", "Iniciando servicio de TeamViewer...")

    print(f"\n[Paso 7 de {total_steps}] Creando acceso directo PDA...")
    create_shortcut(shortcut_name="PDA", target_path=os.path.join(LOCAL_TARGET_FOLDER, "GC_1.EXE"), working_directory=LOCAL_TARGET_FOLDER, arguments="PDA")

    print(f"\n[Paso 8 de {total_steps}] Configurando reglas del Firewall...")
    add_firewall_rules()

    print(f"\n[Paso 9 de {total_steps}] Introduciendo licencia en la aplicación...")
    enter_license_key()

    print(f"\n[Paso 10 de {total_steps}] Cambiando formato regional e idioma")

    run_cambio_idioma()
    print("\n--- PROCESO FINALIZADO ---")
    input("Todas las tareas se han completado. Presiona Enter para cerrar esta ventana.")




if __name__ == "__main__":
    if not is_admin():
        print("Se requieren privilegios de administrador. Intentando re-lanzar...")
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        except Exception as e:
            input(f"Error al elevar privilegios: {e}\nPor favor, ejecuta como Administrador. Presiona Enter para salir.")
    else:
        main()
        input("\nProceso principal finalizado. Presiona Enter para salir.")
