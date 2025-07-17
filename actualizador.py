# -*- coding: utf-8 -*-

"""
SCRIPT DE ACTUALIZACIÓN MEJORADO (VERSIÓN 4.2 - LOG Y ALERTAS CORREGIDOS)

Descripción:
Este script moderniza y reemplaza el antiguo proceso de actualización por lotes (.bat).
Realiza las siguientes tareas de forma segura y robusta, funcionando desde cualquier
letra de unidad (C:, Z:, F:, etc.), y generando un log detallado de cada ejecución.
1.  Crea una copia de seguridad completa de la aplicación en el directorio padre.
2.  Si un error CRÍTICO ocurre, restaura automáticamente la copia de seguridad, registrando todo el proceso.
3.  Tras reindexar, comprueba si 'errorlog.htm' ha sido modificado y muestra un mensaje de error limpio.
4.  Descarga, extrae y actualiza todos los componentes de la aplicación.
5.  Si la actualización es exitosa, pregunta al usuario si desea eliminar la copia de seguridad.

Requisitos:
- Se necesita el ejecutable 7z.exe en la ruta especificada en la configuración.
- Se necesita instalar la librería 'tqdm' para las barras de progreso:
  pip install tqdm
"""

import os
import sys
import shutil
import subprocess
import ftplib
import time
import ctypes
import logging
import re
from tqdm import tqdm

# --- CONFIGURACIÓN ---
FTP_HOST = "webconsulting.tvoipadsl.com"
FTP_USER = "megassl"
FTP_PASS = "1024"
REMOTE_UPDATE_FILE = "/UPDATE/UPDATE.ZIP"

# Ruta al ejecutable de 7-Zip. Ajustar si es necesario.
SEVEN_ZIP_EXE = os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "7-Zip", "7z.exe")

# Directorio raíz donde se ejecuta el script
ROOT_DIR = os.getcwd()
# --- FIN DE LA CONFIGURACIÓN ---


def setup_logger():
    """Configura el logger para guardar un log detallado en un archivo de texto."""
    log_filename = f"actualizacion_{time.strftime('%Y-%m-%d_%H-%M-%S')}.log"
    log_filepath = os.path.join(ROOT_DIR, log_filename)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s [%(levelname)-7s] %(message)s")

    file_handler = logging.FileHandler(log_filepath, 'w', 'utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    logging.info(f"Se creará un log detallado en: {log_filename}")
    logging.info("Inicio del proceso de actualización.")
    return log_filepath

def print_step(step, total_steps, message):
    """Imprime y registra un encabezado de paso formateado."""
    header = f" PASO {step} de {total_steps}: {message} "
    logging.info("\n" + "="*80)
    logging.info(header.center(80))
    logging.info("="*80)

def run_command(command, working_dir=None, check=True):
    """Ejecuta un comando, lo registra y lanza una excepción en caso de error si check=True."""
    cmd_str = ' '.join(command)
    logging.info(f"Ejecutando comando: {cmd_str} en {working_dir or ROOT_DIR}")
    try:
        creation_flags = subprocess.CREATE_NO_WINDOW
        result = subprocess.run(
            command,
            cwd=working_dir or ROOT_DIR,
            capture_output=True,
            text=True,
            check=check,
            creationflags=creation_flags,
            encoding='latin-1',
            errors='ignore'
        )
        if result.stdout:
            logging.info(f"Salida del comando:\n{result.stdout.strip()}")
        if result.stderr:
            logging.warning(f"Salida de error del comando:\n{result.stderr.strip()}")
        logging.info(f"Comando '{cmd_str}' ejecutado con éxito.")
        return True
    except FileNotFoundError as e:
        logging.error(f"No se encontró el comando o ejecutable: {command[0]}")
        raise e
    except subprocess.CalledProcessError as e:
        logging.error(f"El comando '{cmd_str}' falló con el código {e.returncode}.")
        logging.error(f"Stderr: {e.stderr.strip()}")
        raise e
    except Exception as e:
        logging.critical(f"Ocurrió un error inesperado al ejecutar '{cmd_str}': {e}")
        raise e

def create_backup(backup_dir):
    """Crea una copia de seguridad completa del directorio de la aplicación."""
    print_step("1/N", "N/A", "Creando copia de seguridad completa")
    if os.path.exists(backup_dir):
        logging.warning(f"El directorio de backup '{backup_dir}' ya existe. Se eliminará.")
        shutil.rmtree(backup_dir, ignore_errors=True)

    os.makedirs(backup_dir)
    logging.info(f"Directorio de backup creado en: {backup_dir}")

    items_to_copy = os.listdir(ROOT_DIR)

    with tqdm(total=len(items_to_copy), desc="-> Respaldando archivos", unit="item") as pbar:
        for item in items_to_copy:
            source_path = os.path.join(ROOT_DIR, item)
            if source_path == backup_dir: continue
            dest_path = os.path.join(backup_dir, item)
            try:
                if os.path.isfile(source_path):
                    shutil.copy2(source_path, dest_path)
                elif os.path.isdir(source_path):
                    shutil.copytree(source_path, dest_path)
            except Exception as e:
                logging.warning(f"No se pudo respaldar '{item}': {e}. Omitiendo.")
            pbar.update(1)
    logging.info("Copia de seguridad completada.")

def restore_from_backup(backup_dir, log_filepath):
    """Restaura la aplicación desde la copia de seguridad de forma robusta."""
    logging.error("¡¡¡INICIANDO PROCESO DE RESTAURACIÓN (ROLLBACK)!!!")
    if not os.path.exists(backup_dir):
        logging.critical("No se encontró el directorio de la copia de seguridad. No se puede restaurar.")
        return

    logging.info("Eliminando archivos de la instalación fallida...")
    for item in os.listdir(ROOT_DIR):
        path = os.path.join(ROOT_DIR, item)
        if os.path.normpath(path) == os.path.normpath(log_filepath) or os.path.normpath(path) == os.path.normpath(backup_dir):
            continue
        try:
            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
        except Exception as e:
            logging.error(f"Error al eliminar {path} durante el rollback: {e}")

    logging.info(f"Restaurando archivos desde {backup_dir}...")
    items_to_restore = os.listdir(backup_dir)
    with tqdm(total=len(items_to_restore), desc="-> Restaurando", unit="item") as pbar:
        for item in items_to_restore:
            source_path = os.path.join(backup_dir, item)
            dest_path = os.path.join(ROOT_DIR, item)
            try:
                if os.path.isfile(source_path):
                    shutil.copy2(source_path, dest_path)
                elif os.path.isdir(source_path):
                    if os.path.exists(dest_path): shutil.rmtree(dest_path, ignore_errors=True)
                    shutil.copytree(source_path, dest_path)
            except Exception as e:
                logging.error(f"Error al restaurar {source_path} a {dest_path}: {e}")
            pbar.update(1)

    logging.info("Restauración completada. El sistema está en el estado anterior a la actualización.")
    try:
        shutil.rmtree(backup_dir, ignore_errors=True)
        logging.info("Carpeta de backup temporal eliminada.")
    except Exception as e:
        logging.error(f"No se pudo eliminar la carpeta de backup {backup_dir}: {e}")

def update_process(total_steps):
    """Contiene la lógica principal de la actualización."""

    print_step(1, total_steps, "Limpiando archivos de actualizaciones anteriores")
    files_to_clean = ["UPDATE.ZIP", "MIGRADBF.EXE", "GC_1.XXX", "CHKDBF.ZIP", "ENVFTP.TXT", "TRANSFER.ZIP", "INFORMES.ZIP", "FORMATOS.ZIP", "CHKPDA.ZIP", "errorlog.htm"]
    for f in tqdm(files_to_clean, desc="-> Limpiando archivos"):
        if os.path.exists(f): os.remove(f)

    print_step(2, total_steps, "Descargando paquete de actualización principal")
    try:
        logging.info(f"Conectando a FTP: {FTP_HOST}")
        with ftplib.FTP(FTP_HOST, FTP_USER, FTP_PASS, timeout=30) as ftp:
            ftp.set_pasv(True)
            total_size = ftp.size(REMOTE_UPDATE_FILE)
            logging.info(f"Conexión establecida. Tamaño de {REMOTE_UPDATE_FILE}: {total_size} bytes.")

            with open("UPDATE.ZIP", 'wb') as f, \
                    tqdm(total=total_size, unit='B', unit_scale=True, desc="-> UPDATE.ZIP", leave=False) as pbar:
                def callback(data):
                    f.write(data)
                    pbar.update(len(data))
                ftp.retrbinary(f"RETR {REMOTE_UPDATE_FILE}", callback)
            sys.stdout.write("\n")
    except Exception as e:
        logging.error(f"No se pudo descargar el archivo de actualización: {e}")
        raise e

    print_step(3, total_steps, "Extrayendo archivos y restaurando configuración")
    if not os.path.exists(SEVEN_ZIP_EXE):
        raise FileNotFoundError(f"No se encuentra 7-Zip en '{SEVEN_ZIP_EXE}'.")
    run_command([SEVEN_ZIP_EXE, 'e', 'UPDATE.ZIP', '-y'])
    run_command([SEVEN_ZIP_EXE, 'e', 'TRANSFER.ZIP', '-y'], check=False)

    print_step(4, total_steps, "Actualizando componentes y reindexando")
    if not os.path.exists("CHKDBF"): os.makedirs("CHKDBF")
    if not os.path.exists("INFORMES"): os.makedirs("INFORMES")
    if not os.path.exists("FORMATOS"): os.makedirs("FORMATOS")

    if os.path.exists("CHKDBF.ZIP"):
        run_command([SEVEN_ZIP_EXE, 'e', 'CHKDBF.ZIP', '-oCHKDBF', '-y'])
        if os.path.exists("MIGRADBF.EXE"):
            run_command(["MIGRADBF.EXE"])

    run_command([SEVEN_ZIP_EXE, 'e', 'INFORMES.ZIP', '-oINFORMES', '-y'], check=False)
    run_command([SEVEN_ZIP_EXE, 'e', 'FORMATOS.ZIP', '-oFORMATOS', '-y'], check=False)

    logging.info("Reindexando base de datos...")
    error_log_path = os.path.join(ROOT_DIR, "errorlog.htm")
    initial_mod_time = os.path.getmtime(error_log_path) if os.path.exists(error_log_path) else 0.0

    run_command(["GC_1.EXE", "INDEXAR"])

    if check_for_post_update_errors(error_log_path, initial_mod_time):
        raise Exception("Rollback solicitado por el usuario tras detectar errores en errorlog.htm.")

    print_step(5, total_steps, "Actualizando componente PDA")
    if os.path.exists("CHKPDA.ZIP"):
        drive_root = os.path.splitdrive(ROOT_DIR)[0] + os.sep
        pda_root = os.path.join(drive_root, "POCKET")
        if not os.path.exists(pda_root): os.makedirs(pda_root)
        pda_chk_dir = os.path.join(pda_root, "CHKDBF")
        if not os.path.exists(pda_chk_dir): os.makedirs(pda_chk_dir)

        shutil.copy2("CHKPDA.ZIP", pda_chk_dir)
        shutil.copy2("MIGRADBF.EXE", pda_root)
        shutil.copy2("GCPOCKET.EXE", pda_root)
        run_command([SEVEN_ZIP_EXE, 'e', os.path.join(pda_chk_dir, "CHKPDA.ZIP"), f'-o{pda_chk_dir}', '-y'])
        run_command(["MIGRADBF.EXE", "S", "S"], working_dir=pda_root)
    else:
        logging.warning("No se encontró CHKPDA.ZIP. Omitiendo actualización de PDA.")

    print_step(6, total_steps, "Duplicando ejecutable principal actualizado")
    new_gc1_exe = os.path.join(ROOT_DIR, "GC_1.EXE")
    if os.path.exists(new_gc1_exe):
        exe_dir = os.path.join(ROOT_DIR, "EXE")
        if not os.path.exists(exe_dir): os.makedirs(exe_dir)
        destinations = [
            os.path.join(ROOT_DIR, "ZZ.EXE"),
            os.path.join(exe_dir, "GC_1.EXE"),
            os.path.join(exe_dir, "ZZ.EXE")
        ]
        for dest_path in tqdm(destinations, desc="-> Duplicando ejecutables"):
            shutil.copy2(new_gc1_exe, dest_path)
    else:
        raise FileNotFoundError(f"No se encontró el nuevo ejecutable '{new_gc1_exe}' para duplicar.")

def check_for_post_update_errors(error_log_path, initial_mod_time):
    """Verifica si errorlog.htm ha sido modificado y pregunta al usuario si desea hacer rollback."""
    if not os.path.exists(error_log_path):
        return False

    try:
        current_mod_time = os.path.getmtime(error_log_path)
    except OSError:
        return False

    if current_mod_time <= initial_mod_time:
        logging.info(f"El archivo '{os.path.basename(error_log_path)}' no ha sido modificado durante la indexación. Se ignora.")
        return False

    logging.warning(f"Se ha detectado una modificación reciente en el archivo de errores: {error_log_path}")

    try:
        with open(error_log_path, 'r', encoding='latin-1', errors='ignore') as f:
            full_content = f.read()

        # Extraer solo el texto del primer error para mostrarlo
        first_error_match = re.search(r'<p class="updated">(.*?)</p>', full_content, re.DOTALL)
        if first_error_match:
            error_html = first_error_match.group(1)
            # Limpiar el HTML para mostrar texto plano
            error_text = re.sub(r'<br\s*/?>', '\n', error_html)
            error_text = re.sub(r'<[^>]+>', '', error_text).strip()
        else:
            error_text = "No se pudo extraer el detalle del error."

        if not error_text:
            logging.warning("'errorlog.htm' fue modificado pero parece estar vacío. Se ignora.")
            return False

    except Exception as e:
        logging.error(f"No se pudo leer el archivo de errores: {e}")
        error_text = f"No se pudo leer o procesar el archivo de errores: {e}"

    MB_YESNO = 4
    MB_ICONERROR = 16
    IDYES = 6

    message = (
        "¡ATENCIÓN! Se ha detectado un error durante la reindexación.\n\n"
        "DETALLES DEL ERROR:\n"
        "--------------------------------\n"
        f"{error_text}\n"
        "--------------------------------\n\n"
        "¿Desea deshacer la actualización y restaurar la versión anterior (Rollback)?"
    )

    response = ctypes.windll.user32.MessageBoxW(0, message, "Error Detectado Post-Actualización", MB_YESNO | MB_ICONERROR)

    if response == IDYES:
        logging.error("El usuario ha solicitado un rollback tras detectar errores en errorlog.htm.")
        return True
    else:
        logging.warning("El usuario ha decidido ignorar los errores de errorlog.htm y continuar.")
        try:
            os.rename(error_log_path, error_log_path + f".ignored_{time.strftime('%Y%m%d%H%M%S')}")
        except OSError:
            pass
        return False

def main():
    """Función principal que orquesta el proceso de actualización."""
    log_filepath = setup_logger()

    parent_dir = os.path.abspath(os.path.join(ROOT_DIR, os.pardir))
    current_folder_name = os.path.basename(ROOT_DIR)
    backup_dir = os.path.join(parent_dir, f"COPIASEG_{current_folder_name}_{time.strftime('%Y-%m-%d_%H-%M-%S')}")

    try:
        create_backup(backup_dir)
        update_process(total_steps=6)

        logging.info("No se detectaron errores críticos o el usuario decidió continuar.")

        MB_YESNO = 4
        MB_ICONQUESTION = 32
        IDYES = 6

        message = (f"La actualización se completó con éxito.\n\n"
                   f"Se ha conservado una copia de seguridad en:\n{backup_dir}\n\n"
                   f"¿Desea eliminar esta copia de seguridad ahora?")

        response = ctypes.windll.user32.MessageBoxW(0, message, "Actualización Completa", MB_YESNO | MB_ICONQUESTION)

        if response == IDYES:
            logging.info("El usuario ha decidido eliminar la copia de seguridad.")
            try:
                shutil.rmtree(backup_dir, ignore_errors=True)
                logging.info("Copia de seguridad eliminada.")
                ctypes.windll.user32.MessageBoxW(0, "La copia de seguridad ha sido eliminada.", "Limpieza Finalizada", 64)
            except Exception as e:
                logging.warning(f"No se pudo eliminar la copia de seguridad en {backup_dir}: {e}")
                error_msg = f"No se pudo eliminar la copia de seguridad:\n{e}"
                ctypes.windll.user32.MessageBoxW(0, error_msg, "Error de Limpieza", 16)
        else:
            logging.info(f"El usuario ha decidido conservar la copia de seguridad en: {backup_dir}")
            info_msg = f"Se ha conservado la copia de seguridad en la siguiente ruta:\n\n{backup_dir}"
            ctypes.windll.user32.MessageBoxW(0, info_msg, "Copia de Seguridad Conservada", 64)

    except Exception as e:
        logging.critical(f"Ha ocurrido un error fatal durante la actualización: {e}", exc_info=True)
        restore_from_backup(backup_dir, log_filepath)
        error_message = (
            "La actualización no pudo completarse.\n\n"
            "Se ha restaurado la versión anterior para garantizar la estabilidad del sistema.\n\n"
            f"Para más información, consulte el archivo de registro:\n{os.path.basename(log_filepath)}"
        )
        ctypes.windll.user32.MessageBoxW(0, error_message, "Actualización Revertida", 16)
    finally:
        input("\nPresiona Enter para cerrar la ventana.")


if __name__ == "__main__":
    main()
