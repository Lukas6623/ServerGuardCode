import sys
import os
import json
import hashlib
import shutil
import zipfile
import tempfile
import subprocess
import ctypes
import time
from pathlib import Path
from urllib.request import Request, urlopen

from PySide6.QtCore import Qt, QThread, Signal, QPointF
from PySide6.QtGui import (
    QFont,
    QColor,
    QIcon,
    QPainter,
    QPixmap,
    QPolygonF,
)
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QLabel,
    QPushButton,
    QProgressBar,
    QTextEdit,
    QVBoxLayout,
    QHBoxLayout,
    QFrame,
    QDialog,
)


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "ServerGuard"
APP_VERSION = "1.0.0"

MANIFEST_URL = (
    "https://raw.githubusercontent.com/"
    "Lukas6623/ServerGuard/main/updates/manifest.json"
)

INSTALL_DIRECTORY = Path(
    r"C:\Program Files\ServerGuard"
)

SERVERGUARD_EXE = (
    INSTALL_DIRECTORY / "ServerGuard.exe"
)

VERSION_FILE = (
    INSTALL_DIRECTORY / "version.txt"
)

DESKTOP_SHORTCUT = (
    Path.home()
    / "Desktop"
    / "ServerGuard.lnk"
)

START_MENU_DIRECTORY = (
    Path(
        os.environ.get(
            "PROGRAMDATA",
            r"C:\ProgramData"
        )
    )
    / "Microsoft"
    / "Windows"
    / "Start Menu"
    / "Programs"
    / "ServerGuard"
)

START_MENU_SHORTCUT = (
    START_MENU_DIRECTORY
    / "ServerGuard.lnk"
)

BACKUP_DIRECTORY = Path(
    r"C:\Program Files\ServerGuard_Backup"
)


# ============================================================
# COLORS
# ============================================================

BG = "#080c11"
CARD = "#10161e"
CARD_2 = "#151d27"
BORDER = "#25313e"

TEXT = "#f4f7fb"
TEXT_SECONDARY = "#8996a6"
TEXT_MUTED = "#657384"

ACCENT = "#4f8cff"
ACCENT_HOVER = "#679bff"

SUCCESS = "#35d07f"
WARNING = "#ffbd4a"
ERROR = "#ff5967"

LOG_BG = "#0b1016"


# ============================================================
# ADMINISTRATOR
# ============================================================

def is_admin():
    try:
        return bool(
            ctypes.windll.shell32.IsUserAnAdmin()
        )
    except Exception:
        return False


def restart_as_admin():

    if is_admin():
        return

    # --------------------------------------------------------
    # Python
    # --------------------------------------------------------

    if not getattr(
        sys,
        "frozen",
        False
    ):

        executable = Path(
            sys.executable
        )

        pythonw = (
            executable.parent
            / "pythonw.exe"
        )

        if pythonw.exists():
            executable = pythonw

        parameters = (
            f'"{Path(__file__).resolve()}"'
        )

    # --------------------------------------------------------
    # PyInstaller
    # --------------------------------------------------------

    else:

        executable = Path(
            sys.executable
        )

        parameters = " ".join(
            f'"{arg}"'
            for arg in sys.argv[1:]
        )

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        str(executable),
        parameters,
        None,
        1,
    )

    if result <= 32:

        raise RuntimeError(
            "Не удалось получить права администратора."
        )

    sys.exit(0)


# ============================================================
# VERSION
# ============================================================

def parse_version(version):

    if not version:
        return (0, 0, 0)

    try:

        version = str(version).strip()

        if version.lower().startswith("v"):
            version = version[1:]

        parts = version.split(".")

        numbers = []

        for part in parts:

            number = ""

            for char in part:

                if char.isdigit():
                    number += char
                else:
                    break

            if number:
                numbers.append(
                    int(number)
                )
            else:
                numbers.append(0)

        while len(numbers) < 3:
            numbers.append(0)

        return tuple(numbers[:3])

    except Exception:

        return (0, 0, 0)


def compare_versions(a, b):

    va = parse_version(a)
    vb = parse_version(b)

    if va > vb:
        return 1

    if va < vb:
        return -1

    return 0


def read_installed_version():

    try:

        if VERSION_FILE.exists():

            version = VERSION_FILE.read_text(
                encoding="utf-8"
            ).strip()

            if version:
                return version

    except Exception:
        pass

    return None


def save_installed_version(version):

    INSTALL_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )

    VERSION_FILE.write_text(
        str(version),
        encoding="utf-8"
    )


# ============================================================
# SHA256
# ============================================================

def calculate_sha256(path):

    sha256 = hashlib.sha256()

    with open(
        path,
        "rb"
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest().lower()


# ============================================================
# MANIFEST
# ============================================================

def download_manifest():

    request = Request(
        MANIFEST_URL,
        headers={
            "User-Agent":
            "ServerGuardSetup/1.0"
        }
    )

    with urlopen(
        request,
        timeout=30
    ) as response:

        data = response.read()

    manifest = json.loads(
        data.decode("utf-8")
    )

    if not isinstance(
        manifest,
        dict
    ):

        raise RuntimeError(
            "manifest.json имеет неправильный формат."
        )

    return manifest


# ============================================================
# DOWNLOAD
# ============================================================

def download_file(
    url,
    destination,
    progress_callback=None
):

    request = Request(
        url,
        headers={
            "User-Agent":
            "ServerGuardSetup/1.0"
        },
    )

    with urlopen(
        request,
        timeout=60
    ) as response:

        total = response.headers.get(
            "Content-Length"
        )

        try:
            total = (
                int(total)
                if total
                else 0
            )
        except Exception:
            total = 0

        downloaded = 0

        with open(
            destination,
            "wb"
        ) as file:

            while True:

                chunk = response.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                file.write(chunk)

                downloaded += len(
                    chunk
                )

                if (
                    total
                    and progress_callback
                ):

                    percent = int(
                        downloaded
                        * 100
                        / total
                    )

                    progress_callback(
                        min(
                            percent,
                            100
                        )
                    )


# ============================================================
# SAFE ZIP EXTRACTION
# ============================================================

def safe_extract(
    zip_path,
    destination
):

    destination = Path(
        destination
    ).resolve()

    destination.mkdir(
        parents=True,
        exist_ok=True
    )

    with zipfile.ZipFile(
        zip_path,
        "r"
    ) as archive:

        for member in archive.infolist():

            member_path = (
                destination
                / member.filename
            ).resolve()

            if (
                member_path != destination
                and destination
                not in member_path.parents
            ):

                raise RuntimeError(
                    "Обнаружен небезопасный "
                    "путь в ZIP-архиве."
                )

        archive.extractall(
            destination
        )


# ============================================================
# FIND SERVERGUARD.EXE
# ============================================================

def find_serverguard_exe(
    directory
):

    directory = Path(
        directory
    )

    direct = (
        directory
        / "ServerGuard.exe"
    )

    if direct.exists():
        return direct

    for file in directory.rglob(
        "ServerGuard.exe"
    ):

        if file.is_file():
            return file

    return None


# ============================================================
# GET PACKAGE ROOT
# ============================================================

def find_package_root(
    extracted_directory,
    serverguard_exe
):

    extracted_directory = Path(
        extracted_directory
    ).resolve()

    serverguard_exe = Path(
        serverguard_exe
    ).resolve()

    # --------------------------------------------------------
    # Если ServerGuard.exe лежит прямо в extracted
    # --------------------------------------------------------

    if (
        serverguard_exe.parent
        == extracted_directory
    ):

        return extracted_directory

    # --------------------------------------------------------
    # Обычно ZIP выглядит так:
    #
    # ServerGuard-v1.0.0/
    #     ServerGuard.exe
    #     libssh2.dll
    #     ...
    #
    # Тогда root = ServerGuard-v1.0.0
    # --------------------------------------------------------

    current = serverguard_exe.parent

    while current != extracted_directory:

        if current.parent == extracted_directory:

            return current

        current = current.parent

    return serverguard_exe.parent


# ============================================================
# PROCESS CHECK
# ============================================================

def is_serverguard_running():

    try:

        result = subprocess.run(
            [
                "tasklist",
                "/FI",
                "IMAGENAME eq ServerGuard.exe",
            ],
            capture_output=True,
            text=True,
            creationflags=(
                subprocess.CREATE_NO_WINDOW
            ),
        )

        return (
            "ServerGuard.exe"
            in result.stdout
        )

    except Exception:

        return False


def stop_serverguard():

    if not is_serverguard_running():
        return True

    try:

        subprocess.run(
            [
                "taskkill",
                "/F",
                "/IM",
                "ServerGuard.exe",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=(
                subprocess.CREATE_NO_WINDOW
            ),
        )

    except Exception:

        return False

    for _ in range(30):

        if not is_serverguard_running():
            return True

        time.sleep(
            0.25
        )

    return False


# ============================================================
# SHORTCUT
# ============================================================

def create_shortcut(
    shortcut_path,
    target
):

    shortcut_path = Path(
        shortcut_path
    )

    target = Path(
        target
    )

    shortcut_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    escaped_target = (
        str(target)
        .replace(
            "'",
            "''"
        )
    )

    escaped_shortcut = (
        str(shortcut_path)
        .replace(
            "'",
            "''"
        )
    )

    escaped_working = (
        str(target.parent)
        .replace(
            "'",
            "''"
        )
    )

    script = (
        "$ws = New-Object "
        "-ComObject WScript.Shell; "
        f"$s = $ws.CreateShortcut("
        f"'{escaped_shortcut}'); "
        f"$s.TargetPath = "
        f"'{escaped_target}'; "
        f"$s.WorkingDirectory = "
        f"'{escaped_working}'; "
        f"$s.IconLocation = "
        f"'{escaped_target},0'; "
        "$s.Save();"
    )

    subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        check=True,
        creationflags=(
            subprocess.CREATE_NO_WINDOW
        ),
    )


def create_all_shortcuts():

    create_shortcut(
        DESKTOP_SHORTCUT,
        SERVERGUARD_EXE
    )

    create_shortcut(
        START_MENU_SHORTCUT,
        SERVERGUARD_EXE
    )


# ============================================================
# SHIELD ICON
# ============================================================

def create_shield_icon():

    pixmap = QPixmap(
        96,
        96
    )

    pixmap.fill(
        Qt.GlobalColor.transparent
    )

    painter = QPainter(
        pixmap
    )

    painter.setRenderHint(
        QPainter.RenderHint.Antialiasing
    )

    painter.setBrush(
        QColor(ACCENT)
    )

    painter.setPen(
        Qt.PenStyle.NoPen
    )

    points = QPolygonF(
        [
            QPointF(48, 5),
            QPointF(82, 18),
            QPointF(76, 57),
            QPointF(48, 88),
            QPointF(20, 57),
            QPointF(14, 18),
        ]
    )

    painter.drawPolygon(
        points
    )

    painter.setPen(
        QColor("#ffffff")
    )

    painter.setBrush(
        Qt.BrushStyle.NoBrush
    )

    painter.drawLine(
        30,
        47,
        42,
        59
    )

    painter.drawLine(
        42,
        59,
        66,
        34
    )

    painter.end()

    return QIcon(
        pixmap
    )


# ============================================================
# DARK DIALOG
# ============================================================

class DarkDialog(QDialog):

    def __init__(
        self,
        parent,
        title,
        message,
        dialog_type="info",
        button_text="OK"
    ):

        super().__init__(
            parent
        )

        self.setWindowTitle(
            title
        )

        self.setFixedWidth(
            500
        )

        self.setModal(
            True
        )

        self.setStyleSheet(
            f"""
            QDialog {{
                background: {BG};
            }}

            QLabel#dialogTitle {{
                color: {TEXT};
                font-size: 19px;
                font-weight: 700;
            }}

            QLabel#dialogMessage {{
                color: {TEXT_SECONDARY};
                font-size: 13px;
            }}

            QPushButton {{
                min-width: 100px;
                min-height: 38px;
                border: none;
                border-radius: 9px;
                padding: 0 20px;
                font-size: 13px;
                font-weight: 600;
                background: {ACCENT};
                color: white;
            }}

            QPushButton:hover {{
                background: {ACCENT_HOVER};
            }}
            """
        )

        layout = QVBoxLayout(
            self
        )

        layout.setContentsMargins(
            28,
            25,
            28,
            24
        )

        layout.setSpacing(
            15
        )

        header = QHBoxLayout()

        icon_label = QLabel()

        icon_pixmap = QPixmap(
            42,
            42
        )

        icon_pixmap.fill(
            Qt.GlobalColor.transparent
        )

        painter = QPainter(
            icon_pixmap
        )

        painter.setRenderHint(
            QPainter.RenderHint.Antialiasing
        )

        if dialog_type == "success":

            icon_color = SUCCESS
            symbol = "✓"

        elif dialog_type == "error":

            icon_color = ERROR
            symbol = "×"

        elif dialog_type == "warning":

            icon_color = WARNING
            symbol = "!"

        else:

            icon_color = ACCENT
            symbol = "i"

        painter.setBrush(
            QColor(icon_color)
        )

        painter.setPen(
            Qt.PenStyle.NoPen
        )

        painter.drawEllipse(
            2,
            2,
            38,
            38
        )

        painter.setPen(
            QColor("#ffffff")
        )

        painter.setFont(
            QFont(
                "Segoe UI",
                18,
                QFont.Weight.Bold
            )
        )

        painter.drawText(
            icon_pixmap.rect(),
            Qt.AlignmentFlag.AlignCenter,
            symbol
        )

        painter.end()

        icon_label.setPixmap(
            icon_pixmap
        )

        header.addWidget(
            icon_label
        )

        title_label = QLabel(
            title
        )

        title_label.setObjectName(
            "dialogTitle"
        )

        header.addWidget(
            title_label
        )

        header.addStretch()

        layout.addLayout(
            header
        )

        message_label = QLabel(
            message
        )

        message_label.setObjectName(
            "dialogMessage"
        )

        message_label.setWordWrap(
            True
        )

        layout.addWidget(
            message_label
        )

        buttons = QHBoxLayout()

        buttons.addStretch()

        button = QPushButton(
            button_text
        )

        button.clicked.connect(
            self.accept
        )

        buttons.addWidget(
            button
        )

        layout.addLayout(
            buttons
        )


def show_dialog(
    parent,
    title,
    message,
    dialog_type="info"
):

    dialog = DarkDialog(
        parent,
        title,
        message,
        dialog_type
    )

    dialog.exec()


# ============================================================
# INSTALL / UPDATE WORKER
# ============================================================

class InstallerWorker(
    QThread
):

    progress = Signal(int)
    status = Signal(str)
    log = Signal(str)

    success = Signal(
        str,
        bool
    )

    failure = Signal(
        str,
        bool
    )

    def __init__(
        self,
        update_mode=False
    ):

        super().__init__()

        self.update_mode = (
            update_mode
        )

    def run(self):

        temp_directory = None
        backup_created = False
        new_version = None

        try:

            # =================================================
            # MANIFEST
            # =================================================

            self.status.emit(
                "Проверка версии..."
            )

            self.log.emit(
                "Получение manifest.json..."
            )

            manifest = download_manifest()

            new_version = str(
                manifest.get(
                    "version",
                    ""
                )
            ).strip()

            download_url = str(
                manifest.get(
                    "url",
                    ""
                )
            ).strip()

            expected_sha256 = str(
                manifest.get(
                    "sha256",
                    ""
                )
            ).strip().lower()

            if not new_version:

                raise RuntimeError(
                    "В manifest.json отсутствует version."
                )

            if not download_url:

                raise RuntimeError(
                    "В manifest.json отсутствует url."
                )

            if not expected_sha256:

                raise RuntimeError(
                    "В manifest.json отсутствует sha256."
                )

            installed_version = (
                read_installed_version()
            )

            if installed_version:

                self.log.emit(
                    f"Текущая версия: "
                    f"{installed_version}"
                )

            else:

                self.log.emit(
                    "Текущая версия: не установлена"
                )

            self.log.emit(
                f"Версия на сервере: "
                f"{new_version}"
            )

            # =================================================
            # CHECK VERSION
            # =================================================

            if installed_version:

                comparison = compare_versions(
                    installed_version,
                    new_version
                )

                self.log.emit(
                    f"Результат сравнения версий: "
                    f"{comparison}"
                )

                # ------------------------------------------------
                # ВАЖНО:
                #
                # comparison:
                #
                # -1 = серверная версия НОВЕЕ
                #  0 = версии одинаковые
                #  1 = локальная версия НОВЕЕ
                #
                # Поэтому при update_mode ошибка должна быть
                # только если comparison >= 0.
                # ------------------------------------------------

                if (
                    self.update_mode
                    and comparison >= 0
                ):

                    raise RuntimeError(
                        "Новой версии ServerGuard "
                        "не найдено."
                    )

            self.progress.emit(
                5
            )

            # =================================================
            # STOP SERVERGUARD
            # =================================================

            if is_serverguard_running():

                self.status.emit(
                    "Остановка ServerGuard..."
                )

                self.log.emit(
                    "ServerGuard сейчас запущен."
                )

                if not stop_serverguard():

                    raise RuntimeError(
                        "Не удалось остановить "
                        "ServerGuard.exe."
                    )

                self.log.emit(
                    "ServerGuard остановлен."
                )

            # =================================================
            # TEMP DIRECTORY
            # =================================================

            temp_directory = Path(
                tempfile.mkdtemp(
                    prefix="ServerGuardSetup_"
                )
            )

            zip_path = (
                temp_directory
                / "ServerGuard.zip"
            )

            extract_directory = (
                temp_directory
                / "extracted"
            )

            extract_directory.mkdir(
                parents=True,
                exist_ok=True
            )

            # =================================================
            # DOWNLOAD
            # =================================================

            self.status.emit(
                "Загрузка ServerGuard..."
            )

            self.log.emit(
                "Загрузка ZIP-архива..."
            )

            self.progress.emit(
                10
            )

            def download_progress(
                value
            ):

                mapped = (
                    10
                    + int(
                        value
                        * 35
                        / 100
                    )
                )

                self.progress.emit(
                    min(
                        mapped,
                        45
                    )
                )

            download_file(
                download_url,
                zip_path,
                download_progress
            )

            self.log.emit(
                "Архив загружен."
            )

            self.progress.emit(
                48
            )

            # =================================================
            # SHA256
            # =================================================

            self.status.emit(
                "Проверка целостности..."
            )

            self.log.emit(
                "Вычисление SHA-256..."
            )

            actual_sha256 = (
                calculate_sha256(
                    zip_path
                )
            )

            self.log.emit(
                f"SHA-256 полученного архива: "
                f"{actual_sha256}"
            )

            if (
                actual_sha256
                != expected_sha256
            ):

                raise RuntimeError(
                    "Ошибка проверки SHA-256.\n\n"
                    f"Ожидалось:\n"
                    f"{expected_sha256}\n\n"
                    f"Получено:\n"
                    f"{actual_sha256}"
                )

            self.log.emit(
                "SHA-256 успешно проверен."
            )

            self.progress.emit(
                55
            )

            # =================================================
            # EXTRACT
            # =================================================

            self.status.emit(
                "Распаковка файлов..."
            )

            self.log.emit(
                "Распаковка ZIP..."
            )

            safe_extract(
                zip_path,
                extract_directory
            )

            self.log.emit(
                "Архив распакован."
            )

            # =================================================
            # FIND EXE
            # =================================================

            serverguard_exe = (
                find_serverguard_exe(
                    extract_directory
                )
            )

            if not serverguard_exe:

                raise RuntimeError(
                    "В ZIP-архиве не найден "
                    "ServerGuard.exe."
                )

            package_root = (
                find_package_root(
                    extract_directory,
                    serverguard_exe
                )
            )

            self.log.emit(
                f"Папка пакета: "
                f"{package_root}"
            )

            self.log.emit(
                "ServerGuard.exe найден."
            )

            self.progress.emit(
                63
            )

            # =================================================
            # BACKUP
            # =================================================

            if INSTALL_DIRECTORY.exists():

                self.status.emit(
                    "Создание резервной копии..."
                )

                self.log.emit(
                    "Создание резервной копии "
                    "текущей версии..."
                )

                if BACKUP_DIRECTORY.exists():

                    shutil.rmtree(
                        BACKUP_DIRECTORY,
                        ignore_errors=True
                    )

                shutil.copytree(
                    INSTALL_DIRECTORY,
                    BACKUP_DIRECTORY
                )

                backup_created = True

                self.log.emit(
                    f"Резервная копия: "
                    f"{BACKUP_DIRECTORY}"
                )

            self.progress.emit(
                70
            )

            # =================================================
            # REMOVE OLD PROGRAM FILES
            # =================================================

            if INSTALL_DIRECTORY.exists():

                self.status.emit(
                    "Подготовка обновления..."
                )

                self.log.emit(
                    "Замена файлов ServerGuard..."
                )

                shutil.rmtree(
                    INSTALL_DIRECTORY,
                    ignore_errors=True
                )

                if INSTALL_DIRECTORY.exists():

                    raise RuntimeError(
                        "Не удалось удалить старую "
                        "папку ServerGuard."
                    )

            INSTALL_DIRECTORY.mkdir(
                parents=True,
                exist_ok=True
            )

            # =================================================
            # COPY NEW FILES
            # =================================================

            self.status.emit(
                "Установка файлов..."
            )

            files = list(
                package_root.rglob("*")
            )

            total_files = max(
                1,
                len(
                    [
                        x
                        for x in files
                        if x.is_file()
                    ]
                )
            )

            copied = 0

            for source in files:

                relative = (
                    source.relative_to(
                        package_root
                    )
                )

                destination = (
                    INSTALL_DIRECTORY
                    / relative
                )

                if source.is_dir():

                    destination.mkdir(
                        parents=True,
                        exist_ok=True
                    )

                else:

                    destination.parent.mkdir(
                        parents=True,
                        exist_ok=True
                    )

                    shutil.copy2(
                        source,
                        destination
                    )

                    copied += 1

                    progress = (
                        70
                        + int(
                            copied
                            * 20
                            / total_files
                        )
                    )

                    self.progress.emit(
                        min(
                            progress,
                            90
                        )
                    )

            # =================================================
            # VERIFY INSTALLATION
            # =================================================

            if not SERVERGUARD_EXE.exists():

                raise RuntimeError(
                    "После установки "
                    "ServerGuard.exe не найден."
                )

            self.log.emit(
                "ServerGuard.exe успешно установлен."
            )

            self.progress.emit(
                92
            )

            # =================================================
            # VERSION FILE
            # =================================================

            save_installed_version(
                new_version
            )

            self.log.emit(
                f"Установлена версия "
                f"{new_version}."
            )

            # =================================================
            # SHORTCUTS
            # =================================================

            self.status.emit(
                "Создание ярлыков..."
            )

            self.log.emit(
                "Создание ярлыка рабочего стола..."
            )

            create_shortcut(
                DESKTOP_SHORTCUT,
                SERVERGUARD_EXE
            )

            self.log.emit(
                "Ярлык рабочего стола создан."
            )

            self.log.emit(
                "Создание ярлыка меню Пуск..."
            )

            create_shortcut(
                START_MENU_SHORTCUT,
                SERVERGUARD_EXE
            )

            self.log.emit(
                "Ярлык меню Пуск создан."
            )

            self.progress.emit(
                98
            )

            # =================================================
            # COMPLETE
            # =================================================

            self.status.emit(
                "Готово"
            )

            self.progress.emit(
                100
            )

            self.log.emit(
                "--------------------------------"
            )

            if self.update_mode:

                self.log.emit(
                    "ServerGuard успешно обновлён."
                )

            else:

                self.log.emit(
                    "ServerGuard успешно установлен."
                )

            self.log.emit(
                f"Версия: {new_version}"
            )

            self.log.emit(
                f"Путь: {INSTALL_DIRECTORY}"
            )

            self.log.emit(
                "--------------------------------"
            )

            self.success.emit(
                new_version,
                self.update_mode
            )

        except Exception as error:

            # =================================================
            # ROLLBACK
            # =================================================

            if (
                self.update_mode
                and backup_created
                and BACKUP_DIRECTORY.exists()
            ):

                try:

                    self.log.emit(
                        "Произошла ошибка."
                    )

                    self.log.emit(
                        "Восстановление предыдущей "
                        "версии..."
                    )

                    if INSTALL_DIRECTORY.exists():

                        shutil.rmtree(
                            INSTALL_DIRECTORY,
                            ignore_errors=True
                        )

                    shutil.copytree(
                        BACKUP_DIRECTORY,
                        INSTALL_DIRECTORY
                    )

                    self.log.emit(
                        "Предыдущая версия "
                        "восстановлена."
                    )

                except Exception as rollback_error:

                    self.log.emit(
                        "Не удалось восстановить "
                        "предыдущую версию."
                    )

                    self.log.emit(
                        f"Ошибка восстановления: "
                        f"{rollback_error}"
                    )

            self.failure.emit(
                str(error),
                self.update_mode
            )

        finally:

            if temp_directory:

                try:

                    shutil.rmtree(
                        temp_directory,
                        ignore_errors=True
                    )

                except Exception:
                    pass


# ============================================================
# MAIN WINDOW
# ============================================================

class InstallerWindow(
    QMainWindow
):

    def __init__(self):

        super().__init__()

        self.worker = None
        self.manifest = None
        self.remote_version = None

        self.installed_version = (
            read_installed_version()
        )

        self.setWindowTitle(
            "ServerGuard Setup"
        )

        self.setFixedSize(
            780,
            640
        )

        self.setWindowIcon(
            create_shield_icon()
        )

        self.setStyleSheet(
            f"""
            QMainWindow {{
                background: {BG};
            }}

            QWidget {{
                color: {TEXT};
                font-family: "Segoe UI";
            }}

            QFrame#card {{
                background: {CARD};
                border: 1px solid {BORDER};
                border-radius: 14px;
            }}

            QLabel#title {{
                font-size: 30px;
                font-weight: 700;
                color: {TEXT};
            }}

            QLabel#subtitle {{
                font-size: 14px;
                color: {TEXT_SECONDARY};
            }}

            QLabel#section {{
                font-size: 11px;
                font-weight: 700;
                color: {TEXT_MUTED};
            }}

            QLabel#status {{
                font-size: 16px;
                font-weight: 600;
                color: {TEXT};
            }}

            QLabel#version {{
                font-size: 13px;
                color: {TEXT_SECONDARY};
            }}

            QProgressBar {{
                background: #202a35;
                border: none;
                border-radius: 6px;
                height: 10px;
            }}

            QProgressBar::chunk {{
                background: {ACCENT};
                border-radius: 6px;
            }}

            QTextEdit {{
                background: {LOG_BG};
                border: 1px solid {BORDER};
                border-radius: 10px;
                padding: 10px;
                color: #aeb9c6;
                font-family: "Cascadia Mono";
                font-size: 11px;
            }}

            QPushButton {{
                border: none;
                border-radius: 9px;
                padding: 11px 20px;
                font-size: 13px;
                font-weight: 600;
            }}

            QPushButton#primary {{
                background: {ACCENT};
                color: white;
            }}

            QPushButton#primary:hover {{
                background: {ACCENT_HOVER};
            }}

            QPushButton#secondary {{
                background: #202a35;
                color: {TEXT};
            }}

            QPushButton#secondary:hover {{
                background: #293644;
            }}

            QPushButton#success {{
                background: {SUCCESS};
                color: #06130b;
            }}

            QPushButton#success:hover {{
                background: #55dd92;
            }}

            QPushButton:disabled {{
                background: #1a222c;
                color: #566373;
            }}
            """
        )

        self.build_ui()

        self.check_for_updates()

    # ========================================================
    # UI
    # ========================================================

    def build_ui(self):

        central = QWidget()

        self.setCentralWidget(
            central
        )

        root = QVBoxLayout(
            central
        )

        root.setContentsMargins(
            32,
            28,
            32,
            28
        )

        root.setSpacing(
            16
        )

        # ====================================================
        # HEADER
        # ====================================================

        header = QHBoxLayout()

        icon = QLabel()

        icon.setPixmap(
            create_shield_icon().pixmap(
                62,
                62
            )
        )

        header.addWidget(
            icon
        )

        title_layout = QVBoxLayout()

        title = QLabel(
            "ServerGuard"
        )

        title.setObjectName(
            "title"
        )

        subtitle = QLabel(
            "Безопасная установка и обновление"
        )

        subtitle.setObjectName(
            "subtitle"
        )

        title_layout.addWidget(
            title
        )

        title_layout.addWidget(
            subtitle
        )

        header.addLayout(
            title_layout
        )

        header.addStretch()

        root.addLayout(
            header
        )

        # ====================================================
        # VERSION CARD
        # ====================================================

        version_card = QFrame()

        version_card.setObjectName(
            "card"
        )

        version_layout = QHBoxLayout(
            version_card
        )

        version_layout.setContentsMargins(
            20,
            15,
            20,
            15
        )

        left = QVBoxLayout()

        label = QLabel(
            "ТЕКУЩАЯ УСТАНОВКА"
        )

        label.setObjectName(
            "section"
        )

        self.version_label = QLabel()

        self.version_label.setObjectName(
            "version"
        )

        if self.installed_version:

            self.version_label.setText(
                "Установлена версия: "
                + self.installed_version
            )

        else:

            self.version_label.setText(
                "ServerGuard ещё не установлен"
            )

        left.addWidget(
            label
        )

        left.addWidget(
            self.version_label
        )

        version_layout.addLayout(
            left
        )

        version_layout.addStretch()

        self.ready_status = QLabel(
            "● Проверка..."
        )

        self.ready_status.setStyleSheet(
            f"""
            color: {ACCENT};
            font-weight: 600;
            """
        )

        version_layout.addWidget(
            self.ready_status
        )

        root.addWidget(
            version_card
        )

        # ====================================================
        # STATUS CARD
        # ====================================================

        status_card = QFrame()

        status_card.setObjectName(
            "card"
        )

        status_layout = QVBoxLayout(
            status_card
        )

        status_layout.setContentsMargins(
            20,
            16,
            20,
            16
        )

        self.status_label = QLabel(
            "Проверка обновлений..."
        )

        self.status_label.setObjectName(
            "status"
        )

        self.progress = QProgressBar()

        self.progress.setRange(
            0,
            100
        )

        self.progress.setValue(
            0
        )

        self.progress.setTextVisible(
            False
        )

        status_layout.addWidget(
            self.status_label
        )

        status_layout.addSpacing(
            10
        )

        status_layout.addWidget(
            self.progress
        )

        root.addWidget(
            status_card
        )

        # ====================================================
        # LOG
        # ====================================================

        log_label = QLabel(
            "ЖУРНАЛ УСТАНОВКИ"
        )

        log_label.setObjectName(
            "section"
        )

        root.addWidget(
            log_label
        )

        self.log_box = QTextEdit()

        self.log_box.setReadOnly(
            True
        )

        self.log_box.setMinimumHeight(
            195
        )

        root.addWidget(
            self.log_box
        )

        # ====================================================
        # BUTTONS
        # ====================================================

        buttons = QHBoxLayout()

        self.cancel_button = QPushButton(
            "Закрыть"
        )

        self.cancel_button.setObjectName(
            "secondary"
        )

        self.cancel_button.clicked.connect(
            self.close
        )

        self.install_button = QPushButton(
            "Проверка..."
        )

        self.install_button.setObjectName(
            "primary"
        )

        self.install_button.setEnabled(
            False
        )

        self.install_button.clicked.connect(
            self.start_installation
        )

        self.launch_button = QPushButton(
            "Запустить ServerGuard"
        )

        self.launch_button.setObjectName(
            "success"
        )

        self.launch_button.setEnabled(
            False
        )

        self.launch_button.clicked.connect(
            self.launch_serverguard
        )

        buttons.addWidget(
            self.cancel_button
        )

        buttons.addStretch()

        buttons.addWidget(
            self.install_button
        )

        buttons.addWidget(
            self.launch_button
        )

        root.addLayout(
            buttons
        )

        self.add_log(
            "ServerGuard Setup запущен."
        )

        if self.installed_version:

            self.add_log(
                "Текущая версия: "
                + self.installed_version
            )

        else:

            self.add_log(
                "ServerGuard ещё не установлен."
            )

    # ========================================================
    # LOG
    # ========================================================

    def add_log(
        self,
        text
    ):

        self.log_box.append(
            "<span style='color:#4f8cff'>›</span> "
            + text
        )

    # ========================================================
    # CHECK FOR UPDATES
    # ========================================================

    def check_for_updates(self):

        self.install_button.setEnabled(
            False
        )

        self.ready_status.setText(
            "● Проверка обновлений"
        )

        self.ready_status.setStyleSheet(
            f"""
            color: {ACCENT};
            font-weight: 600;
            """
        )

        self.status_label.setText(
            "Проверка последней версии..."
        )

        QApplication.processEvents()

        try:

            self.add_log(
                "Проверка manifest.json..."
            )

            self.manifest = (
                download_manifest()
            )

            self.remote_version = str(
                self.manifest.get(
                    "version",
                    ""
                )
            ).strip()

            if not self.remote_version:

                raise RuntimeError(
                    "В manifest.json отсутствует version."
                )

            self.add_log(
                "Последняя версия: "
                + self.remote_version
            )

            # ------------------------------------------------
            # NOT INSTALLED
            # ------------------------------------------------

            if (
                not self.installed_version
                or not SERVERGUARD_EXE.exists()
            ):

                self.status_label.setText(
                    "ServerGuard готов к установке."
                )

                self.ready_status.setText(
                    "● Готов к установке"
                )

                self.ready_status.setStyleSheet(
                    f"""
                    color: {SUCCESS};
                    font-weight: 600;
                    """
                )

                self.install_button.setText(
                    "Установить ServerGuard"
                )

                self.install_button.setEnabled(
                    True
                )

                self.launch_button.setEnabled(
                    False
                )

                self.add_log(
                    "ServerGuard не установлен."
                )

                return

            # ------------------------------------------------
            # COMPARE
            # ------------------------------------------------

            comparison = compare_versions(
                self.installed_version,
                self.remote_version
            )

            self.add_log(
                f"Сравнение версий: "
                f"{self.installed_version} "
                f"vs "
                f"{self.remote_version}"
            )

            # ------------------------------------------------
            # UPDATE AVAILABLE
            # ------------------------------------------------

            if comparison < 0:

                self.status_label.setText(
                    "Доступно новое обновление."
                )

                self.status_label.setStyleSheet(
                    f"color: {ACCENT};"
                )

                self.ready_status.setText(
                    "● Доступно обновление"
                )

                self.ready_status.setStyleSheet(
                    f"""
                    color: {ACCENT};
                    font-weight: 600;
                    """
                )

                self.install_button.setText(
                    "Обновить до "
                    + self.remote_version
                )

                self.install_button.setEnabled(
                    True
                )

                self.launch_button.setEnabled(
                    True
                )

                self.add_log(
                    "Найдено новое обновление:"
                )

                self.add_log(
                    f"{self.installed_version} "
                    f"→ "
                    f"{self.remote_version}"
                )

            # ------------------------------------------------
            # SAME VERSION
            # ------------------------------------------------

            elif comparison == 0:

                self.status_label.setText(
                    "Установлена последняя версия."
                )

                self.status_label.setStyleSheet(
                    f"color: {SUCCESS};"
                )

                self.ready_status.setText(
                    "● Последняя версия"
                )

                self.ready_status.setStyleSheet(
                    f"""
                    color: {SUCCESS};
                    font-weight: 600;
                    """
                )

                self.install_button.setText(
                    "Переустановить"
                )

                self.install_button.setEnabled(
                    True
                )

                self.launch_button.setEnabled(
                    True
                )

                self.add_log(
                    "Установлена последняя версия."
                )

            # ------------------------------------------------
            # LOCAL VERSION NEWER
            # ------------------------------------------------

            else:

                self.status_label.setText(
                    "Установлена более новая версия."
                )

                self.status_label.setStyleSheet(
                    f"color: {WARNING};"
                )

                self.ready_status.setText(
                    "● Локальная версия новее"
                )

                self.ready_status.setStyleSheet(
                    f"""
                    color: {WARNING};
                    font-weight: 600;
                    """
                )

                self.install_button.setText(
                    "Переустановить"
                )

                self.install_button.setEnabled(
                    True
                )

                self.launch_button.setEnabled(
                    True
                )

                self.add_log(
                    "Локальная версия новее версии "
                    "на GitHub."
                )

        except Exception as error:

            self.status_label.setText(
                "Не удалось проверить обновления."
            )

            self.status_label.setStyleSheet(
                f"color: {ERROR};"
            )

            self.ready_status.setText(
                "● Ошибка проверки"
            )

            self.ready_status.setStyleSheet(
                f"""
                color: {ERROR};
                font-weight: 600;
                """
            )

            self.install_button.setText(
                "Повторить проверку"
            )

            self.install_button.setEnabled(
                True
            )

            try:

                self.install_button.clicked.disconnect()

            except Exception:
                pass

            self.install_button.clicked.connect(
                self.retry_update_check
            )

            self.launch_button.setEnabled(
                (
                    SERVERGUARD_EXE.exists()
                    and
                    bool(
                        self.installed_version
                    )
                )
            )

            self.add_log(
                "Ошибка проверки: "
                + str(error)
            )

    # ========================================================
    # RETRY CHECK
    # ========================================================

    def retry_update_check(self):

        try:

            self.install_button.clicked.disconnect()

        except Exception:
            pass

        self.install_button.clicked.connect(
            self.start_installation
        )

        self.check_for_updates()

    # ========================================================
    # START INSTALLATION / UPDATE
    # ========================================================

    def start_installation(self):

        if (
            self.worker
            and self.worker.isRunning()
        ):
            return

        if not self.manifest:

            try:

                self.manifest = (
                    download_manifest()
                )

                self.remote_version = str(
                    self.manifest.get(
                        "version",
                        ""
                    )
                ).strip()

            except Exception as error:

                show_dialog(
                    self,
                    "Ошибка",
                    (
                        "Не удалось получить "
                        "информацию о версии.\n\n"
                        f"{error}"
                    ),
                    "error"
                )

                return

        update_mode = (
            bool(self.installed_version)
            and SERVERGUARD_EXE.exists()
            and bool(self.remote_version)
            and
            compare_versions(
                self.installed_version,
                self.remote_version
            ) < 0
        )

        # ----------------------------------------------------
        # UI
        # ----------------------------------------------------

        self.install_button.setEnabled(
            False
        )

        self.cancel_button.setEnabled(
            False
        )

        self.launch_button.setEnabled(
            False
        )

        self.ready_status.setText(
            "● "
            + (
                "Обновление выполняется"
                if update_mode
                else
                "Установка выполняется"
            )
        )

        self.ready_status.setStyleSheet(
            f"""
            color: {ACCENT};
            font-weight: 600;
            """
        )

        self.status_label.setText(
            (
                "Подготовка обновления..."
                if update_mode
                else
                "Подготовка установки..."
            )
        )

        self.progress.setValue(
            0
        )

        self.add_log(
            "--------------------------------"
        )

        if update_mode:

            self.add_log(
                "Начало обновления ServerGuard."
            )

            self.add_log(
                f"{self.installed_version} "
                f"→ "
                f"{self.remote_version}"
            )

        else:

            self.add_log(
                "Начало установки ServerGuard."
            )

        self.worker = InstallerWorker(
            update_mode=update_mode
        )

        self.worker.progress.connect(
            self.progress.setValue
        )

        self.worker.status.connect(
            self.status_label.setText
        )

        self.worker.log.connect(
            self.add_log
        )

        self.worker.success.connect(
            self.installation_success
        )

        self.worker.failure.connect(
            self.installation_failed
        )

        self.worker.start()

    # ========================================================
    # SUCCESS
    # ========================================================

    def installation_success(
        self,
        version,
        was_update
    ):

        self.installed_version = (
            version
        )

        self.version_label.setText(
            "Установлена версия: "
            + version
        )

        self.status_label.setText(
            (
                "ServerGuard успешно обновлён."
                if was_update
                else
                "ServerGuard успешно установлен."
            )
        )

        self.status_label.setStyleSheet(
            f"color: {SUCCESS};"
        )

        self.ready_status.setText(
            "● "
            + (
                "Обновлено"
                if was_update
                else
                "Установлено"
            )
        )

        self.ready_status.setStyleSheet(
            f"""
            color: {SUCCESS};
            font-weight: 600;
            """
        )

        self.progress.setValue(
            100
        )

        self.install_button.setVisible(
            False
        )

        self.cancel_button.setEnabled(
            True
        )

        self.launch_button.setEnabled(
            True
        )

        self.add_log(
            (
                "Обновление завершено успешно."
                if was_update
                else
                "Установка завершена успешно."
            )
        )

        self.add_log(
            f"Версия ServerGuard: {version}"
        )

        show_dialog(
            self,
            (
                "Обновление завершено"
                if was_update
                else
                "Установка завершена"
            ),
            (
                f"ServerGuard успешно "
                f"{'обновлён' if was_update else 'установлен'}.\n\n"
                f"Версия: {version}"
            ),
            "success"
        )

    # ========================================================
    # ERROR
    # ========================================================

    def installation_failed(
        self,
        error,
        was_update
    ):

        self.status_label.setText(
            (
                "Ошибка обновления"
                if was_update
                else
                "Ошибка установки"
            )
        )

        self.status_label.setStyleSheet(
            f"color: {ERROR};"
        )

        self.ready_status.setText(
            "● Ошибка"
        )

        self.ready_status.setStyleSheet(
            f"""
            color: {ERROR};
            font-weight: 600;
            """
        )

        self.install_button.setEnabled(
            True
        )

        self.cancel_button.setEnabled(
            True
        )

        self.launch_button.setEnabled(
            SERVERGUARD_EXE.exists()
        )

        self.add_log(
            "ОШИБКА: "
            + error
        )

        if was_update:

            message = (
                "Не удалось обновить "
                "ServerGuard.\n\n"
                f"{error}\n\n"
                "Если обновление уже успело "
                "заменить файлы, Setup попытался "
                "автоматически восстановить "
                "предыдущую версию."
            )

        else:

            message = (
                "Не удалось установить "
                "ServerGuard.\n\n"
                f"{error}"
            )

        show_dialog(
            self,
            (
                "Ошибка обновления"
                if was_update
                else
                "Ошибка установки"
            ),
            message,
            "error"
        )

    # ========================================================
    # LAUNCH SERVERGUARD
    # ========================================================

    def launch_serverguard(self):

        if not SERVERGUARD_EXE.exists():

            show_dialog(
                self,
                "ServerGuard не найден",
                (
                    "Файл ServerGuard.exe "
                    "не найден.\n\n"
                    "Ожидаемый путь:\n"
                    f"{SERVERGUARD_EXE}"
                ),
                "error"
            )

            return

        if is_serverguard_running():

            self.add_log(
                "ServerGuard уже запущен."
            )

            self.status_label.setText(
                "ServerGuard уже запущен"
            )

            self.close()

            return

        self.add_log(
            "Запуск ServerGuard..."
        )

        self.status_label.setText(
            "Запуск ServerGuard..."
        )

        self.ready_status.setText(
            "● Запуск"
        )

        self.ready_status.setStyleSheet(
            f"""
            color: {ACCENT};
            font-weight: 600;
            """
        )

        self.launch_button.setEnabled(
            False
        )

        self.cancel_button.setEnabled(
            False
        )

        self.install_button.setEnabled(
            False
        )

        QApplication.processEvents()

        try:

            process = subprocess.Popen(
                [
                    str(
                        SERVERGUARD_EXE
                    )
                ],
                cwd=str(
                    INSTALL_DIRECTORY
                ),
                creationflags=(
                    subprocess.CREATE_NEW_CONSOLE
                )
            )

        except Exception as error:

            self.launch_button.setEnabled(
                True
            )

            self.cancel_button.setEnabled(
                True
            )

            self.status_label.setText(
                "Ошибка запуска"
            )

            self.ready_status.setText(
                "● Ошибка"
            )

            self.ready_status.setStyleSheet(
                f"""
                color: {ERROR};
                font-weight: 600;
                """
            )

            self.add_log(
                "Ошибка запуска ServerGuard."
            )

            show_dialog(
                self,
                "Ошибка запуска",
                (
                    "Не удалось запустить "
                    "ServerGuard.exe.\n\n"
                    f"{error}"
                ),
                "error"
            )

            return

        started = False

        for _ in range(20):

            time.sleep(
                0.15
            )

            QApplication.processEvents()

            if process.poll() is None:

                started = True
                break

        if started:

            self.add_log(
                "ServerGuard успешно запущен."
            )

            self.status_label.setText(
                "ServerGuard запущен"
            )

            self.ready_status.setText(
                "● Работает"
            )

            self.ready_status.setStyleSheet(
                f"""
                color: {SUCCESS};
                font-weight: 600;
                """
            )

            QApplication.processEvents()

            time.sleep(
                0.5
            )

            self.close()

            return

        exit_code = process.returncode

        self.launch_button.setEnabled(
            True
        )

        self.cancel_button.setEnabled(
            True
        )

        self.status_label.setText(
            "ServerGuard не запустился"
        )

        self.ready_status.setText(
            "● Ошибка"
        )

        self.ready_status.setStyleSheet(
            f"""
            color: {ERROR};
            font-weight: 600;
            """
        )

        self.add_log(
            "ServerGuard завершился "
            "сразу после запуска."
        )

        self.add_log(
            f"Код завершения: {exit_code}"
        )

        show_dialog(
            self,
            "ServerGuard не запустился",
            (
                "ServerGuard.exe был запущен, "
                "но сразу завершил работу.\n\n"
                f"Код завершения: {exit_code}\n\n"
                "Проверь запуск непосредственно "
                "из папки:\n"
                f"{INSTALL_DIRECTORY}"
            ),
            "error"
        )


# ============================================================
# APPLICATION
# ============================================================

def main():

    # --------------------------------------------------------
    # Убираем консоль самого Setup
    # --------------------------------------------------------

    if sys.platform == "win32":

        try:

            ctypes.windll.kernel32.FreeConsole()

        except Exception:
            pass

    # --------------------------------------------------------
    # ADMIN
    # --------------------------------------------------------

    if not is_admin():

        try:

            restart_as_admin()

        except Exception as error:

            ctypes.windll.user32.MessageBoxW(
                0,
                str(error),
                "ServerGuard Setup",
                0x10
            )

            sys.exit(1)

    # --------------------------------------------------------
    # QT
    # --------------------------------------------------------

    app = QApplication(
        sys.argv
    )

    app.setApplicationName(
        "ServerGuard Setup"
    )

    app.setOrganizationName(
        "ServerGuard"
    )

    app.setStyle(
        "Fusion"
    )

    app.setWindowIcon(
        create_shield_icon()
    )

    window = InstallerWindow()

    window.show()

    sys.exit(
        app.exec()
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()