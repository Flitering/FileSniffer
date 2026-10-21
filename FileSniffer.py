"""
FileSniffer — анализ папок и архивов, поиск «неважных» данных и их безопасная очистка.

Запуск:
    python FileSniffer.py [папка]
"""
import os
import sys
import json
import time
import shutil
import zipfile
from dataclasses import dataclass, field

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Font
from send2trash import send2trash

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTableView, QVBoxLayout, QWidget, QPushButton,
    QMessageBox, QFileDialog, QLabel, QHBoxLayout, QHeaderView, QPlainTextEdit,
    QProgressBar, QLineEdit, QCheckBox, QSplitter, QAbstractItemView, QDialog,
    QDialogButtonBox, QGroupBox, QGridLayout, QSpinBox, QFormLayout
)
from PyQt5.QtCore import (
    QSortFilterProxyModel, Qt, QTimer, QThread, pyqtSignal, QItemSelection, QItemSelectionModel
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QColor, QBrush

__version__ = "1.0.0"
APP_NAME = "FileSniffer"

# --- Настройки определения файлов ---
# Категории «важных» файлов, из которых пользователь собирает свой набор
CATEGORIES = {
    "photos": ("Фото", ".jpg .jpeg .png .gif .bmp .tif .tiff .heic .heif .webp .raw .cr2 .cr3 .nef .arw .dng"),
    "documents": ("Документы", ".pdf .doc .docx .odt .rtf .djvu .epub .fb2"),
    "spreadsheets": ("Таблицы и презентации", ".xls .xlsx .xlsm .ods .csv .ppt .pptx .odp"),
    "video": ("Видео", ".mp4 .mov .avi .mkv .wmv .m4v .3gp .webm .mts"),
    "audio": ("Музыка и звук", ".mp3 .flac .wav .m4a .aac .ogg .wma .opus"),
    "design": ("Дизайн и чертежи", ".psd .ai .svg .cdr .indd .fig .sketch .dwg .dxf .blend .fbx .obj"),
    "code": ("Исходный код", ".py .js .ts .java .cs .cpp .c .h .go .rs .php .rb .sql .ipynb"),
    "mail": ("Почта и базы", ".pst .ost .eml .msg .mdb .accdb .sqlite .kdbx"),
}
DEFAULT_CATEGORIES = ["photos", "documents", "spreadsheets"]
DEFAULT_METADATA = ".tmp .db .sys .ini .log"

METADATA_EXTENSIONS = set()
NECESSARY_EXTENSIONS = set()
ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z'}
PREVIEW_LIMIT = 10
# Запас свободного места при распаковке (доля от свободного места на диске)
FREE_SPACE_RESERVE = 0.9

STATUS_IMPORTANT = "Важное"
STATUS_NESTED = "Важное (во вложенных)"
STATUS_NORMAL = "Обычное"
STATUS_ERROR = "Ошибка"
TYPE_FOLDER = "Папка"
TYPE_ARCHIVE = "Архив"

COLUMNS = ["Путь к папке", "Количество файлов", "Файлы в папке (первые 10)", "Файлы метаданных",
           "Размер файлов", "Размер с вложенными", "Изменено", "Статус", "Тип"]
COL_STATUS = COLUMNS.index("Статус")
SORT_ROLE = Qt.UserRole
RECORD_ROLE = Qt.UserRole + 1


def parse_extensions(text):
    """'.jpg, png;  .PDF' -> {'.jpg', '.png', '.pdf'}"""
    result = set()
    for token in text.replace(",", " ").replace(";", " ").split():
        token = token.strip().lower()
        if token and token != ".":
            result.add(token if token.startswith(".") else "." + token)
    return result


def format_extensions(exts):
    return " ".join(sorted(exts))


# --- Хранение настроек ---

def settings_path():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, APP_NAME, "settings.json")


def default_settings():
    return {"categories": list(DEFAULT_CATEGORIES), "custom": "", "metadata": DEFAULT_METADATA}


def load_settings():
    settings = default_settings()
    try:
        with open(settings_path(), encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            if isinstance(data.get("categories"), list):
                settings["categories"] = [c for c in data["categories"] if c in CATEGORIES]
            for key in ("custom", "metadata"):
                if isinstance(data.get(key), str):
                    settings[key] = data[key]
    except (OSError, ValueError):
        pass
    return settings


def save_settings(settings):
    p = settings_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(settings, f, ensure_ascii=False, indent=2)


def apply_settings(settings):
    """Пересобирает наборы расширений. Вызывать только когда нет фоновых задач."""
    necessary = set()
    for key in settings["categories"]:
        necessary |= parse_extensions(CATEGORIES[key][1])
    necessary |= parse_extensions(settings["custom"])
    NECESSARY_EXTENSIONS.clear()
    NECESSARY_EXTENSIONS.update(necessary - ARCHIVE_EXTENSIONS)
    METADATA_EXTENSIONS.clear()
    METADATA_EXTENSIONS.update(parse_extensions(settings["metadata"]) - NECESSARY_EXTENSIONS)


apply_settings(default_settings())


def _oem_encoding():
    """Кодировка имён в ZIP без флага UTF-8 (так пишут архиваторы Windows, напр. cp866)."""
    if sys.platform == "win32":
        try:
            import ctypes
            return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
        except Exception:
            pass
    return "cp437"


OEM_ENCODING = _oem_encoding()


@dataclass
class Record:
    path: str
    kind: str
    file_count: int = 0
    files: list = field(default_factory=list)
    metadata_files: list = field(default_factory=list)
    size: int = 0          # для папки — сумма её файлов, для архива — распакованный размер
    total_size: int = 0    # место на диске вместе со всем вложенным
    mtime: float = 0.0     # самое свежее изменение внутри (с учётом вложенного)
    important: bool = False
    nested_protected: bool = False
    encrypted: bool = False
    error: str = ""

    @property
    def protected(self):
        """Запись нельзя удалять: важное содержимое, шифрование, ошибка чтения или защищённые вложения."""
        return self.important or self.nested_protected or self.encrypted or bool(self.error)

    @property
    def status(self):
        if self.error:
            return f"{STATUS_ERROR}: {self.error}"
        if self.important:
            status = STATUS_IMPORTANT
        elif self.nested_protected:
            status = STATUS_NESTED
        else:
            status = STATUS_NORMAL
        if self.encrypted:
            status += " (Зашифрован)"
        return status

    @property
    def files_preview(self):
        return ', '.join(self.files[:PREVIEW_LIMIT]) + ('...' if self.file_count > PREVIEW_LIMIT else '')

    @property
    def age_days(self):
        return (time.time() - self.mtime) / 86400 if self.mtime else 0


def ext_of(name):
    return os.path.splitext(name)[1].lower()


def is_necessary_file(filename):
    return ext_of(filename) in NECESSARY_EXTENSIONS


def is_metadata_file(filename):
    return ext_of(filename) in METADATA_EXTENSIONS


def is_archive_file(filename):
    return ext_of(filename) in ARCHIVE_EXTENSIONS


def is_link(p):
    """Символическая ссылка или точка соединения (junction) — по ним не ходим."""
    isjunction = getattr(os.path, "isjunction", None)
    return os.path.islink(p) or bool(isjunction and isjunction(p))


def is_inside(child, parent):
    """child лежит строго внутри parent (с учётом регистра и нормализации путей)."""
    child = os.path.normcase(os.path.abspath(child))
    parent = os.path.normcase(os.path.abspath(parent))
    try:
        return child != parent and os.path.commonpath([child, parent]) == parent
    except ValueError:  # разные диски
        return False


def is_risky_root(p):
    """Корень диска или системная папка — сканировать можно, но удалять оттуда опасно."""
    p = os.path.normcase(os.path.abspath(p))
    if os.path.dirname(p) == p:
        return True
    system = [os.environ.get(v) for v in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData")]
    return any(s and (p == os.path.normcase(s) or is_inside(p, s) or is_inside(s, p)) for s in system)


def human_size(size):
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if size < 1024 or unit == "ТБ":
            return f"{size:.0f} {unit}" if unit == "Б" else f"{size:.1f} {unit}"
        size /= 1024


def format_time(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else ""


def zip_member_name(info):
    if info.flag_bits & 0x800:
        return info.filename
    try:
        return info.filename.encode("cp437").decode(OEM_ENCODING)
    except UnicodeError:
        return info.filename


# --- Чтение архивов ---

def _list_zip(archive_path):
    """Возвращает [(имя, размер, является_папкой, является_ссылкой)], признак шифрования."""
    entries, encrypted = [], False
    with zipfile.ZipFile(archive_path, 'r') as z:
        for info in z.infolist():
            if info.flag_bits & 0x1:
                encrypted = True
            # Unix-симлинк в external_attr (S_IFLNK)
            link = (info.external_attr >> 16) & 0o170000 == 0o120000
            entries.append((zip_member_name(info), info.file_size, info.is_dir(), link))
    return entries, encrypted


def _list_rar(archive_path):
    import rarfile
    entries = []
    with rarfile.RarFile(archive_path) as rf:
        encrypted = rf.needs_password()
        for info in rf.infolist():
            if info.needs_password():
                encrypted = True
            entries.append((info.filename, info.file_size, info.is_dir(), info.is_symlink()))
    return entries, encrypted


def _list_7z(archive_path):
    import py7zr
    entries = []
    with py7zr.SevenZipFile(archive_path, mode='r') as archive:
        encrypted = archive.needs_password()
        if not encrypted:
            for info in archive.list():
                entries.append((info.filename, info.uncompressed or 0, info.is_directory,
                                getattr(info, "is_symlink", False)))
    return entries, encrypted


ARCHIVE_LISTERS = {'.zip': _list_zip, '.rar': _list_rar, '.7z': _list_7z}


def scan_archive(archive_path):
    record = Record(path=archive_path, kind=TYPE_ARCHIVE)
    try:
        st = os.stat(archive_path)
        record.total_size, record.mtime = st.st_size, st.st_mtime
    except OSError:
        pass
    lister = ARCHIVE_LISTERS.get(ext_of(archive_path))
    if lister is None:
        record.error = "неподдерживаемый формат"
        return record
    try:
        entries, record.encrypted = lister(archive_path)
    except ImportError as e:
        record.error = f"не установлена библиотека {e.name}"
        return record
    except Exception as e:
        record.error = str(e) or type(e).__name__
        return record
    for name, size, is_dir, _ in entries:
        if is_dir:
            continue
        record.file_count += 1
        record.size += size
        if len(record.files) < PREVIEW_LIMIT:
            record.files.append(name)
        if is_metadata_file(name):
            record.metadata_files.append(name)
        if is_necessary_file(name):
            record.important = True
    return record


# --- Сканирование ---

def scan_tree(root_path, on_progress=None, is_cancelled=lambda: False):
    """Обходит дерево и возвращает список Record для папок и архивов (None — если отменено)."""
    records = []
    folders = {}

    def on_error(err):
        rec = Record(path=err.filename or root_path, kind=TYPE_FOLDER, error=err.strerror or str(err))
        records.append(rec)
        folders[os.path.normcase(os.path.normpath(rec.path))] = rec

    for root, dirs, files in os.walk(root_path, onerror=on_error):
        if is_cancelled():
            return None
        dirs[:] = [d for d in dirs if not is_link(os.path.join(root, d))]
        rec = Record(path=root, kind=TYPE_FOLDER)
        archives = []
        for f in files:
            full = os.path.join(root, f)
            if is_archive_file(f):
                archives.append(full)
                continue
            rec.file_count += 1
            if len(rec.files) < PREVIEW_LIMIT:
                rec.files.append(f)
            if is_metadata_file(f):
                rec.metadata_files.append(f)
            if is_necessary_file(f):
                rec.important = True
            try:
                st = os.stat(full)
                rec.size += st.st_size
                rec.mtime = max(rec.mtime, st.st_mtime)
            except OSError:
                pass
        rec.total_size = rec.size
        records.append(rec)
        folders[os.path.normcase(os.path.normpath(root))] = rec
        if on_progress:
            on_progress(root, len(records))
        for archive_path in archives:
            if is_cancelled():
                return None
            records.append(scan_archive(archive_path))

    _propagate(records, folders, root_path)
    return records


def _ancestors(rec_path, folders, root_path):
    """Записи родительских папок от ближайшей до корня сканирования."""
    root_key = os.path.normcase(os.path.normpath(root_path))
    parent = os.path.dirname(os.path.normpath(rec_path))
    while True:
        key = os.path.normcase(parent)
        folder = folders.get(key)
        if folder is not None:
            yield folder
        if key == root_key or not is_inside(parent, root_path):
            return
        next_parent = os.path.dirname(parent)
        if next_parent == parent:
            return
        parent = next_parent


def _propagate(records, folders, root_path):
    """Поднимает к родителям размер, дату изменения и признак «внутри есть защищённое»."""
    for rec in records:
        if rec.kind == TYPE_FOLDER and rec.error:
            continue
        own = rec.size if rec.kind == TYPE_FOLDER else rec.total_size
        for folder in _ancestors(rec.path, folders, root_path):
            folder.total_size += own
            folder.mtime = max(folder.mtime, rec.mtime)
    for rec in records:
        if not (rec.important or rec.encrypted or rec.error):
            continue
        for folder in _ancestors(rec.path, folders, root_path):
            if folder.nested_protected:
                break  # выше уже помечено
            folder.nested_protected = True


# --- Отчёт ---

def _cell_text(value):
    return ILLEGAL_CHARACTERS_RE.sub("", str(value))


def save_report(records, filename):
    wb = Workbook()
    ws = wb.active
    ws.title = "Отчёт"
    headers = COLUMNS[:4] + ["Размер файлов (байт)", "Размер с вложенными (байт)"] + COLUMNS[6:]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)
    for row_idx, rec in enumerate(records, start=2):
        values = [rec.path, rec.file_count, rec.files_preview, ', '.join(rec.metadata_files),
                  rec.size, rec.total_size, format_time(rec.mtime), rec.status, rec.kind]
        for col_idx, value in enumerate(values, start=1):
            cell = ws.cell(row=row_idx, column=col_idx)
            if isinstance(value, int):
                cell.value = value
            else:
                # Явно строковый тип: имя файла вида "=HYPERLINK(...)" не станет формулой
                cell.value = _cell_text(value)
                cell.data_type = "s"
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    for col, width in zip("ABCDEFGHI", (80, 12, 60, 40, 18, 22, 17, 22, 10)):
        ws.column_dimensions[col].width = width
    wb.save(filename)


# --- Удаление ---

def check_deletable(target, root_path):
    """Повторная проверка непосредственно перед удалением. Возвращает (можно, причина)."""
    if not is_inside(target, root_path):
        return False, "вне сканируемой папки"
    if not os.path.lexists(target):
        return False, "не существует"
    if is_link(target):
        return False, "символическая ссылка"
    if os.path.isfile(target):
        if not is_archive_file(target):
            return False, "не архив"
        rec = scan_archive(target)
        return (False, rec.status) if rec.protected else (True, "")

    problems = []

    def on_error(err):
        problems.append(f"нет доступа к {err.filename}")

    for root, dirs, files in os.walk(target, onerror=on_error):
        dirs[:] = [d for d in dirs if not is_link(os.path.join(root, d))]
        for f in files:
            if is_necessary_file(f):
                return False, f"найден важный файл {os.path.join(root, f)}"
            if is_archive_file(f):
                rec = scan_archive(os.path.join(root, f))
                if rec.protected:
                    return False, f"архив {os.path.join(root, f)}: {rec.status}"
        if problems:
            return False, problems[0]
    if problems:
        return False, problems[0]
    return True, ""


def top_level_paths(paths):
    """Оставляет только самые верхние пути: удаление папки удаляет и всё вложенное."""
    # Сортировка по компонентам пути ставит вложенные пути сразу после родителя
    normalized = sorted({os.path.normpath(p) for p in paths}, key=lambda p: os.path.normcase(p).split(os.sep))
    result, last = [], None
    for p in normalized:
        key = os.path.normcase(p)
        if last is not None and (key == last or key.startswith(last.rstrip(os.sep) + os.sep)):
            continue
        result.append(p)
        last = key
    return result


def _remove_readonly(func, p, _exc):
    os.chmod(p, 0o666)
    func(p)


def delete_path(target, permanent):
    if not permanent:
        send2trash(target)
    elif os.path.isdir(target):
        shutil.rmtree(target, onerror=_remove_readonly)
    else:
        os.remove(target)


# --- Распаковка ---

def unique_path(p):
    if not os.path.exists(p):
        return p
    i = 1
    while os.path.exists(f"{p}_{i}"):
        i += 1
    return f"{p}_{i}"


def safe_member_target(dest_root, member_name):
    """Путь для элемента архива внутри dest_root; защита от Zip Slip (../, абсолютные пути, C:, ADS)."""
    name = member_name.replace("\\", "/")
    if ":" in name or name.startswith("/"):
        raise ValueError(f"недопустимое имя в архиве: {member_name}")
    target = os.path.normpath(os.path.join(dest_root, name))
    if not is_inside(target, dest_root):
        raise ValueError(f"элемент архива выходит за пределы папки: {member_name}")
    return target


def _check_entries(entries, encrypted, dest_root):
    if encrypted:
        raise ValueError("архив зашифрован")
    total = 0
    for name, size, _is_dir, link in entries:
        if link:
            raise ValueError(f"архив содержит символическую ссылку: {name}")
        safe_member_target(dest_root, name)
        total += size
    free = shutil.disk_usage(os.path.dirname(dest_root)).free
    if total > free * FREE_SPACE_RESERVE:
        raise ValueError(f"недостаточно места: нужно {human_size(total)}, свободно {human_size(free)}")


def extract_archive(archive_path, destination):
    ext = ext_of(archive_path)
    if ext not in ARCHIVE_LISTERS:
        raise ValueError("неподдерживаемый формат")
    dest_root = unique_path(os.path.join(destination, os.path.splitext(os.path.basename(archive_path))[0]))
    entries, encrypted = ARCHIVE_LISTERS[ext](archive_path)
    _check_entries(entries, encrypted, dest_root)
    os.makedirs(dest_root)
    if ext == '.zip':
        with zipfile.ZipFile(archive_path, 'r') as z:
            for info in z.infolist():
                target = safe_member_target(dest_root, zip_member_name(info))
                if info.is_dir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with z.open(info) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
    elif ext == '.rar':
        import rarfile
        with rarfile.RarFile(archive_path) as rf:
            rf.extractall(dest_root)
    else:
        import py7zr
        with py7zr.SevenZipFile(archive_path, mode='r') as archive:
            archive.extractall(path=dest_root)
    return dest_root


def extract_item(item_path, destination):
    if os.path.isdir(item_path):
        dest = unique_path(os.path.join(destination, os.path.basename(os.path.normpath(item_path))))
        if is_inside(dest, item_path):
            raise ValueError("нельзя копировать папку внутрь самой себя")
        shutil.copytree(item_path, dest, symlinks=True)
        return dest
    return extract_archive(item_path, destination)


# --- Фоновые задачи ---

class ScanWorker(QThread):
    progress = pyqtSignal(str, int)
    done = pyqtSignal(object)

    def __init__(self, root_path):
        super().__init__()
        self.root_path = root_path
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        records = scan_tree(self.root_path, self.progress.emit, lambda: self._cancelled)
        self.done.emit(records)


class DeletionWorker(QThread):
    progress = pyqtSignal(int)
    logMessage = pyqtSignal(str)
    done = pyqtSignal(list)

    def __init__(self, paths, root_path, permanent=False):
        super().__init__()
        self.paths = paths
        self.root_path = root_path
        self.permanent = permanent

    def run(self):
        deleted = []
        total = len(self.paths)
        for i, p in enumerate(self.paths):
            try:
                ok, reason = check_deletable(p, self.root_path)
                if not ok:
                    self.logMessage.emit(f"Пропущено {p}: {reason}")
                else:
                    delete_path(p, self.permanent)
                    deleted.append(p)
                    action = "Удалено навсегда" if self.permanent else "Перемещено в корзину"
                    self.logMessage.emit(f"{action}: {p}")
            except Exception as e:
                self.logMessage.emit(f"Ошибка при удалении {p}: {e}")
            self.progress.emit(int((i + 1) / total * 100))
        self.done.emit(deleted)


class ExtractWorker(QThread):
    progress = pyqtSignal(int)
    logMessage = pyqtSignal(str)
    done = pyqtSignal(list)

    def __init__(self, paths, destination):
        super().__init__()
        self.paths = paths
        self.destination = destination

    def run(self):
        errors = []
        for i, p in enumerate(self.paths):
            try:
                dest = extract_item(p, self.destination)
                self.logMessage.emit(f"Готово: {p} → {dest}")
            except Exception as e:
                errors.append(p)
                self.logMessage.emit(f"Не удалось распаковать {p}: {e}")
            self.progress.emit(int((i + 1) / len(self.paths) * 100))
        self.done.emit(errors)


# --- Интерфейс ---

class SettingsDialog(QDialog):
    """Выбор типов файлов, которые считаются важными и защищают папку от удаления."""

    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Какие файлы считать важными")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)

        group = QGroupBox("Важные файлы: папка или архив с ними не будут удалены")
        grid = QGridLayout(group)
        self.checks = {}
        for i, (key, (title, exts)) in enumerate(CATEGORIES.items()):
            cb = QCheckBox(title)
            cb.setChecked(key in settings["categories"])
            cb.setToolTip(exts)
            grid.addWidget(cb, i // 2, i % 2)
            self.checks[key] = cb
        layout.addWidget(group)

        form = QFormLayout()
        self.custom_edit = QLineEdit(settings["custom"])
        self.custom_edit.setPlaceholderText("например: .dat .bak .sav")
        form.addRow("Свои важные расширения:", self.custom_edit)
        self.metadata_edit = QLineEdit(settings["metadata"])
        form.addRow("Файлы метаданных (для справки):", self.metadata_edit)
        layout.addLayout(form)

        hint = QLabel("Расширения перечисляются через пробел или запятую. "
                      "Наведите курсор на категорию, чтобы увидеть её расширения.")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel | QDialogButtonBox.RestoreDefaults)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.RestoreDefaults).setText("По умолчанию")
        buttons.button(QDialogButtonBox.RestoreDefaults).clicked.connect(self.restoreDefaults)
        layout.addWidget(buttons)

    def restoreDefaults(self):
        defaults = default_settings()
        for key, cb in self.checks.items():
            cb.setChecked(key in defaults["categories"])
        self.custom_edit.setText(defaults["custom"])
        self.metadata_edit.setText(defaults["metadata"])

    def accept(self):
        if not self.settings()["categories"] and not parse_extensions(self.custom_edit.text()):
            QMessageBox.warning(self, "Настройки", "Выберите хотя бы одну категорию или укажите свои расширения — "
                                "иначе любые папки будут считаться неважными.")
            return
        super().accept()

    def settings(self):
        return {
            "categories": [k for k, cb in self.checks.items() if cb.isChecked()],
            "custom": format_extensions(parse_extensions(self.custom_edit.text())),
            "metadata": format_extensions(parse_extensions(self.metadata_edit.text())),
        }


class RecordFilterProxy(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.only_deletable = False
        self.min_age_days = 0

    def setOnlyDeletable(self, value):
        self.only_deletable = value
        self.invalidateFilter()

    def setMinAgeDays(self, days):
        self.min_age_days = days
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        rec = self.sourceModel().item(row, 0).data(RECORD_ROLE)
        if self.only_deletable and rec.protected:
            return False
        if self.min_age_days and rec.age_days < self.min_age_days:
            return False
        return super().filterAcceptsRow(row, parent)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {__version__} — отчёт по папкам и архивам")
        self.resize(1400, 850)
        self.root_path = ""
        self.records = []
        self.worker = None
        self.settings = load_settings()
        apply_settings(self.settings)

        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(COLUMNS)
        self.proxy = RecordFilterProxy()
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(SORT_ROLE)
        self.proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.initUI()
        self.setBusy(False)

    def initUI(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Верхняя панель
        top_layout = QHBoxLayout()
        self.choose_btn = QPushButton("Выбрать папку…")
        self.choose_btn.clicked.connect(self.chooseFolder)
        top_layout.addWidget(self.choose_btn)
        self.rescan_btn = QPushButton("Пересканировать")
        self.rescan_btn.clicked.connect(lambda: self.startScan(self.root_path))
        top_layout.addWidget(self.rescan_btn)
        self.stop_btn = QPushButton("Остановить")
        self.stop_btn.clicked.connect(self.stopScan)
        top_layout.addWidget(self.stop_btn)
        self.settings_btn = QPushButton("Типы файлов…")
        self.settings_btn.setToolTip("Выбрать, какие файлы считаются важными")
        self.settings_btn.clicked.connect(self.editSettings)
        top_layout.addWidget(self.settings_btn)
        self.folder_label = QLabel("Папка не выбрана")
        top_layout.addWidget(self.folder_label, 1)
        main_layout.addLayout(top_layout)

        # Фильтры
        filter_layout = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Поиск по таблице…")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self.onFilterChanged)
        filter_layout.addWidget(self.search_edit, 1)
        self.only_deletable_cb = QCheckBox("Только неважные")
        self.only_deletable_cb.toggled.connect(self.proxy.setOnlyDeletable)
        self.only_deletable_cb.toggled.connect(self.updateSummary)
        filter_layout.addWidget(self.only_deletable_cb)
        filter_layout.addWidget(QLabel("Не изменялись дней:"))
        self.age_spin = QSpinBox()
        self.age_spin.setRange(0, 36500)
        self.age_spin.setSpecialValueText("любые")
        self.age_spin.setToolTip("Показывать только то, что не менялось указанное число дней (с учётом вложенного)")
        self.age_spin.valueChanged.connect(self.proxy.setMinAgeDays)
        self.age_spin.valueChanged.connect(self.updateSummary)
        filter_layout.addWidget(self.age_spin)
        main_layout.addLayout(filter_layout)

        # Таблица
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for col, width in enumerate((480, 80, 260, 160, 100, 130, 120, 160, 60)):
            self.table.setColumnWidth(col, width)
        self.table.selectionModel().selectionChanged.connect(self.updateSummary)

        self.logTextEdit = QPlainTextEdit()
        self.logTextEdit.setReadOnly(True)
        self.logTextEdit.setMaximumBlockCount(10000)
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.logTextEdit)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        main_layout.addWidget(splitter, 1)

        # Панель действий
        action_layout = QHBoxLayout()
        self.select_non_important_btn = QPushButton("Выбрать все неважные")
        self.select_non_important_btn.clicked.connect(self.selectNonImportant)
        action_layout.addWidget(self.select_non_important_btn)
        self.delete_button = QPushButton("Удалить (в корзину)")
        self.delete_button.clicked.connect(lambda: self.deleteSelected(permanent=False))
        action_layout.addWidget(self.delete_button)
        self.perm_delete_button = QPushButton("Постоянное удаление")
        self.perm_delete_button.clicked.connect(lambda: self.deleteSelected(permanent=True))
        action_layout.addWidget(self.perm_delete_button)
        self.extract_button = QPushButton("Распаковать / скопировать…")
        self.extract_button.clicked.connect(self.extractSelected)
        action_layout.addWidget(self.extract_button)
        self.report_button = QPushButton("Сохранить отчёт Excel…")
        self.report_button.clicked.connect(self.saveReport)
        action_layout.addWidget(self.report_button)
        action_layout.addStretch()
        self.summary_label = QLabel()
        action_layout.addWidget(self.summary_label)
        main_layout.addLayout(action_layout)

        self.progressBar = QProgressBar()
        self.progressBar.setValue(0)
        main_layout.addWidget(self.progressBar)

    def setBusy(self, busy):
        has_data = bool(self.records)
        scanning = isinstance(self.worker, ScanWorker)
        self.choose_btn.setEnabled(not busy)
        self.settings_btn.setEnabled(not busy)
        self.rescan_btn.setEnabled(not busy and bool(self.root_path))
        self.stop_btn.setEnabled(busy and scanning)
        for btn in (self.select_non_important_btn, self.delete_button, self.perm_delete_button,
                    self.extract_button, self.report_button):
            btn.setEnabled(not busy and has_data)

    def appendLog(self, text):
        self.logTextEdit.appendPlainText(text)

    def onFilterChanged(self, text):
        self.proxy.setFilterFixedString(text)
        self.updateSummary()

    # --- Настройки ---

    def editSettings(self):
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec_() != QDialog.Accepted:
            return
        self.settings = dialog.settings()
        apply_settings(self.settings)
        try:
            save_settings(self.settings)
        except OSError as e:
            self.appendLog(f"Не удалось сохранить настройки: {e}")
        self.appendLog(f"Важные расширения: {format_extensions(NECESSARY_EXTENSIONS)}")
        if self.root_path and QMessageBox.question(
                self, "Настройки изменены", "Пересканировать папку с новыми настройками?",
                QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            self.startScan(self.root_path)
        elif self.records:
            # Старые статусы больше не соответствуют настройкам — удалять по ним нельзя
            self.records = []
            self.model.removeRows(0, self.model.rowCount())
            self.updateSummary()
            self.setBusy(False)
            self.appendLog("Результаты сброшены: пересканируйте папку.")

    # --- Сканирование ---

    def chooseFolder(self):
        folder = QFileDialog.getExistingDirectory(self, "Выберите папку для сканирования", self.root_path)
        if folder:
            self.startScan(folder)

    def startScan(self, folder):
        if not folder or self.worker is not None:
            return
        self.root_path = os.path.normpath(folder)
        self.folder_label.setText(self.root_path)
        self.records = []
        self.model.removeRows(0, self.model.rowCount())
        self.progressBar.setRange(0, 0)  # неопределённый прогресс
        self.appendLog(f"Начинаю сканирование: {self.root_path}")
        if is_risky_root(self.root_path):
            self.appendLog("Внимание: это корень диска или системная папка. Удаление отсюда может "
                           "сломать программы — проверяйте выбранное особенно внимательно.")
        self.worker = ScanWorker(self.root_path)
        self.worker.progress.connect(self.onScanProgress)
        self.worker.done.connect(self.onScanFinished)
        self.setBusy(True)
        self.worker.start()

    def stopScan(self):
        if isinstance(self.worker, ScanWorker):
            self.worker.cancel()

    def onScanProgress(self, current, count):
        self.statusBar().showMessage(f"Просканировано {count}: {current}")

    def onScanFinished(self, records):
        self.worker = None
        self.progressBar.setRange(0, 100)
        self.statusBar().clearMessage()
        if records is None:
            self.progressBar.setValue(0)
            self.appendLog("Сканирование остановлено.")
            self.records = []
        else:
            self.progressBar.setValue(100)
            self.records = records
            self.populate()
            deletable = [r for r in self.records if not r.protected and is_inside(r.path, self.root_path)]
            tops = set(top_level_paths(r.path for r in deletable))
            freeable = sum(r.total_size for r in deletable if os.path.normpath(r.path) in tops)
            self.appendLog(f"Сканирование завершено: {len(self.records)} записей, неважных — {len(deletable)} "
                           f"(можно освободить до {human_size(freeable)}).")
        self.setBusy(False)

    def populate(self):
        self.table.setSortingEnabled(False)
        self.model.removeRows(0, self.model.rowCount())
        protected_brush = QBrush(QColor(255, 235, 200))
        error_brush = QBrush(QColor(255, 210, 210))
        for rec in self.records:
            cells = [
                (rec.path, rec.path.lower()),
                (str(rec.file_count), rec.file_count),
                (rec.files_preview, rec.files_preview.lower()),
                (', '.join(rec.metadata_files), len(rec.metadata_files)),
                (human_size(rec.size), rec.size),
                (human_size(rec.total_size), rec.total_size),
                (format_time(rec.mtime), rec.mtime),
                (rec.status, rec.status),
                (rec.kind, rec.kind),
            ]
            row = []
            for text, sort_key in cells:
                item = QStandardItem(text)
                item.setEditable(False)
                item.setData(sort_key, SORT_ROLE)
                if rec.error:
                    item.setBackground(error_brush)
                elif rec.protected:
                    item.setBackground(protected_brush)
                row.append(item)
            row[0].setData(rec, RECORD_ROLE)
            row[0].setToolTip(rec.path)
            row[5].setToolTip(f"{rec.total_size:,} байт".replace(",", " "))
            self.model.appendRow(row)
        self.table.setSortingEnabled(True)
        self.updateSummary()

    # --- Выделение ---

    def recordAt(self, proxy_row):
        src = self.proxy.mapToSource(self.proxy.index(proxy_row, 0))
        return self.model.item(src.row(), 0).data(RECORD_ROLE)

    def selectedRecords(self):
        return [self.recordAt(i.row()) for i in self.table.selectionModel().selectedRows()]

    def updateSummary(self, *_):
        selected = self.selectedRecords()
        tops = set(top_level_paths(r.path for r in selected))
        total = sum(r.total_size for r in selected if os.path.normpath(r.path) in tops)
        self.summary_label.setText(f"Выбрано: {len(selected)} ({human_size(total)}) | "
                                   f"Показано: {self.proxy.rowCount()} из {self.model.rowCount()}")

    def selectNonImportant(self):
        self.table.clearSelection()
        sel = QItemSelection()
        for row in range(self.proxy.rowCount()):
            if not self.recordAt(row).protected:
                sel.select(self.proxy.index(row, 0), self.proxy.index(row, len(COLUMNS) - 1))
        self.table.selectionModel().select(sel, QItemSelectionModel.Select | QItemSelectionModel.Rows)

    # --- Действия ---

    def deleteSelected(self, permanent):
        candidates = []
        for rec in self.selectedRecords():
            if os.path.normcase(os.path.normpath(rec.path)) == os.path.normcase(self.root_path):
                self.appendLog(f"Пропущено {rec.path}: родительская папка.")
            elif rec.protected:
                self.appendLog(f"Пропущено {rec.path}: {rec.status}.")
            else:
                candidates.append(rec)
        valid_paths = top_level_paths(r.path for r in candidates)
        if not valid_paths:
            QMessageBox.information(self, "Информация",
                                    "Нет элементов для удаления (важные, зашифрованные и нечитаемые элементы защищены).")
            return
        tops = set(valid_paths)
        total = sum(r.total_size for r in candidates if os.path.normpath(r.path) in tops)
        if permanent:
            text = (f"Безвозвратно удалить {len(valid_paths)} элемент(ов), примерно {human_size(total)}?\n"
                    "Это действие нельзя отменить.")
        else:
            text = f"Переместить в корзину {len(valid_paths)} элемент(ов), примерно {human_size(total)}?"
        if QMessageBox.question(self, "Подтверждение", text, QMessageBox.Yes | QMessageBox.No,
                                QMessageBox.No) != QMessageBox.Yes:
            return
        self.progressBar.setValue(0)
        self.appendLog("Начинается постоянное удаление..." if permanent else "Начинается удаление (в корзину)...")
        self.worker = DeletionWorker(valid_paths, self.root_path, permanent=permanent)
        self.worker.progress.connect(self.progressBar.setValue)
        self.worker.logMessage.connect(self.appendLog)
        self.worker.done.connect(self.onDeletionFinished)
        self.setBusy(True)
        self.worker.start()

    def onDeletionFinished(self, deleted):
        self.worker = None
        if deleted:
            gone = lambda p: any(os.path.normpath(p) == d or is_inside(p, d) for d in deleted)
            self.records = [r for r in self.records if not gone(r.path)]
            for row in reversed(range(self.model.rowCount())):
                if gone(self.model.item(row, 0).data(RECORD_ROLE).path):
                    self.model.removeRow(row)
        self.updateSummary()
        self.setBusy(False)
        self.appendLog(f"Удаление завершено: удалено {len(deleted)}. "
                       "Размеры родительских папок обновятся после пересканирования.")
        QMessageBox.information(self, "Информация", f"Удаление завершено. Удалено элементов: {len(deleted)}.")

    def extractSelected(self):
        paths = [r.path for r in self.selectedRecords()]
        if not paths:
            QMessageBox.information(self, "Информация", "Пожалуйста, выберите элементы для распаковки.")
            return
        dest = QFileDialog.getExistingDirectory(self, "Выберите папку для распаковки")
        if not dest:
            return
        self.progressBar.setValue(0)
        self.worker = ExtractWorker(paths, dest)
        self.worker.progress.connect(self.progressBar.setValue)
        self.worker.logMessage.connect(self.appendLog)
        self.worker.done.connect(self.onExtractFinished)
        self.setBusy(True)
        self.worker.start()

    def onExtractFinished(self, errors):
        self.worker = None
        self.setBusy(False)
        if errors:
            QMessageBox.warning(self, "Ошибка", "Не удалось распаковать следующие элементы "
                                "(подробности в журнале):\n" + "\n".join(errors[:20]))
        else:
            QMessageBox.information(self, "Информация", "Распаковка завершена успешно.")

    def saveReport(self):
        name = os.path.basename(self.root_path.rstrip("\\/")) or "disk"
        default = os.path.join(os.path.expanduser("~"), "Documents", f"{name}_files_report.xlsx")
        filename, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт", default, "Excel (*.xlsx)")
        if not filename:
            return
        try:
            save_report(self.records, filename)
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось сохранить отчёт:\n{e}")
            return
        self.appendLog(f"Отчёт сохранён: {filename}")
        if QMessageBox.question(self, "Отчёт сохранён", "Открыть отчёт?",
                                QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            try:
                os.startfile(filename)
            except Exception as e:
                self.appendLog(f"Не удалось открыть файл автоматически: {e}")

    def closeEvent(self, event):
        if self.worker is not None:
            if isinstance(self.worker, ScanWorker):
                self.worker.cancel()
                self.worker.wait()
            else:
                QMessageBox.information(self, "Подождите", "Дождитесь завершения текущей операции.")
                event.ignore()
                return
        event.accept()


def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    window = MainWindow()
    window.show()
    if len(sys.argv) > 1 and os.path.isdir(sys.argv[1]):
        QTimer.singleShot(0, lambda: window.startScan(sys.argv[1]))
    else:
        QTimer.singleShot(0, window.chooseFolder)
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
