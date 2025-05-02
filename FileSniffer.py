import os
import sys
import threading
import math
import shutil
import pandas as pd
import zipfile
from send2trash import send2trash

# Импорты PyQt5
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTableView, QVBoxLayout, QWidget, QPushButton,
    QMessageBox, QFileDialog, QLabel, QHBoxLayout, QHeaderView, QPlainTextEdit, QProgressBar
)
from PyQt5.QtCore import QSortFilterProxyModel, Qt, QRegExp, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QStandardItemModel, QStandardItem

# Глобальная переменная для выбранной папки (родительская папка – её удалять нельзя)
path = ""

# Настройки для определения файлов
metadata_extensions = ['.tmp', '.db', '.sys', '.ini', '.log']
necessary_extensions = ['.jpg', '.jpeg', '.png', '.pdf', '.doc', '.docx', '.xls', '.xlsx']
archive_extensions = ['.zip', '.rar', '.7z']

# Список для хранения результатов сканирования
folders_data = []

# --- Новая функция: фильтрация leaf-путей для каскадного удаления ---
def filter_leaf_paths(paths):
    """
    Оставляет только те пути, которые не являются предками других путей из списка.
    """
    normalized = [os.path.normpath(p) for p in paths]
    leafs = []
    for p in normalized:
        if not any(q != p and q.startswith(p + os.sep) for q in normalized):
            leafs.append(p)
    return leafs


def is_necessary_file(filename):
    return os.path.splitext(filename)[1].lower() in necessary_extensions


def is_metadata_file(filename):
    return os.path.splitext(filename)[1].lower() in metadata_extensions


def scan_archive(archive_path):
    ext = os.path.splitext(archive_path)[1].lower()
    encrypted = False
    if ext == ".zip":
        try:
            with zipfile.ZipFile(archive_path, 'r') as z:
                files_info = []
                total_size = 0
                metadata_files = []
                necessary_files = []
                for info in z.infolist():
                    if info.is_dir():
                        continue
                    files_info.append(info.filename)
                    total_size += info.file_size
                    if info.flag_bits & 0x1:
                        encrypted = True
                    file_ext = os.path.splitext(info.filename)[1].lower()
                    if file_ext in metadata_extensions:
                        metadata_files.append(info.filename)
                    if file_ext in necessary_extensions:
                        necessary_files.append(info.filename)
                status = "Важное" if necessary_files else "Обычное"
                if encrypted:
                    status += " (Зашифрован)"
                    print(f"Архив {archive_path} зашифрован.")
                return {
                    'Путь к папке': archive_path,
                    'Количество файлов': len(files_info),
                    'Файлы в папке (первые 10)': ', '.join(files_info[:10]) + ('...' if len(files_info) > 10 else ''),
                    'Файлы метаданных': ', '.join(metadata_files),
                    'Общий размер файлов (байт)': total_size,
                    'Статус': status,
                    'Тип': 'Архив'
                }
        except Exception as e:
            print(f"Ошибка при обработке архива {archive_path}: {e}")
            return {
                'Путь к папке': archive_path,
                'Количество файлов': 0,
                'Файлы в папке (первые 10)': '',
                'Файлы метаданных': '',
                'Общий размер файлов (байт)': 0,
                'Статус': 'Ошибка',
                'Тип': 'Архив'
            }
    elif ext == ".rar":
        try:
            import rarfile
        except ImportError:
            print("Библиотека rarfile не установлена. Установите её через pip install rarfile.")
            return {
                'Путь к папке': archive_path,
                'Количество файлов': 0,
                'Файлы в папке (первые 10)': '',
                'Файлы метаданных': '',
                'Общий размер файлов (байт)': 0,
                'Статус': 'Ошибка: rarfile не установлен',
                'Тип': 'Архив'
            }
        try:
            rf = rarfile.RarFile(archive_path)
            files_info = []
            total_size = 0
            metadata_files = []
            necessary_files = []
            for info in rf.infolist():
                if info.isdir():
                    continue
                files_info.append(info.filename)
                total_size += info.file_size
                if info.needs_password():
                    encrypted = True
                file_ext = os.path.splitext(info.filename)[1].lower()
                if file_ext in metadata_extensions:
                    metadata_files.append(info.filename)
                if file_ext in necessary_extensions:
                    necessary_files.append(info.filename)
            status = "Важное" if necessary_files else "Обычное"
            if encrypted:
                status += " (Зашифрован)"
                print(f"Архив {archive_path} зашифрован.")
            return {
                'Путь к папке': archive_path,
                'Количество файлов': len(files_info),
                'Файлы в папке (первые 10)': ', '.join(files_info[:10]) + ('...' if len(files_info) > 10 else ''),
                'Файлы метаданных': ', '.join(metadata_files),
                'Общий размер файлов (байт)': total_size,
                'Статус': status,
                'Тип': 'Архив'
            }
        except Exception as e:
            print(f"Ошибка при обработке архива {archive_path}: {e}")
            return {
                'Путь к папке': archive_path,
                'Количество файлов': 0,
                'Файлы в папке (первые 10)': '',
                'Файлы метаданных': '',
                'Общий размер файлов (байт)': 0,
                'Статус': 'Ошибка',
                'Тип': 'Архив'
            }
    elif ext == ".7z":
        try:
            import py7zr
            with py7zr.SevenZipFile(archive_path, mode='r') as archive:
                files_info = []
                total_size = 0  # для 7z размер может не определяться
                metadata_files = []
                necessary_files = []
                allfiles = archive.getnames()
                for filename in allfiles:
                    files_info.append(filename)
                    file_ext = os.path.splitext(filename)[1].lower()
                    if file_ext in metadata_extensions:
                        metadata_files.append(filename)
                    if file_ext in necessary_extensions:
                        necessary_files.append(filename)
                status = "Важное" if necessary_files else "Обычное"
                return {
                    'Путь к папке': archive_path,
                    'Количество файлов': len(files_info),
                    'Файлы в папке (первые 10)': ', '.join(files_info[:10]) + ('...' if len(files_info) > 10 else ''),
                    'Файлы метаданных': ', '.join(metadata_files),
                    'Общий размер файлов (байт)': total_size,
                    'Статус': status,
                    'Тип': 'Архив'
                }
        except Exception as e:
            print(f"Ошибка при обработке архива {archive_path}: {e}")
            return {
                'Путь к папке': archive_path,
                'Количество файлов': 0,
                'Файлы в папке (первые 10)': '',
                'Файлы метаданных': '',
                'Общий размер файлов (байт)': 0,
                'Статус': 'Ошибка',
                'Тип': 'Архив'
            }
    else:
        print(f"Неподдерживаемый формат архива: {archive_path}")
        return {
            'Путь к папке': archive_path,
            'Количество файлов': 0,
            'Файлы в папке (первые 10)': '',
            'Файлы метаданных': '',
            'Общий размер файлов (байт)': 0,
            'Статус': 'Неподдерживаемый формат',
            'Тип': 'Архив'
        }


def scan_folders():
    global path
    print("Начинаю сканирование папок...")
    for root, dirs, files in os.walk(path):
        print(f"Сканирую: {root}")
        normal_files = [f for f in files if not any(f.lower().endswith(ext) for ext in archive_extensions)]
        archive_files = [f for f in files if any(f.lower().endswith(ext) for ext in archive_extensions)]
        metadata_files = [f for f in normal_files if is_metadata_file(f)]
        necessary_files = [f for f in normal_files if is_necessary_file(f)]
        total_size = 0
        for f in normal_files:
            try:
                total_size += os.path.getsize(os.path.join(root, f))
            except Exception as e:
                print(f"Ошибка при получении размера файла {os.path.join(root, f)}: {e}")
        status = "Важное" if necessary_files else "Обычное"
        folders_data.append({
            'Путь к папке': root,
            'Количество файлов': len(normal_files),
            'Файлы в папке (первые 10)': ', '.join(normal_files[:10]) + ('...' if len(normal_files) > 10 else ''),
            'Файлы метаданных': ', '.join(metadata_files),
            'Общий размер файлов (байт)': total_size,
            'Статус': status,
            'Тип': 'Папка'
        })
        print(f"Просканировано: {root} | Статус: {status}")
        for file in archive_files:
            archive_path = os.path.join(root, file)
            archive_record = scan_archive(archive_path)
            folders_data.append(archive_record)
            print(f"Просканирован архив: {archive_path} | Статус: {archive_record['Статус']}")
    print("Сканирование завершено.")


def create_report():
    global path
    df = pd.DataFrame(folders_data)
    last_folder_name = os.path.basename(os.path.normpath(path))
    output_filename = f"{last_folder_name}_files_report.xlsx"
    df.to_excel(output_filename, index=False)
    print(f"Отчёт сохранён в: {os.path.abspath(output_filename)}")
    try:
        os.startfile(output_filename)
    except Exception as e:
        print(f"Не удалось открыть файл автоматически: {e}")


def delete_folders(folder_list):
    folder_list_sorted = sorted(folder_list, key=lambda x: len(x), reverse=True)
    for folder in folder_list_sorted:
        try:
            norm_folder = os.path.normpath(folder)
            if norm_folder.startswith("\\\\?\\"): norm_folder = norm_folder[4:]
            if os.path.exists(norm_folder):
                send2trash(norm_folder)
                print(f"Элемент перемещён в корзину: {norm_folder}")
            else:
                print(f"Элемент не существует: {norm_folder}")
        except Exception as e:
            print(f"Ошибка при перемещении {norm_folder} в корзину: {e}")


def delete_folders_permanently(folder_list):
    folder_list_sorted = sorted(folder_list, key=lambda x: len(x), reverse=True)
    for folder in folder_list_sorted:
        try:
            norm_folder = os.path.normpath(folder)
            if norm_folder.startswith("\\\\?\\"): norm_folder = norm_folder[4:]
            if os.path.exists(norm_folder):
                if os.path.isdir(norm_folder): shutil.rmtree(norm_folder); print(f"Папка удалена: {norm_folder}")
                elif os.path.isfile(norm_folder): os.remove(norm_folder); print(f"Файл удалён: {norm_folder}")
            else: print(f"Элемент не существует: {norm_folder}")
        except Exception as e:
            print(f"Ошибка при постоянном удалении {norm_folder}: {e}")


def extract_item(item_path, destination):
    if os.path.isdir(item_path):
        dest_folder = os.path.join(destination, os.path.basename(item_path))
        if os.path.exists(dest_folder): dest_folder += "_copy"
        try: shutil.copytree(item_path, dest_folder); return True
        except Exception as e: print(f"Ошибка при копировании папки {item_path}: {e}"); return False
    else:
        ext = os.path.splitext(item_path)[1].lower()
        if ext == ".zip":
            try:
                with zipfile.ZipFile(item_path, 'r') as z:
                    dest_folder = os.path.join(destination, os.path.splitext(os.path.basename(item_path))[0])
                    os.makedirs(dest_folder, exist_ok=True)
                    z.extractall(dest_folder)
                return True
            except Exception as e:
                print(f"Ошибка при распаковке архива {item_path}: {e}")
                return False
        elif ext == ".rar":
            try:
                import rarfile
                rf = rarfile.RarFile(item_path)
                dest_folder = os.path.join(destination, os.path.splitext(os.path.basename(item_path))[0])
                os.makedirs(dest_folder, exist_ok=True)
                rf.extractall(dest_folder)
                return True
            except Exception as e:
                print(f"Ошибка при распаковке архива {item_path}: {e}")
                return False
        elif ext == ".7z":
            try:
                import py7zr
                with py7zr.SevenZipFile(item_path, mode='r') as archive:
                    dest_folder = os.path.join(destination, os.path.splitext(os.path.basename(item_path))[0])
                    os.makedirs(dest_folder, exist_ok=True)
                    archive.extractall(path=dest_folder)
                return True
            except Exception as e:
                print(f"Ошибка при распаковке архива {item_path}: {e}")
                return False
        else:
            print(f"Неподдерживаемый формат для распаковки: {item_path}")
            return False

# Работник удаления с прогресс-баром
class DeletionWorker(QThread):
    progress = pyqtSignal(int)
    logMessage = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, paths, permanent=False):
        super().__init__()
        self.paths = paths
        self.permanent = permanent

    def run(self):
        total = len(self.paths)
        for i, p in enumerate(self.paths):
            norm_folder = os.path.normpath(p)
            if norm_folder.startswith("\\\\?\\"): norm_folder = norm_folder[4:]
            try:
                if os.path.exists(norm_folder):
                    if os.path.isdir(norm_folder):
                        self.logMessage.emit(f"Пропущено удаление {norm_folder}: содержит важные данные.")
                        continue
                    elif os.path.isfile(norm_folder):
                        if self.permanent:
                            os.remove(norm_folder)
                            self.logMessage.emit(f"Файл удалён: {norm_folder}")
                        else:
                            send2trash(norm_folder)
                            self.logMessage.emit(f"Элемент перемещён в корзину: {norm_folder}")
                else:
                    self.logMessage.emit(f"Элемент не существует: {norm_folder}")
            except Exception as e:
                self.logMessage.emit(f"Ошибка при удалении {norm_folder}: {e}")
            self.progress.emit(int(((i+1)/total)*100))
        self.finished.emit()

# Главный класс с пагинацией, динамичным обновлением и современным интерфейсом
class MainWindow(QMainWindow):
    def __init__(self, data):
        super().__init__()
        self.setWindowTitle("Отчёт по папкам и архивам")
        self.resize(1200, 800)
        self.data = data
        self.currentPage = 0
        self.rowsPerPage = 500  # 2000 строк на страницу
        self.fullModel = QStandardItemModel()
        self.fullModel.setHorizontalHeaderLabels(["Путь к папке", "Количество файлов", "Файлы в папке (первые 10)", "Файлы метаданных", "Общий размер файлов (байт)", "Статус", "Тип"])
        for entry in self.data:
            row = []
            row.append(QStandardItem(entry.get('Путь к папке', "")))
            row.append(QStandardItem(str(entry.get('Количество файлов', ""))))
            row.append(QStandardItem(entry.get('Файлы в папке (первые 10)', "")))
            row.append(QStandardItem(entry.get('Файлы метаданных', "")))
            row.append(QStandardItem(str(entry.get('Общий размер файлов (байт)', ""))))
            row.append(QStandardItem(entry.get('Статус', "")))
            row.append(QStandardItem(entry.get('Тип', "")))
            self.fullModel.appendRow(row)
        self.sortFilterProxy = QSortFilterProxyModel()
        self.sortFilterProxy.setSourceModel(self.fullModel)
        self.sortFilterProxy.setSortCaseSensitivity(Qt.CaseInsensitive)
        self.sortFilterProxy.setFilterKeyColumn(-1)
        self.pageModel = QStandardItemModel()
        self.pageModel.setHorizontalHeaderLabels(["Путь к папке", "Количество файлов", "Файлы в папке (первые 10)", "Файлы метаданных", "Общий размер файлов (байт)", "Статус", "Тип"])
        self.initUI()
        self.updatePage()

    def initUI(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Верхняя панель
        top_layout = QHBoxLayout()
        top_layout.addWidget(QLabel("Сканируемая папка:"))
        self.folder_label = QLabel(f"{path}")
        top_layout.addWidget(self.folder_label)
        top_layout.addStretch()
        self.filter_non_important_btn = QPushButton("Фильтр: неважные")
        self.filter_non_important_btn.clicked.connect(self.filterNonImportant)
        top_layout.addWidget(self.filter_non_important_btn)
        self.clear_filter_btn = QPushButton("Сбросить фильтр")
        self.clear_filter_btn.clicked.connect(self.clearFilter)
        top_layout.addWidget(self.clear_filter_btn)
        main_layout.addLayout(top_layout)

        # Таблица
        self.table = QTableView()
        self.table.setModel(self.pageModel)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.MultiSelection)
        main_layout.addWidget(self.table)

        # Панель навигации
        nav_layout = QHBoxLayout()
        self.prev_btn = QPushButton("◀ Предыдущая")
        self.prev_btn.clicked.connect(self.prevPage)
        nav_layout.addWidget(self.prev_btn)
        self.page_label = QLabel()
        nav_layout.addWidget(self.page_label)
        self.next_btn = QPushButton("Следующая ▶")
        self.next_btn.clicked.connect(self.nextPage)
        nav_layout.addWidget(self.next_btn)
        self.refresh_btn = QPushButton("Обновить")
        self.refresh_btn.clicked.connect(self.updatePage)
        nav_layout.addWidget(self.refresh_btn)
        nav_layout.addStretch()
        main_layout.addLayout(nav_layout)

        # Панель действий
        action_layout = QHBoxLayout()
        self.delete_button = QPushButton("Удалить (в корзину)")
        self.delete_button.clicked.connect(self.deleteSelected)
        action_layout.addWidget(self.delete_button)
        self.perm_delete_button = QPushButton("Постоянное удаление")
        self.perm_delete_button.clicked.connect(self.permanentDeleteSelected)
        action_layout.addWidget(self.perm_delete_button)
        self.extract_button = QPushButton("Распаковать")
        self.extract_button.clicked.connect(self.extractSelected)
        action_layout.addWidget(self.extract_button)
        self.select_non_important_btn = QPushButton("Выбрать неважные на странице")
        self.select_non_important_btn.clicked.connect(self.selectNonImportantOnPage)
        action_layout.addWidget(self.select_non_important_btn)
        action_layout.addStretch()
        main_layout.addLayout(action_layout)

        # Прогресс и лог
        progress_layout = QHBoxLayout()
        self.progressBar = QProgressBar()
        self.progressBar.setValue(0)
        progress_layout.addWidget(self.progressBar)
        main_layout.addLayout(progress_layout)
        self.logTextEdit = QPlainTextEdit()
        self.logTextEdit.setReadOnly(True)
        main_layout.addWidget(self.logTextEdit)

    def updatePage(self):
        totalRows = self.sortFilterProxy.rowCount()
        totalPages = math.ceil(totalRows / self.rowsPerPage) if totalRows > 0 else 1
        if self.currentPage >= totalPages:
            self.currentPage = totalPages - 1
        start = self.currentPage * self.rowsPerPage
        end = min(start + self.rowsPerPage, totalRows)
        self.pageModel.removeRows(0, self.pageModel.rowCount())
        for i in range(start, end):
            row_items = []
            for j in range(self.sortFilterProxy.columnCount()):
                index = self.sortFilterProxy.index(i, j)
                data = self.sortFilterProxy.data(index)
                row_items.append(QStandardItem(str(data)))
            self.pageModel.appendRow(row_items)
        self.page_label.setText(f"Страница {self.currentPage+1} из {totalPages}")

    def prevPage(self):
        if self.currentPage > 0:
            self.currentPage -= 1
            self.updatePage()

    def nextPage(self):
        totalRows = self.sortFilterProxy.rowCount()
        totalPages = math.ceil(totalRows / self.rowsPerPage) if totalRows > 0 else 1
        if self.currentPage < totalPages - 1:
            self.currentPage += 1
            self.updatePage()

    def filterNonImportant(self):
        reg_exp = QRegExp("^Обычное$", Qt.CaseInsensitive)
        self.sortFilterProxy.setFilterKeyColumn(5)
        self.sortFilterProxy.setFilterRegExp(reg_exp)
        self.currentPage = 0
        self.updatePage()

    def clearFilter(self):
        self.sortFilterProxy.setFilterRegExp("")
        self.currentPage = 0
        self.updatePage()

    def selectNonImportantOnPage(self):
        self.table.clearSelection()
        self.currentSelectionRow = 0
        self.rowsPerChunk = 100
        self.selectionTimer = QTimer()
        self.selectionTimer.timeout.connect(self.selectNonImportantChunk)
        self.selectionTimer.start(10)

    def selectNonImportantChunk(self):
        total = self.pageModel.rowCount()
        end = min(self.currentSelectionRow + self.rowsPerChunk, total)
        for row in range(self.currentSelectionRow, end):
            status = self.pageModel.item(row, 5).text()
            if status.strip().lower() == "обычное":
                self.table.selectRow(row)
        self.currentSelectionRow = end
        if self.currentSelectionRow >= total:
            self.selectionTimer.stop()

    def getSelectedPathsAndStatus(self):
        selected = self.table.selectionModel().selectedRows()
        results = []
        for index in selected:
            row = index.row()
            path_item = self.pageModel.item(row, 0)
            status_item = self.pageModel.item(row, 5)
            if path_item and status_item:
                results.append((path_item.text(), status_item.text()))
        return results

    def removeFromFullModel(self, path_to_remove):
        rows = self.fullModel.rowCount()
        for row in range(rows):
            item = self.fullModel.item(row, 0)
            if item and os.path.normpath(item.text()) == os.path.normpath(path_to_remove):
                self.fullModel.removeRow(row)
                break

    def appendLog(self, text):
        self.logTextEdit.appendPlainText(text)

    def onDeletionFinished(self, valid_paths):
        for p in valid_paths:
            self.removeFromFullModel(p)
        self.updatePage()
        self.appendLog("Удаление завершено.")
        QMessageBox.information(self, "Информация", "Удаление завершено.")

    def deleteSelected(self):
        sel = self.getSelectedPathsAndStatus()
        valid_paths = []
        for p, status in sel:
            if os.path.normpath(p) == os.path.normpath(path):
                self.appendLog(f"Пропущено удаление {p}: родительская папка.")
            elif status.strip().lower() == "важное":
                self.appendLog(f"Пропущено удаление {p}: содержит важные данные.")
            else:
                valid_paths.append(p)
        # каскадная фильтрация: оставляем только leaf-пути
        valid_paths = filter_leaf_paths(valid_paths)
        if not valid_paths:
            QMessageBox.information(self, "Информация", "Нет элементов для удаления (папки с важными данными защищены).")
            return
        reply = QMessageBox.question(self, "Подтверждение", "Удалить выбранные элементы (переместить в корзину)?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.progressBar.setValue(0)
            self.appendLog("Начинается удаление (в корзину)...")
            self.deletionWorker = DeletionWorker(valid_paths, permanent=False)
            self.deletionWorker.progress.connect(self.progressBar.setValue)
            self.deletionWorker.logMessage.connect(self.appendLog)
            self.deletionWorker.finished.connect(lambda: self.onDeletionFinished(valid_paths))
            self.deletionWorker.start()

    def permanentDeleteSelected(self):
        sel = self.getSelectedPathsAndStatus()
        valid_paths = []
        for p, status in sel:
            if os.path.normpath(p) == os.path.normpath(path):
                self.appendLog(f"Пропущено удаление {p}: родительская папка.")
            elif status.strip().lower() == "важное":
                self.appendLog(f"Пропущено удаление {p}: содержит важные данные.")
            else:
                valid_paths.append(p)
        # каскадная фильтрация: оставляем только leaf-пути
        valid_paths = filter_leaf_paths(valid_paths)
        if not valid_paths:
            QMessageBox.information(self, "Информация", "Нет элементов для постоянного удаления (папки с важными данными защищены).")
            return
        reply = QMessageBox.question(self, "Подтверждение", "Постоянно удалить выбранные элементы?\nЭто действие нельзя отменить.",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.progressBar.setValue(0)
            self.appendLog("Начинается постоянное удаление...")
            self.deletionWorker = DeletionWorker(valid_paths, permanent=True)
            self.deletionWorker.progress.connect(self.progressBar.setValue)
            self.deletionWorker.logMessage.connect(self.appendLog)
            self.deletionWorker.finished.connect(lambda: self.onDeletionFinished(valid_paths))
            self.deletionWorker.start()

    def extractSelected(self):
        sel = self.getSelectedPathsAndStatus()
        paths = [p for p, s in sel]
        if not paths:
            QMessageBox.information(self, "Информация", "Пожалуйста, выберите элементы для распаковки.")
            return
        dest = QFileDialog.getExistingDirectory(self, "Выберите папку для распаковки")
        if not dest:
            return
        errors = []
        for p in paths:
            result = extract_item(p, dest)
            if not result:
                errors.append(p)
        if errors:
            QMessageBox.warning(self, "Ошибка", "Не удалось распаковать следующие элементы:\n" + "\n".join(errors))
        else:
            QMessageBox.information(self, "Информация", "Распаковка завершена успешно.")


def main():
    global path
    app = QApplication(sys.argv)
    folder = QFileDialog.getExistingDirectory(None, "Выберите папку для сканирования")
    if not folder:
        sys.exit("Папка не выбрана, выход из программы.")
    path = folder

    scan_thread = threading.Thread(target=scan_folders)
    scan_thread.start()
    scan_thread.join()
    create_report()

    window = MainWindow(folders_data)
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
