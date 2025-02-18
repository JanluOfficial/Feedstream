import os
import sys
import time
import sqlite3
import requests
import feedparser
import webbrowser
from PyQt5.QtCore import Qt #, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIntValidator #, QClipboard
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QAction, QWidget,
    QDialog, QLineEdit, QFormLayout, QDialogButtonBox, QMessageBox, QSizePolicy,
    QTableWidget, QHeaderView, QSplitter, QTableWidgetItem, QLabel,
    QPushButton, QScrollArea
)

from settings_manager import SettingsManager
from StylesheetMixin import StylesheetMixin

class GlobConf:
    database = "feedstream.db"
    config = "feedstream.ini"

class AddFeedDialog(QDialog, StylesheetMixin):
    def __init__(self, showProxyBtn: bool = False):
        super().__init__()
        self.apply_stylesheet()
        self.setWindowTitle('Add Feed')
        self.setMinimumWidth(300)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
        
        self.form_layout = QFormLayout()
        self.layout.addLayout(self.form_layout)
        
        self.url_input = QLineEdit()
        self.form_layout.addRow('URL:', self.url_input)
        
        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText('Leave empty to use feed title')
        self.form_layout.addRow('Title:', self.title_input)
        
        if showProxyBtn:
            self.proxy_button = QPushButton("Set Proxy")
            self.proxy_button.clicked.connect(self.set_proxy)
            self.layout.addWidget(self.proxy_button)
        
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        self.layout.addWidget(self.button_box)
        
        self.settings = SettingsManager.connect(GlobConf.config)
    
    def set_proxy(self):
        EnterProxyDialog(self.settings)

class ManageFeedDialog(QDialog, StylesheetMixin):
    def __init__(self):
        super().__init__()
        self.apply_stylesheet()
        self.database = GlobConf.database
        self.setWindowTitle('Manage Feeds')
        self.setMinimumSize(480, 640)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
        self.form_layout = QFormLayout()
        self.layout.addLayout(self.form_layout)
        self.feed_list = QTableWidget()
        self.feed_list.setColumnCount(2)
        self.feed_list.setHorizontalHeaderLabels(['Title', 'URL'])
        self.feed_list.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.feed_list.verticalHeader().setVisible(False)
        self.feed_list.setEditTriggers(QTableWidget.NoEditTriggers)
        self.feed_list.setSelectionBehavior(QTableWidget.SelectRows)
        self.feed_list.setSelectionMode(QTableWidget.SingleSelection)
        self.layout.addWidget(self.feed_list)
        self.load_feeds()
        self.settings = SettingsManager.connect(GlobConf.config)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.delete_button = QPushButton('Delete')
        self.delete_button.clicked.connect(self.delete_feed)
        self.button_box.addButton(self.delete_button, QDialogButtonBox.ActionRole)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        self.layout.addWidget(self.button_box)

    def load_feeds(self):
        self.feed_list.setRowCount(0)
        with sqlite3.connect(self.database) as db:
            cursor = db.cursor()
            cursor.execute('SELECT title, url FROM feeds')
            feeds = cursor.fetchall()
            for i, (title, url) in enumerate(feeds):
                self.feed_list.insertRow(i)
                self.feed_list.setItem(i, 0, QTableWidgetItem(title))
                self.feed_list.setItem(i, 1, QTableWidgetItem(url))

    def delete_feed(self):
        selected_row = self.feed_list.currentRow()
        confirm = QMessageBox.question(self, 'Delete Feed', 'Are you sure you want to delete this feed?', QMessageBox.Yes | QMessageBox.No)
        if selected_row >= 0 and confirm == QMessageBox.Yes:
            title = self.feed_list.item(selected_row, 0).text()
            with sqlite3.connect(self.database) as db:
                cursor = db.cursor()
                cursor.execute('DELETE FROM feeds WHERE title = ?', (title,))
                db.commit()
            self.feed_list.removeRow(selected_row)

class EnterProxyDialog(QDialog, StylesheetMixin):
    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self.apply_stylesheet()
        self.setWindowTitle('Proxy Setup')
        self.setMinimumWidth(300)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
        
        self.form_layout = QFormLayout()
        self.layout.addLayout(self.form_layout)

        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText('Enter proxy address (e.g., http://proxy.example.com)')
        self.form_layout.addRow('Proxy:', self.proxy_input)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText('Enter proxy port (e.g., 8080)')
        self.port_input.setValidator(QIntValidator(1, 65535, self))
        self.form_layout.addRow('Port:', self.port_input)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.set_proxy)
        self.button_box.rejected.connect(self.reject)
        self.layout.addWidget(self.button_box)

    def set_proxy(self):
        proxy, port = self.proxy_input.text().strip(), self.port_input.text().strip()

        if not proxy or not port:
            QMessageBox.warning(self, 'Invalid Input', 'Both proxy address and port must be provided.')
            return

        proxy = proxy.replace("http://", "").replace("https://", "")
        
        try:
            self.settings.set('proxy', 'proxy_address', proxy)
            self.settings.set('proxy', 'proxy_port', port)
            self.settings.commit()
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Failed to save proxy settings: {e}')
            return
        
        QMessageBox.information(self, 'Proxy Set', f'Proxy has been set to {proxy}:{port}')
        self.accept()

class Feedstream(QMainWindow, StylesheetMixin):
    def __init__(self, feed):
        super().__init__()
        self.settings = self.init_config()
        self.feed = feed
        self.setWindowTitle('Feedstream')
        self.setGeometry(100, 100, 960, 560)
        self.database = GlobConf.database
        with sqlite3.connect(self.database) as db:
            cursor = db.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS feeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    url TEXT UNIQUE, 
                    title TEXT
                )
            """)
            db.commit()
        self.init_ui()
        self.feed_index = 0
        self.refresh_feed()

    def init_ui(self):
        self.apply_stylesheet()
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        self.main_layout = QVBoxLayout()
        main_widget.setLayout(self.main_layout)

        # Menu Bar
        self.menu_bar = self.menuBar()
        self.feed_menu = self.menu_bar.addMenu('Feeds')
        
        self.build_feeds_menu()

        view_menu = self.menu_bar.addMenu('View')
        show_url_action = QAction('Show URL', self, checkable=True)
        show_url_action.setChecked(self.settings.getboolean('TableView', 'show_url', False))
        show_url_action.triggered.connect(lambda: self.hide_column(1, show_url_action, "show_url"))
        view_menu.addAction(show_url_action)
        show_summary_action = QAction('Show Summary', self, checkable=True)
        show_summary_action.setChecked(self.settings.getboolean('TableView', 'show_summary', False))
        show_summary_action.triggered.connect(lambda: self.hide_column(2, show_summary_action, "show_summary"))
        view_menu.addAction(show_summary_action)
        show_timestamp_action = QAction('Show Timestamp', self, checkable=True)
        show_timestamp_action.setChecked(self.settings.getboolean('TableView', 'show_timestamp', True))
        show_timestamp_action.triggered.connect(lambda: self.hide_column(3, show_timestamp_action, "show_timestamp"))
        view_menu.addAction(show_timestamp_action)

        options_menu = self.menu_bar.addMenu('Options')
        proxy_menu = options_menu.addMenu('Proxy')
        self.use_proxy_checkable = QAction("Use Proxy", self, checkable=True)
        self.use_proxy_checkable.setChecked(self.settings.getboolean('proxy', 'use_proxy'))
        self.use_proxy_checkable.triggered.connect(lambda: self.set_proxy_usage(self.use_proxy_checkable.isChecked()))
        proxy_menu.addAction(self.use_proxy_checkable)
        set_up_proxy_action = QAction("Set up Proxy", self)
        set_up_proxy_action.triggered.connect(self.set_proxy)
        proxy_menu.addAction(set_up_proxy_action)

        # Main UI
        self.splitter = QSplitter(Qt.Horizontal)
        self.main_layout.addWidget(self.splitter)

        # Feed List
        feed_list_widget = QWidget()
        feed_list_layout = QVBoxLayout()
        feed_list_widget.setLayout(feed_list_layout)
        self.splitter.addWidget(feed_list_widget)

        self.feed_list_label = QLabel('Feeds')
        self.feed_list_label.setFont(QFont('Arial', 20))
        feed_list_layout.addWidget(self.feed_list_label)

        self.feed_list = QTableWidget()
        self.feed_list.setMinimumSize(600, 200)
        self.feed_list.setColumnCount(4)
        self.feed_list.setHorizontalHeaderLabels(['Title', 'URL', 'Summary', 'Published'])
        self.feed_list.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.feed_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.feed_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.feed_list.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.feed_list.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.feed_list.horizontalHeader().setSectionHidden(1, not self.settings.getboolean('TableView', 'show_url', True))
        self.feed_list.horizontalHeader().setSectionHidden(2, not self.settings.getboolean('TableView', 'show_summary', True))
        self.feed_list.horizontalHeader().setSectionHidden(3, not self.settings.getboolean('TableView', 'show_timestamp', False))
        self.feed_list.verticalHeader().setVisible(False)
        self.feed_list.cellDoubleClicked.connect(self.open_url)
        self.feed_list.cellClicked.connect(self.set_article_details)
        self.feed_list.setEditTriggers(QTableWidget.NoEditTriggers)
        self.feed_list.setSelectionBehavior(QTableWidget.SelectRows)
        self.feed_list.setSelectionMode(QTableWidget.SingleSelection)
        feed_list_layout.addWidget(self.feed_list)

        # Article Details Pane
        self.article_widget = QWidget()
        article_layout = QVBoxLayout(self.article_widget)
        article_layout.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.article_title = QLabel("Article")
        self.article_title.setFont(QFont("Arial", 16))
        self.article_title.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.article_title.setWordWrap(True)
        article_layout.addWidget(self.article_title)

        self.article_summary = QLabel("Summary")
        self.article_summary.setFont(QFont("Arial", 12))
        self.article_summary.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.article_summary.setWordWrap(True)
        article_layout.addWidget(self.article_summary)

        self.article_url = QLabel("URL")
        self.article_url.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.article_url.setWordWrap(True)
        article_layout.addWidget(self.article_url)

        article_url_options = QHBoxLayout()
        open_in_browser = QPushButton("Open in Browser")
        open_in_browser.clicked.connect(lambda: webbrowser.open(self.article_url.text()))
        article_url_options.addWidget(open_in_browser)
        copy_to_clipboard = QPushButton("Copy to Clipboard")
        copy_to_clipboard.clicked.connect(lambda: QApplication.clipboard().setText(self.article_url.text()))
        article_url_options.addWidget(copy_to_clipboard)
        article_layout.addLayout(article_url_options)
        
        self.article_timestamp = QLabel("Timestamp")
        self.article_timestamp.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.article_timestamp.setWordWrap(True)
        article_layout.addWidget(self.article_timestamp)

        self.article_details_pane = QScrollArea()
        self.article_details_pane.setMinimumWidth(300)
        self.article_details_pane.setWidget(self.article_widget)
        self.article_details_pane.setWidgetResizable(True)
    
    def show_article_details_pane(self):
        if self.article_details_pane not in self.splitter.children():
            self.splitter.addWidget(self.article_details_pane)
            self.splitter.setStretchFactor(0, 4)
            self.splitter.setStretchFactor(1, 1)

    def set_article_details(self):
        selected_row = self.feed_list.currentRow()
        if selected_row >= 0:
            self.article_title.setText(self.feed_list.item(selected_row, 0).text())
            self.article_summary.setText(self.feed_list.item(selected_row, 2).text())
            self.article_url.setText(self.feed_list.item(selected_row, 1).text())
            self.article_timestamp.setText(self.feed_list.item(selected_row, 3).text())
        self.show_article_details_pane()

    def add_feed(self, showProxyBtn: bool = False):
        dialog = AddFeedDialog(showProxyBtn=showProxyBtn)
        if dialog.exec_() == QDialog.Accepted:
            url = dialog.url_input.text()
            title = dialog.title_input.text()
            feed = self.parse_feed(url)
            if hasattr(feed, "status"):
                if feed.status == 429:
                    QMessageBox.warning(self, 'Too Many Requests', 'You have made too many requests to the server. Please try again later.')
                    return
            if feed.bozo:
                QMessageBox.warning(self, 'Invalid Feed', 'The URL does not link to a valid RSS feed.')
                return
            elif title == '':
                title = feed.feed.title
            self.add_feed_to_database(url, title)
            self.build_feeds_menu()

    def add_feed_to_database(self, url: str, title: str = None):
        with sqlite3.connect(self.database) as db:
            try:
                db.cursor().execute('INSERT INTO feeds (url, title) VALUES (?, ?)', (url, title))
                db.commit()
            except sqlite3.IntegrityError:
                QMessageBox.warning(self, 'Feed Exists', 'Feed already exists in database')

    def refresh_feed(self, feed_id: int = None):
        if feed_id is None:
            feed_id = self.feed_index
        with sqlite3.connect(self.database) as db:
            cursor = db.cursor()
            cursor.execute('SELECT url, title FROM feeds')
            result = cursor.fetchall()
        
        while len(result) == 0:
            QMessageBox.warning(self, 'No Feeds found', 'You must first add a feed to refresh')
            self.add_feed(True)
            with sqlite3.connect(self.database) as db:
                cursor = db.cursor()
                cursor.execute('SELECT url, title FROM feeds')
                result = cursor.fetchall()
        if 0 <= feed_id < len(result):
            print("Loading feed", result[feed_id][0])
            feed_url = result[feed_id][0]
            feed = self.parse_feed(feed_url)
            if hasattr(feed, "status"):
                if feed.status == 429:
                    retry = QMessageBox.warning(self, 'Too Many Requests', f'You have made too many requests to {result[feed_id][1]}. Please try again later.', QMessageBox.Retry | QMessageBox.Cancel)
                    if retry == QMessageBox.Retry:
                        self.refresh_feed(feed_id)
                    return
                elif feed.status == 403:
                    retry = QMessageBox.critical(self, 'Client Error', f'The server has responded with <b>403: Forbidden</b> and denied access to this feed.', QMessageBox.Retry | QMessageBox.Cancel)
                    if retry == QMessageBox.Retry:
                        self.refresh_feed(feed_id)
                    return
            self.display_feed(feed, result[feed_id][1])

    def display_feed(self, feed, title):
        if not feed or not title:
            QMessageBox.critical(self, 'Critical Error', 'Failed while refreshing: Feed or Title were set to None')
            return
        self.feed_list_label.setText(title)
        self.feed_list.setRowCount(len(feed.entries))
        for i, entry in enumerate(feed.entries):
            title_item = QTableWidgetItem(entry.title)
            self.feed_list.setItem(i, 0, title_item)
            url_item = QTableWidgetItem(entry.link)
            self.feed_list.setItem(i, 1, url_item)
            summary_item = QTableWidgetItem(entry.summary if entry.summary is not None else "No summary available")
            self.feed_list.setItem(i, 2, summary_item)
            timestamp = time.mktime(entry.published_parsed)
            local_time = time.localtime(timestamp)
            time_item = QTableWidgetItem(time.strftime("%Y-%m-%d at %H:%M:%S", local_time))
            self.feed_list.setItem(i, 3, time_item)

        if self.article_details_pane in self.splitter.children():
            self.article_details_pane.setParent(None)

    def change_feed(self, feed_id):
        self.feed_index = feed_id
        self.refresh_feed(feed_id)

    def manage_feeds(self):
        dialog = ManageFeedDialog()
        dialog.exec_()
        self.build_feeds_menu()

    # def open_setings(self):
    #     dialog = SettingsDialog()
    #     dialog.exec_()
    #     self.build_feeds_menu()

    def build_feeds_menu(self):
        for action in list(self.feed_menu.actions()):
            self.feed_menu.removeAction(action)

        add_feed_action = QAction('Add Feed', self)
        add_feed_action.triggered.connect(self.add_feed)
        add_feed_action.setShortcut('Ctrl+N')
        self.feed_menu.addAction(add_feed_action)

        manage_feeds_action = QAction('Manage Feeds', self)
        manage_feeds_action.triggered.connect(self.manage_feeds)
        self.feed_menu.addAction(manage_feeds_action)

        self.feed_menu.addSeparator()
        
        with sqlite3.connect(self.database) as db:
            cursor = db.cursor()
            cursor.execute('SELECT id, title FROM feeds')
            feeds = cursor.fetchall()

        if hasattr(self, 'more_feeds_menu'):
            self.more_feeds_menu.deleteLater()
            del self.more_feeds_menu
        
        for i, (feed_id, title) in enumerate(feeds):
            if i < 10:
                feed_action = QAction(title, self)
                feed_action.triggered.connect(lambda checked, fid=i: self.change_feed(fid))
                feed_action.setShortcut(f'Ctrl+{i+1 if i < 9 else 0}')
                self.feed_menu.addAction(feed_action)

        if len(feeds) > 10:
            self.more_feeds_menu = self.feed_menu.addMenu('More Feeds')

            for i, (feed_id, title) in enumerate(feeds):
                if i >= 10:
                    feed_action = QAction(title, self)
                    feed_action.triggered.connect(lambda checked, fid=i: self.change_feed(fid))
                    self.more_feeds_menu.addAction(feed_action)

        self.feed_menu.addSeparator()

        refresh_action = QAction('Refresh', self)
        refresh_action.setShortcut('Ctrl+R')
        refresh_action.triggered.connect(lambda: self.refresh_feed(self.feed_index))
        self.feed_menu.addAction(refresh_action)

    def open_url(self, row):
        url = self.feed_list.item(row, 1).text()
        webbrowser.open(url)

    def hide_column(self, column, action, setting: str=None):
        self.feed_list.setColumnHidden(column, not action.isChecked())
        if setting:
            self.settings.set('TableView', setting, action.isChecked())
            print(f"Set '{setting}' to {action.isChecked()}")
            self.settings.commit()

    def toggle_setting(self, category: str, setting: str):
        current = self.settings.getboolean(category, setting)
        self.settings.set(category, setting, not current)
        print(f"Set '{setting}' in '{category}' to {not current}")
        self.settings.commit()

    def init_config(self):
        settings = SettingsManager.connect(GlobConf.config)

        # Categories
        if not settings.config.has_section('TableView'):
            settings.config.add_section('TableView')
            print("Created section 'TableView'.")
        else:
            print("Section 'TableView' already exists.")

        if not settings.config.has_section('UI'):
            settings.config.add_section('UI')
            print("Created section 'UI'.")
        else:
            print("Section 'UI' already exists.")

        if not settings.config.has_section('proxy'):
            settings.config.add_section('proxy')
            print("Created section 'proxy'.")
        else:
            print("Section 'proxy' already exists.")

        # Options
        # TableView
        if not settings.config.has_option('TableView', 'show_url'):
            settings.set('TableView', 'show_url', False)
            print("Option 'show_url' set to False.")
        else:
            print("Option 'show_url' already exists. Skipping.")

        if not settings.config.has_option('TableView', 'show_summary'):
            settings.set('TableView', 'show_summary', False)
            print("Option 'show_summary' set to False.")
        else:
            print("Option 'show_summary' already exists. Skipping.")

        if not settings.config.has_option('TableView', 'show_timestamp'):
            settings.set('TableView', 'show_timestamp', True)
            print("Option 'show_timestamp' set to True.")
        else:
            print("Option 'show_timestamp' already exists. Skipping.")

        # UI
        if not settings.config.has_option('UI', 'custom_theming'):
            settings.set('UI', 'custom_theming', True)
            print("Option 'custom_theming' set to True.")
        else:
            print("Option 'custom_theming' already exists. Skipping.")

        # Proxy
        if not settings.config.has_option('proxy', 'use_proxy'):
            settings.set('proxy', 'use_proxy', False)
            print("Option 'use_proxy' set to False.")
        else:
            print("Option 'use_proxy' already exists. Skipping.")

        if not settings.config.has_option('proxy', 'proxy_address'):
            settings.set('proxy', 'proxy_address', "")
            print("Option 'proxy_address' set to \"\".")
        else:
            print("Option 'proxy_address' already exists. Skipping.")

        if not settings.config.has_option('proxy', 'proxy_port'):
            settings.set('proxy', 'proxy_port', "")
            print("Option 'proxy_port' set to \"\".")
        else:
            print("Option 'proxy_port' already exists. Skipping.")

        settings.commit()
        return settings

    def parse_feed(self, url):
        use_proxy = self.settings.getboolean('proxy', 'use_proxy', fallback=False)
        proxy_address = self.settings.get('proxy', 'proxy_address', fallback="")
        proxy_port = self.settings.get('proxy', 'proxy_port', fallback="")

        if use_proxy and proxy_address and proxy_port:
            print(f"Using proxy {proxy_address}:{proxy_port}")
            proxies = {
                'http': f'http://{proxy_address}:{proxy_port}',
                'https': f'http://{proxy_address}:{proxy_port}',
            }
            try:
                response = requests.get(url, proxies=proxies, timeout=10)
                response.raise_for_status()
                return feedparser.parse(response.text)
            except requests.exceptions.ProxyError:
                QMessageBox.warning(self, 'Proxy Error', 'The proxy failed to connect. It has been disabled.')
                self.set_proxy_usage(False)
                return self.parse_feed(url)
            except requests.RequestException as e:
                QMessageBox.warning(self, 'Network Error', f'Failed to fetch feed: {e}')
                return None
        else:
            return feedparser.parse(url)

    def set_proxy(self):
        EnterProxyDialog(self.settings).exec_()

    def set_proxy_usage(self, enabled: bool):
        if enabled and (not self.settings.get('proxy', 'proxy_address') or not self.settings.get('proxy', 'proxy_port')):
            QMessageBox.critical(self, 'Invalid Proxy Settings', 'No valid proxy set. Proxy usage cannot be enabled.')
            self.use_proxy_checkable.setChecked(False)
            return
        self.settings.set('proxy', 'use_proxy', enabled)
        self.use_proxy_checkable.setChecked(enabled)
        self.settings.commit()
        
if __name__ == '__main__':
    app = QApplication(sys.argv)
    feedstream = Feedstream(None)
    feedstream.show()
    sys.exit(app.exec_())