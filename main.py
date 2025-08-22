import sys
from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from PyQt5.QtCore import Qt


class SubWindow(QDialog):
    """Placeholder window for future tools."""

    def __init__(self, title: str):
        super().__init__()
        self.setWindowTitle(title)

        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"{title} window placeholder"))
        self.setLayout(layout)


class MainWindow(QMainWindow):
    """Main menu for the AWS Swiss Army Knife."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("AWS Swiss Army Knife")
        self.resize(400, 300)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        # Top bar with AWS key entry
        top_bar = QWidget()
        top_bar.setStyleSheet("background-color: #005FCE;")
        top_layout = QHBoxLayout()
        top_bar.setLayout(top_layout)

        key_label = QLabel("AWS Access Key:")
        key_label.setStyleSheet("color: white; font-weight: bold;")
        self.access_key_edit = QLineEdit()
        self.access_key_edit.setPlaceholderText("Enter your key")

        top_layout.addWidget(key_label)
        top_layout.addWidget(self.access_key_edit)

        main_layout.addWidget(top_bar)

        # Buttons for tools
        buttons_layout = QVBoxLayout()

        s3_button = QPushButton("S3 Nuke")
        s3_button.clicked.connect(lambda: self.open_subwindow("S3 Nuke"))

        env_button = QPushButton("Environment Purge")
        env_button.clicked.connect(lambda: self.open_subwindow("Environment Purge"))

        lab_button = QPushButton("Lab Setup")
        lab_button.clicked.connect(lambda: self.open_subwindow("Lab Setup"))

        for button in (s3_button, env_button, lab_button):
            button.setMinimumHeight(40)
            buttons_layout.addWidget(button)

        main_layout.addLayout(buttons_layout)
        main_layout.addStretch()

        self.setStyleSheet(
            "QMainWindow {background-color: #F0F0F0;} QPushButton {font-size: 16px;}"
        )

    def open_subwindow(self, title: str) -> None:
        """Open a placeholder window for the chosen tool."""

        window = SubWindow(title)
        window.exec_()


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
