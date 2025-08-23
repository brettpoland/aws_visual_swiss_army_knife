import os
import sys
import boto3
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QInputDialog,
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

        # Top bar with title and credentials
        top_bar = QWidget()
        top_bar.setStyleSheet("background-color: #005FCE;")
        top_layout = QVBoxLayout()
        top_bar.setLayout(top_layout)

        title_label = QLabel("AWS Swiss Army Knife")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet(
            "color: white; font-size: 18px; font-weight: bold; padding: 5px;"
        )

        creds_box = QWidget()
        creds_box.setStyleSheet(
            "background-color: #E0E0E0; border-radius: 4px; padding: 5px;"
        )
        creds_layout = QVBoxLayout()
        creds_box.setLayout(creds_layout)

        access_layout = QHBoxLayout()
        access_label = QLabel("Access Key:")
        self.access_key_edit = QLineEdit()
        access_layout.addWidget(access_label)
        access_layout.addWidget(self.access_key_edit)

        secret_layout = QHBoxLayout()
        secret_label = QLabel("Secret Key:")
        self.secret_key_edit = QLineEdit()
        self.secret_key_edit.setEchoMode(QLineEdit.Password)
        secret_layout.addWidget(secret_label)
        secret_layout.addWidget(self.secret_key_edit)

        creds_layout.addLayout(access_layout)
        creds_layout.addLayout(secret_layout)

        top_layout.addWidget(title_label)
        top_layout.addWidget(creds_box)

        main_layout.addWidget(top_bar)

        # Buttons for tools
        buttons_layout = QVBoxLayout()

        s3_button = QPushButton("S3 Nuke")
        s3_button.clicked.connect(self.open_s3_nuke)

        env_button = QPushButton("Environment Purge")
        env_button.clicked.connect(self.open_env_purge)

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

    def open_env_purge(self) -> None:
        """Open the environment purge dialog with provided credentials."""

        access_key = self.access_key_edit.text()
        secret_key = self.secret_key_edit.text()
        window = EnvironmentPurgeWindow(access_key, secret_key)
        window.exec_()

    def open_s3_nuke(self) -> None:
        """Open the S3 nuke window with provided credentials."""

        access_key = self.access_key_edit.text()
        secret_key = self.secret_key_edit.text()
        window = S3NukeWindow(access_key, secret_key)
        window.exec_()


class S3NukeWindow(QDialog):
    """Manage S3 buckets and objects."""

    def __init__(self, access_key: str, secret_key: str):
        super().__init__()
        self.access_key = access_key
        self.secret_key = secret_key
        self.setWindowTitle("S3 Nuke")

        layout = QVBoxLayout()
        self.setLayout(layout)

        region_layout = QHBoxLayout()
        region_label = QLabel("Region:")
        self.region_combo = QComboBox()
        self.region_combo.addItem("us-east1")
        for reg in boto3.session.Session().get_available_regions("s3"):
            if reg != "us-east-1":
                self.region_combo.addItem(reg)
        self.region_combo.setCurrentText("us-east1")
        self.region_combo.currentTextChanged.connect(self.connect_to_region)
        region_layout.addWidget(region_label)
        region_layout.addWidget(self.region_combo)
        layout.addLayout(region_layout)

        self.bucket_list = QListWidget()
        layout.addWidget(self.bucket_list)

        buttons_layout = QHBoxLayout()
        upload_btn = QPushButton("Upload File")
        upload_btn.clicked.connect(self.upload_file)
        delete_file_btn = QPushButton("Delete File")
        delete_file_btn.clicked.connect(self.delete_file)
        delete_folder_btn = QPushButton("Delete Folder")
        delete_folder_btn.clicked.connect(self.delete_folder)
        nuke_btn = QPushButton("Nuke ALL Buckets")
        nuke_btn.clicked.connect(self.nuke_buckets)
        for btn in (upload_btn, delete_file_btn, delete_folder_btn, nuke_btn):
            buttons_layout.addWidget(btn)
        layout.addLayout(buttons_layout)

        self.connect_to_region(self.region_combo.currentText())

    def canonical_region(self, region: str) -> str:
        return "us-east-1" if region == "us-east1" else region

    def connect_to_region(self, region: str) -> None:
        region = self.canonical_region(region)
        try:
            self.s3 = boto3.client(
                "s3",
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=region,
            )
            self.list_buckets()
        except Exception as exc:
            QMessageBox.warning(self, "Connection Error", str(exc))

    def list_buckets(self) -> None:
        self.bucket_list.clear()
        try:
            resp = self.s3.list_buckets()
            region = self.canonical_region(self.region_combo.currentText())
            for bucket in resp.get("Buckets", []):
                name = bucket["Name"]
                loc = (
                    self.s3.get_bucket_location(Bucket=name).get("LocationConstraint")
                    or "us-east-1"
                )
                if loc == region:
                    self.bucket_list.addItem(name)
        except Exception as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def selected_bucket(self) -> str:
        item = self.bucket_list.currentItem()
        return item.text() if item else ""

    def upload_file(self) -> None:
        bucket = self.selected_bucket()
        if not bucket:
            QMessageBox.warning(self, "No Bucket", "Select a bucket first")
            return
        file_path, _ = QFileDialog.getOpenFileName(self, "Select file to upload")
        if file_path:
            key = os.path.basename(file_path)
            try:
                self.s3.upload_file(file_path, bucket, key)
                QMessageBox.information(
                    self, "Uploaded", f"{key} uploaded to {bucket}"
                )
            except Exception as exc:
                QMessageBox.warning(self, "Error", str(exc))

    def delete_file(self) -> None:
        bucket = self.selected_bucket()
        if not bucket:
            QMessageBox.warning(self, "No Bucket", "Select a bucket first")
            return
        key, ok = QInputDialog.getText(self, "Delete File", "Object key:")
        if ok and key:
            try:
                self.s3.delete_object(Bucket=bucket, Key=key)
                QMessageBox.information(
                    self, "Deleted", f"{key} deleted from {bucket}"
                )
            except Exception as exc:
                QMessageBox.warning(self, "Error", str(exc))

    def delete_folder(self) -> None:
        bucket = self.selected_bucket()
        if not bucket:
            QMessageBox.warning(self, "No Bucket", "Select a bucket first")
            return
        prefix, ok = QInputDialog.getText(self, "Delete Folder", "Folder prefix:")
        if ok and prefix:
            s3_resource = boto3.resource(
                "s3",
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.canonical_region(self.region_combo.currentText()),
            )
            bucket_obj = s3_resource.Bucket(bucket)
            bucket_obj.objects.filter(Prefix=prefix).delete()
            QMessageBox.information(
                self, "Deleted", f"Folder {prefix} deleted from {bucket}"
            )

    def nuke_buckets(self) -> None:
        reply = QMessageBox.question(
            self,
            "Confirm Nuke",
            "Delete all buckets in this region?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            s3_resource = boto3.resource(
                "s3",
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.canonical_region(self.region_combo.currentText()),
            )
            for i in range(self.bucket_list.count()):
                name = self.bucket_list.item(i).text()
                bucket = s3_resource.Bucket(name)
                bucket.objects.all().delete()
                bucket.delete()
            self.list_buckets()
            QMessageBox.information(self, "Nuked", "All buckets deleted")


class EnvironmentPurgeWindow(QDialog):
    """Dialog to purge an AWS environment."""

    def __init__(self, access_key: str, secret_key: str):
        super().__init__()
        self.access_key = access_key
        self.secret_key = secret_key
        self.setWindowTitle("Environment Purge")

        layout = QVBoxLayout()

        region_layout = QHBoxLayout()
        region_label = QLabel("Region:")
        self.region_combo = QComboBox()
        self.region_combo.addItem("All")
        for reg in boto3.session.Session().get_available_regions("ec2"):
            self.region_combo.addItem(reg)
        region_layout.addWidget(region_label)
        region_layout.addWidget(self.region_combo)

        layout.addLayout(region_layout)
        purge_button = QPushButton("Purge All")
        purge_button.setStyleSheet("font-weight: bold;")
        purge_button.clicked.connect(self.confirm_purge)

        layout.addWidget(purge_button)
        self.setLayout(layout)

    def confirm_purge(self) -> None:
        """Ask for confirmation before purging resources."""

        reply = QMessageBox.question(
            self,
            "Confirm Purge",
            "Are you sure you want to purge all resources?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            region = self.region_combo.currentText()
            purge_aws_environment(self.access_key, self.secret_key, region)
            QMessageBox.information(self, "Purge Complete", "All resources purged.")


def purge_aws_environment(access_key: str, secret_key: str, region: str) -> None:
    """Delete common AWS resources using the provided credentials."""

    regions = (
        boto3.session.Session().get_available_regions("ec2")
        if region == "All"
        else [region]
    )

    # S3 buckets (global service but buckets have regions)
    s3_client = boto3.client(
        "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key
    )
    buckets = s3_client.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket["Name"]
        loc = (
            s3_client.get_bucket_location(Bucket=name).get("LocationConstraint")
            or "us-east-1"
        )
        if region == "All" or loc == region:
            s3 = boto3.resource(
                "s3",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=loc,
            )
            b = s3.Bucket(name)
            b.objects.all().delete()
            b.delete()

    for reg in regions:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=reg,
        )

        ec2 = session.resource("ec2")

        # EC2 instances
        for instance in ec2.instances.all():
            instance.terminate()

        # VPCs
        for vpc in ec2.vpcs.all():
            if vpc.is_default:
                continue
            for subnet in vpc.subnets.all():
                subnet.delete()
            for igw in vpc.internet_gateways.all():
                vpc.detach_internet_gateway(InternetGatewayId=igw.id)
                igw.delete()
            for rt in vpc.route_tables.all():
                if not rt.associations:
                    rt.delete()
            vpc.delete()

    # Route53 hosted zones (global)
    if region == "All":
        r53 = boto3.client(
            "route53", aws_access_key_id=access_key, aws_secret_access_key=secret_key
        )
        zones = r53.list_hosted_zones().get("HostedZones", [])
        for zone in zones:
            zone_id = zone["Id"]
            records = r53.list_resource_record_sets(HostedZoneId=zone_id)[
                "ResourceRecordSets"
            ]
            changes = []
            for record in records:
                if record["Type"] in ("NS", "SOA"):
                    continue
                changes.append({"Action": "DELETE", "ResourceRecordSet": record})
            if changes:
                r53.change_resource_record_sets(
                    HostedZoneId=zone_id, ChangeBatch={"Changes": changes}
                )
            r53.delete_hosted_zone(Id=zone_id)


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
