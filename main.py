import sys
import boto3
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
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
        s3_button.clicked.connect(lambda: self.open_subwindow("S3 Nuke"))

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
