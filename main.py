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
    QCheckBox,
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
        lab_button.clicked.connect(self.open_lab_setup)

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

    def open_lab_setup(self) -> None:
        """Open the lab setup dialog with provided credentials."""

        access_key = self.access_key_edit.text()
        secret_key = self.secret_key_edit.text()
        window = LabSetupWindow(access_key, secret_key)
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


class LabSetupWindow(QDialog):
    """Dialog to create or destroy a simple lab VPC."""

    def __init__(self, access_key: str, secret_key: str):
        super().__init__()
        self.access_key = access_key
        self.secret_key = secret_key
        self.setWindowTitle("Lab Setup")

        layout = QVBoxLayout()

        region_layout = QHBoxLayout()
        region_label = QLabel("Region:")
        self.region_combo = QComboBox()
        for reg in boto3.session.Session().get_available_regions("ec2"):
            self.region_combo.addItem(reg)
        region_layout.addWidget(region_label)
        region_layout.addWidget(self.region_combo)
        layout.addLayout(region_layout)

        az_layout = QHBoxLayout()
        az_label = QLabel("Availability Zones:")
        self.az_combo = QComboBox()
        for i in range(1, 4):
            self.az_combo.addItem(str(i))
        az_layout.addWidget(az_label)
        az_layout.addWidget(self.az_combo)
        layout.addLayout(az_layout)

        igw_layout = QHBoxLayout()
        igw_label = QLabel("Internet Gateway:")
        self.igw_check = QCheckBox()
        igw_layout.addWidget(igw_label)
        igw_layout.addWidget(self.igw_check)
        layout.addLayout(igw_layout)

        nat_layout = QHBoxLayout()
        nat_label = QLabel("NAT Gateway:")
        self.nat_check = QCheckBox()
        nat_layout.addWidget(nat_label)
        nat_layout.addWidget(self.nat_check)
        layout.addLayout(nat_layout)

        buttons_layout = QHBoxLayout()
        create_btn = QPushButton("Create")
        destroy_btn = QPushButton("Destroy")
        create_btn.clicked.connect(self.create_lab)
        destroy_btn.clicked.connect(self.destroy_lab)
        buttons_layout.addWidget(create_btn)
        buttons_layout.addWidget(destroy_btn)
        layout.addLayout(buttons_layout)

        self.setLayout(layout)

    def create_lab(self) -> None:
        region = self.region_combo.currentText()
        num_azs = int(self.az_combo.currentText())
        include_nat = self.nat_check.isChecked()
        include_igw = self.igw_check.isChecked() or include_nat
        try:
            create_lab_environment(
                self.access_key,
                self.secret_key,
                region,
                num_azs,
                include_igw,
                include_nat,
            )
            QMessageBox.information(self, "Created", "Lab environment created.")
        except Exception as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def destroy_lab(self) -> None:
        region = self.region_combo.currentText()
        try:
            destroy_lab_environment(self.access_key, self.secret_key, region)
            QMessageBox.information(self, "Destroyed", "Lab environment destroyed.")
        except Exception as exc:
            QMessageBox.warning(self, "Error", str(exc))


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


def create_lab_environment(
    access_key: str,
    secret_key: str,
    region: str,
    num_azs: int,
    include_igw: bool,
    include_nat: bool,
) -> None:
    """Create a VPC for lab use with optional internet and NAT gateways."""

    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )
    ec2 = session.resource("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc.wait_until_available()
    vpc.create_tags(Tags=[{"Key": "Name", "Value": "LabVPC"}])

    ec2_client = session.client("ec2")
    azs = ec2_client.describe_availability_zones()["AvailabilityZones"]

    if include_nat:
        include_igw = True

    public_subnets = []
    private_subnets = []
    for i in range(num_azs):
        az = azs[i]["ZoneName"]
        private_cidr = f"10.0.{i*2}.0/24"
        priv_subnet = vpc.create_subnet(CidrBlock=private_cidr, AvailabilityZone=az)
        priv_subnet.create_tags(
            Tags=[{"Key": "Name", "Value": f"PrivateSubnet{i+1}"}]
        )
        private_subnets.append(priv_subnet)
        if include_igw:
            public_cidr = f"10.0.{i*2+1}.0/24"
            pub_subnet = vpc.create_subnet(CidrBlock=public_cidr, AvailabilityZone=az)
            pub_subnet.create_tags(
                Tags=[{"Key": "Name", "Value": f"PublicSubnet{i+1}"}]
            )
            public_subnets.append(pub_subnet)

    if include_igw:
        igw = ec2.create_internet_gateway()
        igw.create_tags(Tags=[{"Key": "Name", "Value": "LabIGW"}])
        vpc.attach_internet_gateway(InternetGatewayId=igw.id)
        rt = vpc.create_route_table()
        rt.create_tags(Tags=[{"Key": "Name", "Value": "PublicRouteTable"}])
        rt.create_route(DestinationCidrBlock="0.0.0.0/0", GatewayId=igw.id)
        for subnet in public_subnets:
            rt.associate_with_subnet(SubnetId=subnet.id)

    if include_nat:
        eip = ec2_client.allocate_address(Domain="vpc")
        nat = ec2_client.create_nat_gateway(
            SubnetId=public_subnets[0].id,
            AllocationId=eip["AllocationId"],
        )["NatGateway"]
        waiter = ec2_client.get_waiter("nat_gateway_available")
        waiter.wait(NatGatewayIds=[nat["NatGatewayId"]])
        priv_rt = vpc.create_route_table()
        priv_rt.create_tags(Tags=[{"Key": "Name", "Value": "PrivateRouteTable"}])
        priv_rt.create_route(
            DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat["NatGatewayId"]
        )
        for subnet in private_subnets:
            priv_rt.associate_with_subnet(SubnetId=subnet.id)


def destroy_lab_environment(access_key: str, secret_key: str, region: str) -> None:
    """Delete the lab VPC and related resources."""

    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )
    ec2 = session.resource("ec2")
    ec2_client = session.client("ec2")
    vpcs = ec2.vpcs.filter(Filters=[{"Name": "tag:Name", "Values": ["LabVPC"]}])
    for vpc in vpcs:
        nat_gws = ec2_client.describe_nat_gateways(
            Filters=[{"Name": "vpc-id", "Values": [vpc.id]}]
        ).get("NatGateways", [])
        for nat in nat_gws:
            nat_id = nat["NatGatewayId"]
            ec2_client.delete_nat_gateway(NatGatewayId=nat_id)
            waiter = ec2_client.get_waiter("nat_gateway_deleted")
            waiter.wait(NatGatewayIds=[nat_id])
            for addr in nat.get("NatGatewayAddresses", []):
                alloc_id = addr.get("AllocationId")
                if alloc_id:
                    ec2_client.release_address(AllocationId=alloc_id)
        for rt in vpc.route_tables.all():
            associations = list(rt.associations)
            if all(not assoc.main for assoc in associations):
                rt.delete()
        for igw in vpc.internet_gateways.all():
            vpc.detach_internet_gateway(InternetGatewayId=igw.id)
            igw.delete()
        for subnet in vpc.subnets.all():
            subnet.delete()
        vpc.delete()


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
