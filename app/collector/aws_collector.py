"""Read-only AWS configuration collector.

In DEMO_MODE (or when credentials are unavailable), loads fixture snapshots
for vulnerable/hardened lab environments so the pipeline remains demo-able.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from sqlalchemy.orm import Session

from app.config import DATA_DIR, EVIDENCE_DIR, get_settings
from app.models import Asset, Evidence, Scan, Snapshot

logger = logging.getLogger(__name__)
FIXTURES_DIR = DATA_DIR / "fixtures"


def _sha256_payload(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _session():
    settings = get_settings()
    kwargs: dict[str, Any] = {"region_name": settings.aws_region}
    if settings.aws_access_key_id and settings.aws_secret_access_key:
        kwargs["aws_access_key_id"] = settings.aws_access_key_id
        kwargs["aws_secret_access_key"] = settings.aws_secret_access_key
        if settings.aws_session_token:
            kwargs["aws_session_token"] = settings.aws_session_token
    session = boto3.Session(**kwargs)
    if settings.aws_role_arn:
        sts = session.client("sts")
        assumed = sts.assume_role(
            RoleArn=settings.aws_role_arn,
            RoleSessionName="CloudAudit360Collector",
        )
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=settings.aws_region,
        )
    return session


def _upsert_asset(
    db: Session,
    *,
    arn: str,
    type_: str,
    service: str,
    name: str,
    region: str,
    criticality: int = 2,
    exposure: str = "private",
    owner: str | None = None,
    tags: dict | None = None,
) -> Asset:
    asset = db.query(Asset).filter(Asset.arn == arn).first()
    if asset is None:
        asset = Asset(
            arn=arn,
            type=type_,
            service=service,
            name=name,
            region=region,
            criticality=criticality,
            exposure=exposure,
            owner=owner,
            tags_json=tags or {},
        )
        db.add(asset)
    else:
        asset.type = type_
        asset.service = service
        asset.name = name
        asset.region = region
        asset.criticality = criticality
        asset.exposure = exposure
        asset.owner = owner
        asset.tags_json = tags or {}
    db.flush()
    return asset


def _store_snapshot(
    db: Session,
    scan: Scan,
    service: str,
    resource_id: str,
    config: dict,
) -> Snapshot:
    snap = Snapshot(
        scan_id=scan.id,
        service=service,
        resource_id=resource_id,
        config_json=config,
        collected_at=_utcnow(),
    )
    db.add(snap)
    db.flush()

    digest = _sha256_payload(config)
    evidence_path = EVIDENCE_DIR / f"scan_{scan.id}" / f"{service}_{snap.id}.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(config, indent=2, default=str), encoding="utf-8")
    db.add(
        Evidence(
            scan_id=scan.id,
            finding_id=None,
            kind="snapshot",
            path_or_json=str(evidence_path),
            sha256=digest,
        )
    )
    return snap


def _criticality_from_tags(tags: dict | None) -> int:
    if not tags:
        return 2
    raw = tags.get("criticality") or tags.get("Criticality")
    try:
        val = int(raw)
        return val if val in (1, 2, 3) else 2
    except (TypeError, ValueError):
        return 2


def load_demo_fixtures(db: Session, scan: Scan, environment: str) -> list[Snapshot]:
    """Load JSON fixtures for vulnerable/hardened demo environments."""
    env = environment if environment in ("vulnerable", "hardened") else "vulnerable"
    fixture_path = FIXTURES_DIR / f"{env}.json"
    if not fixture_path.exists():
        raise FileNotFoundError(f"Demo fixture missing: {fixture_path}")

    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    snapshots: list[Snapshot] = []

    for asset_data in payload.get("assets", []):
        _upsert_asset(
            db,
            arn=asset_data["arn"],
            type_=asset_data["type"],
            service=asset_data["service"],
            name=asset_data["name"],
            region=asset_data.get("region", "us-east-1"),
            criticality=asset_data.get("criticality", 2),
            exposure=asset_data.get("exposure", "private"),
            owner=asset_data.get("owner"),
            tags=asset_data.get("tags"),
        )

    for item in payload.get("snapshots", []):
        snap = _store_snapshot(
            db,
            scan,
            service=item["service"],
            resource_id=item["resource_id"],
            config=item["config"],
        )
        snapshots.append(snap)

    logger.info("Loaded %s demo snapshots for env=%s", len(snapshots), env)
    return snapshots


def collect_live(db: Session, scan: Scan) -> list[Snapshot]:
    """Collect live AWS configuration via boto3 (read-only)."""
    session = _session()
    region = get_settings().aws_region
    snapshots: list[Snapshot] = []

    # --- IAM ---
    iam = session.client("iam")
    account_summary = iam.get_account_summary().get("SummaryMap", {})
    try:
        password_policy = iam.get_account_password_policy().get("PasswordPolicy", {})
    except ClientError:
        password_policy = {}

    users_resp = iam.list_users().get("Users", [])
    users_detail = []
    for user in users_resp:
        uname = user["UserName"]
        mfa = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
        keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
        key_details = []
        for key in keys:
            last_used = {}
            try:
                last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"]).get(
                    "AccessKeyLastUsed", {}
                )
            except ClientError:
                pass
            key_details.append({**key, "LastUsed": last_used})
        attached = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
        users_detail.append(
            {
                **user,
                "MFADevices": mfa,
                "AccessKeys": key_details,
                "AttachedPolicies": attached,
            }
        )
        arn = user["Arn"]
        _upsert_asset(
            db,
            arn=arn,
            type_="iam-user",
            service="iam",
            name=uname,
            region="global",
            criticality=3 if any(p.get("PolicyName") == "AdministratorAccess" for p in attached) else 2,
            exposure="internal",
        )

    root_mfa = account_summary.get("AccountMFAEnabled", 0)
    root_keys = []
    try:
        # Root access keys are reflected in summary; list via credential report is heavy —
        # use AccountAccessKeysPresent
        root_keys = [{"present": bool(account_summary.get("AccountAccessKeysPresent", 0))}]
    except Exception:  # noqa: BLE001
        root_keys = []

    iam_config = {
        "AccountSummary": account_summary,
        "PasswordPolicy": password_policy,
        "Users": users_detail,
        "Root": {
            "MFAEnabled": bool(root_mfa),
            "AccessKeysPresent": bool(account_summary.get("AccountAccessKeysPresent", 0)),
            "AccessKeys": root_keys,
        },
    }
    snapshots.append(_store_snapshot(db, scan, "iam", "account", iam_config))
    _upsert_asset(
        db,
        arn=f"arn:aws:iam::{account_summary.get('AccountId', 'unknown')}:root",
        type_="iam-root",
        service="iam",
        name="root",
        region="global",
        criticality=3,
        exposure="internal",
    )

    # --- S3 ---
    s3 = session.client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    bucket_configs = []
    for bucket in buckets:
        name = bucket["Name"]
        cfg: dict[str, Any] = {"Name": name, "CreationDate": str(bucket.get("CreationDate"))}
        try:
            cfg["PublicAccessBlock"] = s3.get_public_access_block(Bucket=name).get(
                "PublicAccessBlockConfiguration", {}
            )
        except ClientError:
            cfg["PublicAccessBlock"] = {}
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            cfg["Encryption"] = enc.get("ServerSideEncryptionConfiguration", {})
        except ClientError:
            cfg["Encryption"] = {}
        try:
            cfg["Versioning"] = s3.get_bucket_versioning(Bucket=name)
        except ClientError:
            cfg["Versioning"] = {}
        try:
            cfg["Logging"] = s3.get_bucket_logging(Bucket=name).get("LoggingEnabled")
        except ClientError:
            cfg["Logging"] = None
        try:
            cfg["Policy"] = s3.get_bucket_policy(Bucket=name).get("Policy")
        except ClientError:
            cfg["Policy"] = None
        try:
            cfg["ACL"] = s3.get_bucket_acl(Bucket=name)
        except ClientError:
            cfg["ACL"] = {}

        pab = cfg.get("PublicAccessBlock") or {}
        is_public = not all(
            [
                pab.get("BlockPublicAcls", False),
                pab.get("IgnorePublicAcls", False),
                pab.get("BlockPublicPolicy", False),
                pab.get("RestrictPublicBuckets", False),
            ]
        )
        exposure = "public" if is_public else "private"
        arn = f"arn:aws:s3:::{name}"
        _upsert_asset(
            db,
            arn=arn,
            type_="s3-bucket",
            service="s3",
            name=name,
            region=region,
            criticality=2,
            exposure=exposure,
        )
        bucket_configs.append(cfg)
        snapshots.append(_store_snapshot(db, scan, "s3", name, cfg))

    # --- EC2 / VPC ---
    ec2 = session.client("ec2")
    sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    for sg in sgs:
        open_world = False
        for perm in sg.get("IpPermissions", []):
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    open_world = True
        arn = f"arn:aws:ec2:{region}:{sg.get('OwnerId', 'unknown')}:security-group/{sg['GroupId']}"
        _upsert_asset(
            db,
            arn=arn,
            type_="security-group",
            service="ec2",
            name=sg.get("GroupName", sg["GroupId"]),
            region=region,
            criticality=2,
            exposure="public" if open_world else "private",
        )
        snapshots.append(_store_snapshot(db, scan, "ec2", sg["GroupId"], {"SecurityGroup": sg}))

    flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
    snapshots.append(
        _store_snapshot(db, scan, "ec2", "vpc-flow-logs", {"FlowLogs": flow_logs})
    )

    try:
        ebs_enc = ec2.get_ebs_encryption_by_default()
        snapshots.append(
            _store_snapshot(
                db,
                scan,
                "ec2",
                "ebs-default-encryption",
                {"EbsEncryptionByDefault": ebs_enc.get("EbsEncryptionByDefault", False)},
            )
        )
    except ClientError as exc:
        logger.warning("EBS default encryption query failed: %s", exc)

    volumes = ec2.describe_volumes().get("Volumes", [])
    snapshots.append(_store_snapshot(db, scan, "ec2", "ebs-volumes", {"Volumes": volumes}))

    # --- CloudTrail ---
    ct = session.client("cloudtrail")
    trails = ct.describe_trails().get("trailList", [])
    trail_status = []
    for trail in trails:
        status = {}
        try:
            status = ct.get_trail_status(Name=trail["Name"])
        except ClientError:
            pass
        trail_status.append({**trail, "Status": status})
    snapshots.append(
        _store_snapshot(db, scan, "cloudtrail", "trails", {"Trails": trail_status})
    )

    # --- GuardDuty ---
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        snapshots.append(
            _store_snapshot(db, scan, "guardduty", "detectors", {"DetectorIds": detectors})
        )
    except ClientError as exc:
        logger.warning("GuardDuty collect failed: %s", exc)
        snapshots.append(
            _store_snapshot(db, scan, "guardduty", "detectors", {"DetectorIds": [], "error": str(exc)})
        )

    # --- KMS ---
    kms = session.client("kms")
    keys = kms.list_keys().get("Keys", [])
    key_details = []
    for key in keys:
        kid = key["KeyId"]
        meta = kms.describe_key(KeyId=kid).get("KeyMetadata", {})
        rotation = False
        try:
            rotation = kms.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled", False)
        except ClientError:
            pass
        key_details.append({**meta, "KeyRotationEnabled": rotation})
        _upsert_asset(
            db,
            arn=meta.get("Arn", f"arn:aws:kms:{region}:key/{kid}"),
            type_="kms-key",
            service="kms",
            name=meta.get("Description") or kid,
            region=region,
            criticality=2,
            exposure="private",
        )
    snapshots.append(_store_snapshot(db, scan, "kms", "keys", {"Keys": key_details}))

    # --- RDS ---
    rds = session.client("rds")
    instances = rds.describe_db_instances().get("DBInstances", [])
    for inst in instances:
        arn = inst.get("DBInstanceArn", inst["DBInstanceIdentifier"])
        exposure = "public" if inst.get("PubliclyAccessible") else "private"
        _upsert_asset(
            db,
            arn=arn,
            type_="rds-instance",
            service="rds",
            name=inst["DBInstanceIdentifier"],
            region=region,
            criticality=_criticality_from_tags(
                {t["Key"]: t["Value"] for t in inst.get("TagList", [])}
            ),
            exposure=exposure,
        )
        snapshots.append(
            _store_snapshot(db, scan, "rds", inst["DBInstanceIdentifier"], {"DBInstance": inst})
        )

    return snapshots


def collect(db: Session, scan: Scan, environment: str = "other") -> list[Snapshot]:
    """Collect AWS config into snapshots. Falls back to demo fixtures when needed."""
    settings = get_settings()
    if settings.demo_mode or environment in ("vulnerable", "hardened"):
        if settings.demo_mode or not settings.aws_access_key_id:
            return load_demo_fixtures(db, scan, environment)
    try:
        return collect_live(db, scan)
    except (NoCredentialsError, BotoCoreError, ClientError) as exc:
        logger.warning("Live AWS collect failed (%s); using demo fixtures", exc)
        return load_demo_fixtures(db, scan, environment if environment != "other" else "vulnerable")
