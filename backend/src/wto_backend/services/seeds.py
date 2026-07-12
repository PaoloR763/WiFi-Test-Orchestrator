from __future__ import annotations

from uuid import UUID, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from wto_backend.audit import write_audit
from wto_backend.domain.models import Capability, Permission, Role, RolePermission

SEED_NAMESPACE = UUID("f90b764c-e086-4a47-a1f8-c2d996310001")

PERMISSIONS = {
    "users.read": "Read human users.",
    "users.create": "Create human users.",
    "users.update": "Update or disable human users.",
    "users.roles_manage": "Assign or remove human roles.",
    "sessions.revoke": "Revoke user sessions.",
    "roles.read": "Read human roles.",
    "permissions.read": "Read explicit permissions.",
    "audit.read": "Read the bounded audit trail.",
    "admin.protected_read": "Use the protected administrative demonstration endpoint.",
    "enrollment_tokens.create": "Create bounded agent enrollment tokens.",
    "enrollment_tokens.read": "Read enrollment token metadata.",
    "enrollment_tokens.revoke": "Revoke agent enrollment tokens.",
    "agents.read": "Read agent identity and status.",
    "agents.revoke": "Revoke an agent and all of its credentials.",
    "agents.recover": "Issue recovery enrollment tokens for an agent.",
    "agent_credentials.read": "Read non-secret agent credential metadata.",
    "agent_credentials.revoke": "Revoke an individual agent credential.",
    "capability_manifests.read": "Read validated capability manifests.",
    "agent_protocol.read": "Inspect agent protocol compatibility.",
}

ROLES = {
    "administrator": (
        "Administrator",
        "Full explicit human administration permissions.",
    ),
    "test_manager": ("Test Manager", "Read users, RBAC, and audit information."),
    "operator": ("Operator", "Read RBAC reference information."),
    "viewer": ("Viewer", "Read RBAC reference information."),
}

ROLE_PERMISSIONS = {
    "administrator": set(PERMISSIONS),
    "test_manager": {
        "users.read",
        "roles.read",
        "permissions.read",
        "audit.read",
        "enrollment_tokens.create",
        "enrollment_tokens.read",
        "enrollment_tokens.revoke",
        "agents.read",
        "agents.recover",
        "agent_credentials.read",
        "capability_manifests.read",
        "agent_protocol.read",
    },
    "operator": {
        "roles.read",
        "permissions.read",
        "agents.read",
        "agent_credentials.read",
        "capability_manifests.read",
        "agent_protocol.read",
    },
    "viewer": {
        "roles.read",
        "permissions.read",
        "agents.read",
        "capability_manifests.read",
        "agent_protocol.read",
    },
}

CAPABILITY_IDS = (
    "wifi.connection.read",
    "wifi.scan",
    "wifi.rssi.read",
    "network.icmp.ping",
    "network.tcp.probe",
    "network.http.probe",
    "traffic.tcp.throughput",
    "traffic.udp.throughput",
    "traffic.http.download",
    "traffic.http.upload",
    "traffic.latency_under_load",
    "capture.ip",
    "capture.ieee80211.monitor",
    "traffic.pcap.replay",
    "execution.background.continuous",
)


def stable_id(kind: str, key: str) -> UUID:
    return uuid5(SEED_NAMESPACE, f"{kind}:{key}")


def seed_rbac(session: Session, *, correlation_id: str) -> tuple[int, int]:
    created = 0
    updated = 0
    permission_by_key: dict[str, Permission] = {}
    for key, description in PERMISSIONS.items():
        permission = session.scalar(select(Permission).where(Permission.key == key))
        if permission is None:
            permission = Permission(
                id=stable_id("permission", key), key=key, description=description
            )
            session.add(permission)
            created += 1
        elif permission.description != description:
            permission.description = description
            updated += 1
        permission_by_key[key] = permission
    session.flush()
    role_by_key: dict[str, Role] = {}
    for key, (display_name, description) in ROLES.items():
        role = session.scalar(select(Role).where(Role.key == key))
        if role is None:
            role = Role(
                id=stable_id("role", key),
                key=key,
                display_name=display_name,
                description=description,
            )
            session.add(role)
            created += 1
        else:
            if role.display_name != display_name or role.description != description:
                role.display_name = display_name
                role.description = description
                updated += 1
        role_by_key[key] = role
    session.flush()
    for role_key, permission_keys in ROLE_PERMISSIONS.items():
        role = role_by_key[role_key]
        for permission_key in permission_keys:
            permission = permission_by_key[permission_key]
            exists = session.scalar(
                select(RolePermission.id).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == permission.id,
                )
            )
            if exists is None:
                session.add(
                    RolePermission(
                        id=stable_id("role-permission", f"{role_key}:{permission_key}"),
                        role_id=role.id,
                        permission_id=permission.id,
                    )
                )
                created += 1
    for capability_key in CAPABILITY_IDS:
        capability = session.scalar(
            select(Capability).where(
                Capability.key == capability_key, Capability.version == "1.0.0"
            )
        )
        if capability is None:
            session.add(
                Capability(
                    id=stable_id("capability", f"{capability_key}:1.0.0"),
                    key=capability_key,
                    version="1.0.0",
                )
            )
            created += 1
    write_audit(
        session,
        actor_type="system",
        actor_id=None,
        action="rbac.seed",
        resource_type="rbac",
        resource_id=None,
        outcome="success",
        correlation_id=correlation_id,
        metadata={"created_count": created, "updated_count": updated},
    )
    session.commit()
    return created, updated
