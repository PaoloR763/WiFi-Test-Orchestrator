from __future__ import annotations

import argparse
import getpass
import os
import sys
from uuid import uuid4

from wto_backend.config import get_settings
from wto_backend.db.session import Database
from wto_backend.security.passwords import PasswordManager
from wto_backend.services.bootstrap import bootstrap_administrator
from wto_backend.services.seeds import seed_rbac


def password_manager() -> PasswordManager:
    settings = get_settings()
    return PasswordManager(
        memory_cost=settings.argon2_memory_cost,
        time_cost=settings.argon2_time_cost,
        parallelism=settings.argon2_parallelism,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wto-backend")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("seed-rbac")
    bootstrap = commands.add_parser("bootstrap-admin")
    bootstrap.add_argument("--username", required=True)
    bootstrap.add_argument("--password-stdin", action="store_true")
    bootstrap.add_argument("--password-env", action="store_true")
    return parser


def read_bootstrap_password(*, from_stdin: bool, from_environment: bool) -> str:
    if from_stdin and from_environment:
        raise ValueError("choose exactly one password input mechanism")
    if from_environment:
        try:
            return os.environ["WTO_BOOTSTRAP_ADMIN_PASSWORD"]
        except KeyError as error:
            raise ValueError("WTO_BOOTSTRAP_ADMIN_PASSWORD is not set") from error
    if from_stdin:
        value = sys.stdin.readline().rstrip("\r\n")
        if not value:
            raise ValueError("password input was empty")
        return value
    return getpass.getpass("Initial administrator credential: ")


def main() -> None:
    args = build_parser().parse_args()
    settings = get_settings()
    database = Database(settings.database_url)
    correlation_id = f"cli-{uuid4()}"
    try:
        with database.session_factory() as session:
            if args.command == "seed-rbac":
                created, updated = seed_rbac(session, correlation_id=correlation_id)
                print(f"RBAC seed complete: created={created}, updated={updated}")
            elif args.command == "bootstrap-admin":
                password = read_bootstrap_password(
                    from_stdin=args.password_stdin, from_environment=args.password_env
                )
                user, created = bootstrap_administrator(
                    session,
                    username=args.username,
                    password=password,
                    passwords=password_manager(),
                    correlation_id=correlation_id,
                )
                print(
                    f"Administrator {'created' if created else 'already exists'}: {user.username}"
                )
    finally:
        database.close()


if __name__ == "__main__":
    main()
