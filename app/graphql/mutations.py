import strawberry
from typing import Optional
from app.graphql.types import ResourceType
from app.database import get_db_connection

@strawberry.type
class Mutation:
    @strawberry.mutation
    def update_resource(self, id: int, name: str) -> Optional[ResourceType]:
        """
        Updates resource name.
        VULNERABLE RESOLVER BASELINE:
        Fails to verify whether requesting principal owns the resource.
        The security gateway intercepts this and enforces authorization.
        """
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE objects SET name = ? WHERE id = ?", (name, id))
            conn.commit()
            cursor.execute("SELECT * FROM objects WHERE id = ?", (id,))
            row = cursor.fetchone()
            if row:
                return ResourceType(
                    id=row["id"],
                    name=row["name"],
                    owner_id=row["owner_id"],
                    object_type=row["object_type"],
                    parent_id=row["parent_id"]
                )
            return None
        finally:
            conn.close()

    @strawberry.mutation
    def delete_resource(self, id: int) -> bool:
        """
        Deletes a resource.
        VULNERABLE RESOLVER BASELINE:
        Fails to verify whether requesting principal owns the resource.
        """
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM objects WHERE id = ?", (id,))
            conn.commit()
            return True
        finally:
            conn.close()

    @strawberry.mutation
    def transfer_ownership(self, id: int, new_owner_id: int) -> Optional[ResourceType]:
        """
        Transfers resource ownership.
        VULNERABLE RESOLVER BASELINE:
        Fails to verify whether requesting principal owns the resource.
        """
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE objects SET owner_id = ? WHERE id = ?", (new_owner_id, id))
            conn.commit()
            cursor.execute("SELECT * FROM objects WHERE id = ?", (id,))
            row = cursor.fetchone()
            if row:
                return ResourceType(
                    id=row["id"],
                    name=row["name"],
                    owner_id=row["owner_id"],
                    object_type=row["object_type"],
                    parent_id=row["parent_id"]
                )
            return None
        finally:
            conn.close()
