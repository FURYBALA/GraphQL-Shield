import strawberry
from .database import get_db

@strawberry.type
class ObjectType:
    id: int
    name: str
    owner_id: int
    data: str

@strawberry.type
class Query:
    @strawberry.field
    def object(self, id: int) -> ObjectType | None:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, owner_id, data FROM objects WHERE id = ?", (id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
            
        return ObjectType(
            id=row["id"], 
            name=row["name"], 
            owner_id=row["owner_id"], 
            data=row["data"]
        )

schema = strawberry.Schema(query=Query)
