import strawberry
from strawberry.schema.config import StrawberryConfig, BatchingConfig
from app.graphql.queries import Query
from app.graphql.mutations import Mutation
from app.security.field_masking import FieldLevelMaskingExtension

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    extensions=[FieldLevelMaskingExtension],
    config=StrawberryConfig(
        batching_config=BatchingConfig(max_operations=10)
    )
)

# Unshielded baseline schema for differential security evaluation
insecure_schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    config=StrawberryConfig(
        batching_config=BatchingConfig(max_operations=10)
    )
)


