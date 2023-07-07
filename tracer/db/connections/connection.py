from sqlalchemy import create_engine

from tracer.db.entities.header_entity import HeaderEntity
from tracer.db.entities.request_entity import RequestEntity

engine = create_engine('postgresql://postgres:postgres@192.168.72.1:5432/postgres')
models = [
    RequestEntity,
    HeaderEntity
]

for model in models:
    model.metadata.create_all(engine)
