from sqlalchemy import Column, Integer, String

from tracer.db.entities.base import Base


class RequestEntity(Base):
    __tablename__ = 'requests'

    id = Column(Integer, primary_key=True)
    method = Column(String, nullable=False)
    path = Column(String, nullable=False)
    body = Column(String)
    start_time = Column(Integer)
