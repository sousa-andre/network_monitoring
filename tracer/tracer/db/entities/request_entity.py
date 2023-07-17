from sqlalchemy import Column, Integer, String, BigInteger, DateTime

from tracer.tracer.db.entities.base import Base


class RequestEntity(Base):
    __tablename__ = 'requests'

    id = Column(Integer, primary_key=True)
    method = Column(String, nullable=False)
    path = Column(String, nullable=False)
    body = Column(String)
    timestamp_seconds = Column(BigInteger, nullable=False)
    timestamp_nanoseconds = Column(Integer, nullable=False)
    read_delta_nanoseconds = Column(Integer)
    readable_date_time = Column(DateTime)
