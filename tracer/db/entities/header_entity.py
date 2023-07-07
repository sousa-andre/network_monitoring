from sqlalchemy import Integer, Column, String, ForeignKey
from sqlalchemy.orm import relationship

from tracer.db.entities.base import Base
from tracer.db.entities.request_entity import RequestEntity


class HeaderEntity(Base):
    __tablename__ = 'headers'

    id = Column(Integer, primary_key=True)
    key = Column(String, nullable=False)
    value = Column(String, nullable=False)

    request_id = Column(Integer, ForeignKey('requests.id'))
    request = relationship(RequestEntity, backref='headers')

