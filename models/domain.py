from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Boolean

Base = declarative_base()


class Domain(Base):

    __tablename__ = "domains"

    id = Column(Integer, primary_key=True)
    domain_name = Column(String)
    spf_record = Column(String)
    dmarc_record = Column(String)
    spf_strong = Column(Boolean)
    dmarc_policy = Column(String)
    dmarc_strong = Column(Boolean)
    domain_vulnerable = Column(Boolean)

