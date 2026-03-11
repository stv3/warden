from models.base import Base, engine, SessionLocal, get_db
from models.finding import Finding
from models.kev_entry import KEVEntry


def create_tables():
    Base.metadata.create_all(bind=engine)


__all__ = ["Base", "engine", "SessionLocal", "get_db", "Finding", "KEVEntry", "create_tables"]
