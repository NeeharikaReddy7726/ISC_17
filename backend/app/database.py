from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import DATABASE_URL

# check_same_thread=False is needed only for SQLite to allow multiple threads to interact with it
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    FastAPI dependency that provides a transactional database session
    and guarantees it is closed after request handling.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
