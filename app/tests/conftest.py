# conftest.py
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy_utils import create_database, drop_database
from httpx import AsyncClient
from app.main import app
from app.models.user import Base
from dotenv import load_dotenv
import os

# Charge le .env.test
dotenv_path = os.path.join(os.path.dirname(__file__), "../.env.test")
load_dotenv(dotenv_path)

TEST_DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(TEST_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    # Supprime la base si elle existe
    try:
        drop_database(TEST_DATABASE_URL)
    except:
        pass
    # Crée la base
    create_database(TEST_DATABASE_URL)
    Base.metadata.create_all(bind=engine)
    yield
    drop_database(TEST_DATABASE_URL)

@pytest.fixture
def db_session():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()

# Fix du async client
@pytest.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
