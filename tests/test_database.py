from app.core.database import (
    Base,
    engine,
    get_session,
    FileEvent,
    Alert,
    Incident,
)


def test_database_tables_exist():
    Base.metadata.create_all(bind=engine)

    table_names = set(Base.metadata.tables.keys())

    assert "file_events" in table_names
    assert "alerts" in table_names
    assert "incidents" in table_names
    assert "processes" in table_names


def test_file_event_can_be_saved():
    session = get_session()

    try:
        event = FileEvent(
            event_type="test",
            file_path="data/sandbox/test_database.txt",
            entropy=3.5,
            details="Automated test event",
        )

        session.add(event)
        session.commit()

        assert event.id is not None

    finally:
        session.close()
