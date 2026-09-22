from pathlib import Path
import shutil

import yaml


BASE_DIR = Path(__file__).resolve().parents[2]
CONFIG_PATH = BASE_DIR / "config.yaml"


def load_response_config():
    with open(CONFIG_PATH, "r") as file:
        config = yaml.safe_load(file)

    return config["response"]


def quarantine_file(file_path):
    response_config = load_response_config()

    simulation_mode = response_config.get("simulation_mode", True)
    quarantine_path = BASE_DIR / response_config.get(
        "quarantine_path",
        "data/quarantine"
    )

    source = Path(file_path)

    if not source.is_file():
        return {
            "success": False,
            "message": "File does not exist.",
        }

    quarantine_path.mkdir(parents=True, exist_ok=True)

    destination = quarantine_path / source.name

    if simulation_mode:
        shutil.copy2(source, destination)

        return {
            "success": True,
            "simulation_mode": True,
            "source": str(source),
            "quarantine": str(destination),
            "message": "Evidence copied to quarantine. Original file preserved.",
        }

    shutil.copy2(source, destination)

    return {
        "success": True,
        "simulation_mode": False,
        "source": str(source),
        "quarantine": str(destination),
        "message": "File copied to quarantine.",
    }


if __name__ == "__main__":
    test_file = BASE_DIR / "data/sandbox/test.txt"

    result = quarantine_file(test_file)

    print("[RDRS] Incident Response Test")
    print(f"Success: {result['success']}")
    print(f"Simulation Mode: {result.get('simulation_mode')}")
    print(f"Source: {result.get('source')}")
    print(f"Quarantine: {result.get('quarantine')}")
    print(f"Message: {result['message']}")

