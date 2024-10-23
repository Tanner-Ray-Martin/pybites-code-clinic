from pybites_code_clinic import encrypt_secret, EvLoader
import os


if __name__ == "__main__":
    secret = "my_secret"
    password = "my_password"
    encrypted_secret = encrypt_secret(secret, password)
    this_directory = os.path.dirname(os.path.abspath(__file__))
    env_file = os.path.join(this_directory, "secret_box_example.env")
    ev = EvLoader(_env_file=env_file, password=password)  # type: ignore
    print("repr", ev)
    print("model_dump", ev.model_dump())
    print("model_dump_json", ev.model_dump_json())
    print("ev.credential", ev.credential)
