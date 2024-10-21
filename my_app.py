from pybites_code_clinic import Env

my_settings = Env(_env_file="my.env")
print(
    "no password",
)
print("model_dump", my_settings.model_dump())
print("json", my_settings.model_dump_json())
print("decrypted credential", my_settings.credential)
my_settings = Env(_env_file="my.env", password="mypassword")
print(
    "with password",
)
print("model_dump", my_settings.model_dump())
print("json", my_settings.model_dump_json())
print("decrypted credential", my_settings.credential)
my_settings = Env(_env_file="my.env", password="wrongpassword")
print(
    "wrong password",
)
print("model_dump", my_settings.model_dump())
print("json", my_settings.model_dump_json())
print("decrypted credential", my_settings.credential)
