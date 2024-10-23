from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, SecretStr, field_validator
from nacl.hash import blake2b
from nacl.secret import SecretBox


def create_secret_box(password: str | SecretStr) -> SecretBox:
    if isinstance(password, SecretStr):
        password_hex = password.get_secret_value()
        password_bytes = bytes.fromhex(password_hex)
    elif isinstance(password, str):
        password_bytes = password.encode()
    else:
        raise ValueError("Password must be a string or SecretStr")
    blake_hash = blake2b(password_bytes, digest_size=16)
    return SecretBox(blake_hash)


def decrypt_secret(secret: SecretStr, password: SecretStr) -> str:
    secret_box = create_secret_box(password)
    secret_hex = secret.get_secret_value()
    secret_bytes = bytes.fromhex(secret_hex)
    try:
        decrypted_secret = secret_box.decrypt(secret_bytes).decode()
        return decrypted_secret
    except Exception:
        return "Decryption failed"


def encrypt_secret(secret: str, password: str) -> SecretStr:
    secret_box = create_secret_box(password)
    secret_bytes = secret.encode()
    encrypted_secret = secret_box.encrypt(secret_bytes)
    encrypted_secret_hex = encrypted_secret.hex()
    return SecretStr(encrypted_secret_hex)


class EvLoader(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")
    name: str
    age: int
    secret_credential: SecretStr = Field(
        None, repr=False
    )  # this will not be shown when print is called
    password: SecretStr = Field(
        None, repr=False, exclude=True
    )  # this will not be shown when print or dump is called

    @field_validator("password", mode="before")
    def validate_password(cls, value: str | SecretStr) -> SecretStr:
        if isinstance(value, SecretStr):
            return value
        elif isinstance(value, str):
            password_bytes = value.encode()
            password_hex = password_bytes.hex()
            return SecretStr(password_hex)
        else:
            raise ValueError("Password must be a string or SecretStr")

    @property
    def credential(self) -> str:  # this is visible when EvLoader.credentials is called
        if isinstance(self.password, SecretStr):
            return decrypt_secret(self.secret_credential, self.password)
        else:
            return "Password must be a SecretStr"
