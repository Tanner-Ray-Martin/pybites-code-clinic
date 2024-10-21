from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, SecretStr, computed_field, Secret, field_validator
from nacl.signing import SigningKey, VerifyKey
from nacl.hash import blake2b
from nacl.public import PrivateKey, PublicKey, Box
from nacl.exceptions import CryptoError


def create_box(password: str) -> Box:
    password_bytes: bytes = password.encode()
    b2b_password: bytes = blake2b(password_bytes, digest_size=16)
    private_key: PrivateKey = PrivateKey(b2b_password)
    public_key: PublicKey = private_key.public_key
    box: Box = Box(private_key, public_key)
    return box


def encrypt(password: str, value: str) -> str:
    box = create_box(password)
    return box.encrypt(value.encode()).hex()


def decrypt(password: str, value: str) -> str:
    box = create_box(password)
    return box.decrypt(bytes.fromhex(value)).decode()


class Env(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")
    name: str
    age: int
    secret_credential: SecretStr = Field(None)
    password: "SecretStr | None" = Field(default=None, repr=False, exclude=True)

    @property
    def credential(self) -> str:
        secret_credential: SecretStr = self.secret_credential
        visible_credential: str = secret_credential.get_secret_value()
        if self.password is None:
            return visible_credential
        try:
            return decrypt(self.password.get_secret_value(), visible_credential)
        except CryptoError:
            return "Invalid password"
