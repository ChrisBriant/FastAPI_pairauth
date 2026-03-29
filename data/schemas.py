from pydantic import BaseModel, field_validator, ConfigDict, computed_field
import re

class UserInputSchema(BaseModel):
    user_name : str
    password : str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):

        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")

        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain an uppercase letter")

        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain a lowercase letter")

        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain a number")

        if not re.search(r"[^\w\s]", v):
            raise ValueError("Password must contain a special character")

        return v