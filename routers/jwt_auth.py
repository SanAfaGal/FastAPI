from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# openssl rand -hex 32
SECRET_KEY = "bb09e9c19946f6b1ece7515acb6a2bcd3b9561a5fe5df4e99a2e6f1168d5c125"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2a$12$zZaDbOBh0GuAAqxjnRbgau7s/CZaB0mUkm4rfDWkhmTqOxacnauHu",
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
router = APIRouter(tags=["jwt auth"], responses={404: {"message": "Not found"}})


def verify_password(plain_password, hashed_password):
    """
    Verify if a plain text password matches a hashed password.

    Args:
        plain_password (str): The plain text password.
        hashed_password (str): The hashed password to compare against.

    Returns:
        bool: True if the passwords match, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    """
    Generate a hashed version of the given password.

    Args:
        password (str): The password to be hashed.

    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(password)


def get_user(db, username: str):
    """
    Retrieve a user from the database based on the username.

    Args:
        db (dict): The user database.
        username (str): The username of the user to retrieve.

    Returns:
        UserInDB: The user data stored in the database.
    """
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    """
    Authenticate a user by checking the provided username and password.

    Args:
        fake_db (dict): The fake user database.
        username (str): The username to authenticate.
        password (str): The password to verify.

    Returns:
        Union[bool, UserInDB]: If authentication is successful, returns the user data.
                               If authentication fails, returns False.

    Note:
        This function uses the `get_user` function to retrieve user information
        from the fake database and the `verify_password` function to check if
        the provided password matches the stored hashed password.

    Example:
    ```python
        authenticated_user = authenticate_user(fake_users_db, "johndoe", "password123")
        if authenticated_user:
            print(f"Authentication successful. User: {authenticated_user.username}")
        else:
            print("Authentication failed.")
    ```
    """
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """
    Create an access token with the provided data and optional expiration duration.

    Args:
        data (dict): The payload data to be encoded into the token.
        expires_delta (timedelta | None, optional): The duration until the token expires.
            If None, a default expiration of 15 minutes is applied.

    Returns:
        str: The encoded JWT (JSON Web Token) representing the access token.
    """
    to_encode = data.copy()

    # Calculate expiration time based on the provided delta or use a default of 15 minutes
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    # Update the payload with the expiration time
    to_encode.update({"exp": expire})

    # Encode the payload into a JWT using the specified secret key and algorithm
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """
    Retrieve the current user based on the provided authentication token.

    Args:
        token (str): The authentication token obtained from the client.

    Raises:
        HTTPException: If the credentials cannot be validated or if there is an issue with the token.

    Returns:
        UserInDB: The user data associated with the provided token.

    Notes:
        This function is used as a dependency to extract the current user from the authentication token.
        It decodes the token, validates the credentials, and returns the corresponding user data.

    Example:
        ```python
        current_user = await get_current_user("valid_authentication_token")
        ```
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decode the JWT token and extract user information
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")

        # Check if the username is present in the token payload
        if username is None:
            raise credentials_exception

        # Create a TokenData object with the extracted username
        token_data = TokenData(username=username)

    except JWTError:
        # Raise exception if there is an error decoding the token
        raise credentials_exception

    # Retrieve user data from the fake database based on the token's username
    user = get_user(fake_users_db, username=token_data.username)

    # Raise exception if user is not found in the database
    if user is None:
        raise credentials_exception

    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    """
    Get the current active user based on the provided user data.

    This function is a dependency used to ensure that the current user is active.
    It checks the 'disabled' attribute in the user data. If the user is disabled,
    it raises an HTTPException with a 400 status code indicating an inactive user.

    Args:
        current_user (User): The current user obtained from the `get_current_user` dependency.

    Raises:
        HTTPException: If the user is inactive, a 400 status code is returned with the
        detail message "Inactive user."

    Returns:
        User: The current active user.
    """
    # Dependency to ensure that the current user is active
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """
    Endpoint to generate an access token for user authentication.

    This endpoint handles user login, authenticates the user, and generates an access token
    for subsequent authenticated requests.

    Args:
        form_data (OAuth2PasswordRequestForm): The form data containing the username and password.

    Raises:
        HTTPException: If the username or password is incorrect, a 401 status code is returned
        with the detail message "Incorrect username or password," and a 'WWW-Authenticate'
        header is included for Bearer authentication.

    Returns:
        dict: A dictionary containing the access token and token type.
    """
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate an access token with expiration time
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    """
    Endpoint to retrieve information about the currently logged-in user.

    This endpoint returns user details based on the provided authentication token.

    Args:
        current_user (User): The current active user obtained from the `get_current_active_user` dependency.

    Returns:
        User: The details of the currently logged-in user.
    """
    return current_user


@router.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    """
    Endpoint to retrieve items owned by the currently logged-in user.

    This endpoint returns a list of items owned by the currently logged-in user.

    Args:
        current_user (User): The current active user obtained from the `get_current_active_user` dependency.

    Returns:
        List[dict]: A list of items, each represented by a dictionary containing an 'item_id'
        and the 'owner' (username) of the item.
    """
    return [{"item_id": "Foo", "owner": current_user.username}]
