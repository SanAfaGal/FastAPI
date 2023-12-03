from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Union

router = APIRouter(prefix="/users", 
                   tags=["users"],
                   responses={404: {"message": "Not found"}})


class User(BaseModel):
    id: int
    age: int | None = None
    name: str
    surname: str
    username: str


users_list = [
    User(id=1, age=21, name="Santiago", surname="Afanador", username="safanador0"),
    User(id=2, age=45, name="Natalia", surname="Afanador", username="nata1812"),
    User(id=3, age=18, name="Camila", surname="Galeano", username="camisantos12"),
]


@router.get("/", response_model=List[User])
async def read_users(skip: int = 0, limit: Optional[int] = 10):
    return users_list[skip : skip + limit]


@router.get("//me", response_model=dict)
async def get_user_me():
    return {"user_id": "current user"}


@router.get("//{id}", response_model=Union[User, dict])
async def read_user(id: int):
    try:
        user_found = next(user for user in users_list if user.id == id)
        return user_found
    except StopIteration:
        raise HTTPException(status_code=404, detail=f"User not found with id {id}")


@router.post("/", status_code=201, response_model=dict)
async def create_user(user: User):
    if any(existing_user.id == user.id for existing_user in users_list):
        raise HTTPException(status_code=400, detail="User already created")
    else:
        users_list.routerend(user)
        return {"message": "User created successfully"}


@router.delete("/{id}", response_model=dict)
async def delete_user_by_id(id: int):
    try:
        user_to_remove = next(user for user in users_list if user.id == id)
        users_list.remove(user_to_remove)
        return {"message": "User deleted successfully"}
    except StopIteration:
        raise HTTPException(status_code=404, detail=f"User not found with id {id}")


@router.put("/", response_model=dict)
async def update_user(user_to_update: User):
    for i, user in enumerate(users_list):
        if user_to_update.id == user.id:
            users_list[i] = user_to_update
            return {"message": "User updated successfully"}
    raise HTTPException(status_code=404, detail="User not found")
