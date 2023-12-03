from fastapi import APIRouter
from enum import Enum

router = APIRouter(prefix="/models", tags=["models"],
                   responses={404: {"message": "Not found"}})

class ModelName(Enum):
    alexnet = "alexnet"
    resnet = "resnet"
    lenet = "lenet"
    VGG = "vgg"

@router.get("/{model_name}")
async def get_model(model_name: ModelName):
    if model_name is ModelName.alexnet:
        return {"model_name": model_name, "message": "Deep Learning FTW!"}
    
    if model_name.value == "lenet":
        return {"model_name": model_name, "message": "LeCNN all the images"}
    
    if model_name.name == "VGG":
        return {"model_name": model_name, "message": "Visual Geometry Group"}

    return {"model_name": model_name, "message": "Have some residuals"}