from fastapi.responses import JSONResponse


def json_error(message: str, status_code: int = 400):
    return JSONResponse(status_code=status_code, content={"message": message})
