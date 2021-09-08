import base64


def debug(txt: str, params: list, flag: bool = False):
    if flag:
        print(txt.format(*__prepare_params(params)))


def __prepare_params(params: list) -> list:
    new_msgs = []
    max_length = 64
    for param in params:
        if type(param) is bytes:
            param = base64.b64encode(param).decode()
        else:
            param = str(param)
        if len(param) > max_length:
            new_msgs.append(param[0:max_length-3]+"...")
        else:
            new_msgs.append(param)
    return new_msgs
