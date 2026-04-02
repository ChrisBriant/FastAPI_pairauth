from data.models import Device

# def check_active_device_exist(devices : [Device]):
#     active = False
#     for device in devices:
#         if not device.revoked:
#             active = True
#             break
#     return active

#AI VERSION
def check_active_device_exists(devices: list[Device]) -> bool:
    return any(not device.revoked for device in devices)