from data.models import Device

#Helper to check they have an active device registered
def check_active_device_exists(devices: list[Device]) -> bool:
    return any(not device.revoked for device in devices)