package base

// Device identifies the LINE application profile to emulate.
type Device string

const (
	DeviceDesktopWindows   Device = "DESKTOPWIN"
	DeviceDesktopMac       Device = "DESKTOPMAC"
	DeviceAndroid          Device = "ANDROID"
	DeviceAndroidSecondary Device = "ANDROIDSECONDARY"
	DeviceIOS              Device = "IOS"
	DeviceIOSIPad          Device = "IOSIPAD"
	DeviceWatchOS          Device = "WATCHOS"
	DeviceWearOS           Device = "WEAROS"
)

// DeviceDetails are the client and operating-system values sent in LINE
// request headers.
type DeviceDetails struct {
	Device        Device
	AppVersion    string
	SystemName    string
	SystemVersion string
}

func getDeviceDetails(device Device, version string) (DeviceDetails, bool) {
	if version == "" {
		version = defaultAppVersion(device)
	}

	var systemName string
	var systemVersion string
	switch device {
	case DeviceDesktopWindows:
		systemName = "WINDOWS"
		systemVersion = "10.0.0-NT-x64"
	case DeviceDesktopMac:
		systemName = "MAC"
		systemVersion = "13.0.0"
	case DeviceAndroid, DeviceAndroidSecondary:
		systemName = "Android OS"
		systemVersion = "16"
	case DeviceIOS, DeviceIOSIPad:
		systemName = "iOS"
		systemVersion = "18.0"
	case DeviceWatchOS:
		systemName = "Watch OS"
		systemVersion = "11.0"
	case DeviceWearOS:
		systemName = "Wear OS"
		systemVersion = "3.0"
	default:
		return DeviceDetails{}, false
	}
	return DeviceDetails{
		Device:        device,
		AppVersion:    version,
		SystemName:    systemName,
		SystemVersion: systemVersion,
	}, true
}

func defaultAppVersion(device Device) string {
	switch device {
	case DeviceDesktopWindows:
		return "9.7.0.3556"
	case DeviceDesktopMac:
		return "26.2.0"
	case DeviceAndroid, DeviceAndroidSecondary:
		return "26.6.2"
	case DeviceIOS, DeviceIOSIPad, DeviceWatchOS:
		return "26.7.2"
	case DeviceWearOS:
		return "13.4.1"
	default:
		return ""
	}
}
