class PlatformTests:
    def test_system_compatibility(self):
        platform_checks = {
            'windows': self.check_windows_compatibility,
            'linux': self.check_linux_compatibility,
            'macos': self.check_macos_compatibility
        }
