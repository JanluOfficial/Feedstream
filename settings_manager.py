import configparser

class SettingsManager:
    def __init__(self, filename, defaults=None):
        """
        Initialize the SettingsManager with the given INI file.
        If defaults is provided, it should be a dict of default settings.
        """
        self.filename = filename
        self.config = configparser.ConfigParser()

        # Load default settings if provided
        if defaults:
            self.config.read_dict(defaults)

        # Read existing settings from file (if any)
        self.config.read(self.filename)

    @classmethod
    def connect(cls, filename, defaults=None):
        """
        Mimics the SQLite3 connect() function.
        
        Usage:
            settings = SettingsManager.connect('settings.ini', defaults=my_defaults)
        """
        return cls(filename, defaults)

    def get(self, section, option, fallback=None):
        """
        Retrieve a value from the settings.
        """
        return self.config.get(section, option, fallback=fallback)

    def getint(self, section, option, fallback=None):
        """
        Retrieve an integer value from the settings.
        """
        return self.config.getint(section, option, fallback=fallback)

    def getfloat(self, section, option, fallback=None):
        """
        Retrieve a float value from the settings.
        """
        return self.config.getfloat(section, option, fallback=fallback)

    def getboolean(self, section, option, fallback=None):
        """
        Retrieve a boolean value from the settings.
        """
        return self.config.getboolean(section, option, fallback=fallback)

    def set(self, section, option, value):
        """
        Set a value in the settings. If the section doesn't exist, it will be created.
        """
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, option, str(value))

    def remove_option(self, section, option):
        """
        Remove an option from a section.
        """
        if self.config.has_section(section):
            self.config.remove_option(section, option)

    def add_section(self, section):
        """
        Add a new section.
        """
        if not self.config.has_section(section):
            self.config.add_section(section)

    def remove_section(self, section):
        """
        Remove a section from the settings.
        """
        self.config.remove_section(section)

    def commit(self):
        """
        Write any changes back to the file.
        """
        with open(self.filename, 'w') as configfile:
            self.config.write(configfile)

    def close(self):
        """
        Mimic SQLite3's close() method.
        Commits changes to the file.
        """
        self.commit()

    def __enter__(self):
        """
        Support context manager entry.
        """
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Support context manager exit by closing the settings file.
        """
        self.close()


# Example usage:
if __name__ == '__main__':
    # Optional default settings
    defaults = {
        'General': {
            'theme': 'light',
            'language': 'en'
        }
    }
    
    # Initialize the settings manager similar to sqlite3.connect()
    settings = SettingsManager.connect('settings.ini', defaults)

    # Set a new value
    settings.set('General', 'theme', 'dark')
    
    # Retrieve a value
    theme = settings.get('General', 'theme')
    print(f"The current theme is: {theme}")

    # Commit changes to file and close
    settings.close()
