import threading
import logging
from Queue import Queue

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.proxy import Proxy
from selenium.common.exceptions import TimeoutException


log = logging.getLogger(__name__)


class BaseDriver(object):
    '''
    The `BaseDriver` class is a base class for custom driver classes used in browser automation. It provides a basic structure and common functionality for initializing, starting, and controlling web drivers.
    The `BaseDriver` class serves as a foundation for creating custom driver classes tailored to specific browsers by extending it and implementing the `create_driver` method.
    '''

    browser = None
    '''
    `browser` variable is intended to be overridden in subclasses to specify the browser name associated with the driver.
    '''

    def __init__(self, config=None):
        '''
        The constructor (`__init__` method) initializes various instance variables such as `driver`, `config`, `alive`, `ready_condition`, and `task_queue`. It also sets up the logging configuration to suppress unnecessary log messages from the `selenium.webdriver` package.
        '''
        self.driver = None
        self.config = config or {}
        self.alive = False

        self.ready_condition = threading.Condition()
        self.task_queue = Queue()

        # turn off logging
        selenium_logger = logging.getLogger('selenium.webdriver.remote.remote_connection')
        selenium_logger.setLevel(logging.WARNING)

    def _initialize_driver(self, driver, config):
        '''
        The `_initialize_driver` method is a helper method that can be overridden in subclasses to perform additional driver initialization steps. By default, it deletes all cookies from the driver if the `cookies` configuration option is not explicitly set to `True`.
        '''
        # config.setdefault('window_size', {'width': 1200, 'height': 800})
        # driver.set_window_size(config['window_size']['width'], config['window_size']['height'])

        if not config.setdefault('cookies', False):
            driver.delete_all_cookies()

        self.initialize_driver(driver, config)

    def create_driver(self, config):
        '''
        The `create_driver` method is an abstract method that must be implemented in subclasses to create and configure the web driver instance.
        '''
        pass

    def initialize_driver(self, driver, config):
        '''
        The `initialize_driver` method is a hook that can be overridden in subclasses to perform any additional initialization steps on the driver instance.
        '''
        pass

    def wait_until_ready(self):
        '''
        The `wait_until_ready` method waits until the driver is ready for use. It uses a `ready_condition` object to synchronize the waiting process.
        '''
        with self.ready_condition:
            self.ready_condition.wait()

    def start(self, wait=False):
        '''
        The `start` method starts the driver in a separate thread. By default, it calls the `_start` method in a daemon thread. If the `wait` parameter is set to `True`, it waits until the driver is ready by calling `wait_until_ready`.
        '''
        t = threading.Thread(target=self._start)
        t.daemon = True
        t.start()

        if wait:
            self.wait_until_ready()

    def _start(self):
        '''
        The `_start` method is the entry point for the driver thread. It creates the driver instance using the `create_driver` method, initializes the driver using `_initialize_driver`, and then enters a loop to process tasks from the `task_queue`.
        '''
        self.driver = self.create_driver(self.config)
        self._initialize_driver(self.driver, self.config)
        log.info("Browser initialized")

        with self.ready_condition:
            self.ready_condition.notifyAll()

        self.alive = True
        while self.alive:
            task = self.task_queue.get()
            self.get(task)

    def get(self, url):
        '''
        The `get` method opens a URL in the driver. It calls the `driver.get` method with the specified URL. If a `TimeoutException` occurs, it ignores it.
        '''
        try:
            # self.driver.set_page_load_timeout(50)
            self.driver.get(url)
        except TimeoutException:
            pass

    def queue_url(self, url):
        '''
        The `queue_url` method adds a URL to the task queue for processing by the driver thread.
        '''
        self.task_queue.put_nowait(url)

    def close(self):
        '''
        The `close` method closes the driver's current window.
        '''
        self.driver.close()

    def stop(self):
        '''
        The `stop` method stops the driver's client.
        '''
        self.driver.stop_client()

    def pid(self):
        '''
        The `pid` method retrieves the process ID (PID) of the driver process.
        '''
        import psutil
        gecko_pid = self.driver.service.process.pid
        return psutil.Process(gecko_pid).children()[0].pid

    def quit(self):
        '''
        The `quit` method stops the driver thread and quits the driver.
        '''
        self.alive = False
        self.driver.quit()


class FirefoxDriver(BaseDriver):
    '''
    The `FirefoxDriver` class is a subclass of the `BaseDriver` class and provides a specific implementation for creating and configuring a Firefox web driver.
    '''
    browser = 'Firefox'

    def create_driver(self, config):
        '''
        The `create_driver` method is implemented to create and configure the Firefox web driver. It creates a `webdriver.FirefoxProfile` object and calls the `init_profile` method to further configure the profile based on the provided `config`. Finally, it creates a `webdriver.Firefox` instance using the configured profile and returns it.
        '''
        profile = webdriver.FirefoxProfile()
        self.init_profile(profile, config)

        return webdriver.Firefox(firefox_profile=profile)

    def initialize_driver(self, driver, config):
        '''
        The `initialize_driver` method is not overridden, so it remains empty, indicating that no additional initialization steps are needed for the Firefox driver.
        '''
        pass

    def init_profile(self, profile, config):
        '''
        The `init_profile` method is a helper method used to configure the Firefox profile based on the provided `config`. It performs the following tasks:
        - If the `cache` option in the `config` is set to `False`, it disables the browser cache and DNS cache by setting various preferences of the profile.
        - If a `proxy` is specified in the `config`, it sets the proxy settings in the profile based on the provided information.
        - If the `verify_certs` option in the `config` is set to `False`, it sets the `accept_untrusted_certs` attribute of the profile to `True`, indicating that it should accept untrusted SSL certificates.
        '''

        # Turn off cache
        if not config.get('cache', True):
            profile.set_preference('browser.download.folderList', 2)
            profile.set_preference("browser.cache.disk.enable", False)
            profile.set_preference("browser.cache.memory.enable", False)
            profile.set_preference("browser.cache.offline.enable", False)
            profile.set_preference("network.http.use-cache", False)

            # Disable DNS cache
            profile.set_preference('network.dnsCacheExpiration', 0)

        # Set proxy
        if 'proxy' in config:
            profile.set_preference('network.proxy.type', 1)
            if 'ssl' in config['proxy']:
                profile.set_preference('network.proxy.ssl', config['proxy']['ssl']['host'])
                profile.set_preference('network.proxy.ssl_port', config['proxy']['ssl']['port'])

        if not config.get('verify_certs', True):
            profile.accept_untrusted_certs = True


class PhantomDriver(BaseDriver):
    '''
    The `PhantomDriver` class is a custom driver class that extends the `BaseDriver` class. It is used to create and configure a web driver instance for the PhantomJS browser. The `create_driver` method returns the configured web driver instance, which can be used for browser automation tasks.
    '''
    browser = 'PhantomJS'

    def create_driver(self, config):
        service_args = []
        if 'proxy' in config:
            if 'ssl' in config['proxy']:
                service_args.append('--proxy={}:{}'.format(config['proxy']['ssl']['host'], config['proxy']['ssl']['port']))
                service_args.append('--proxy-type=https')

        if not config.get('verify_certs', True):
            service_args.append('--ignore-ssl-errors=true')

        if not config.get('cache', True):
            # !! No way to disable memory cache
            service_args.append('--disk-cache=false')

        return webdriver.PhantomJS(service_args=service_args)

