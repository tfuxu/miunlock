# MiUnlock
**MiUnlock** is a small tool for Xiaomi devices that allows you to retrieve bootloader unlock token from Xiaomi servers.


## Usage:
**[NOTE]** This tool CANNOT bypass the 7, 14, 30 day unlock time.

### Requirements:
- Python 3.7 or newer (remember to tick the "Add Python X.X to PATH" option if you are using Windows)
- Python developement headers - `python-dev`
- `wheel`


Install required Python libraries:
```
pip3 install -r requirements.txt
```

**[WARNING]** Do not reboot your device while performing the instructions or else you'll have to start over the unlock process!
#### Step 1
Run the program and do what it tells you to do:

Windows: ```py -3 main.py``` or ```python main.py```

Linux: ```python3 main.py``` or ```chmod +x main.py && ./main.py```
<br><br>


**[WARNING]** Do next steps ONLY if unlocking wasn't done automatically before (e.g you didn't get a prompt like: `Do you want to unlock now?`)

#### Step 2
If the code succeeds it will give you a really long string which is the unlock token, put this into a file and name it `token`


#### Step 3
Download https://github.com/penn5/fastbrute


#### Step 4
Run `interpreter.py` just like shown in step 1. 


#### Step 5
Type:
```
=token
oem unlock
```
The device will perform a factory reset and unlock successfully.


## F.A.Q

### I tried to run the code and it said "python.exe is not recognized"
You didn't install Python properly, re-read the instructions.


### Fastbrute gives "Error 0xffffffff" and reboots device.
I'm assuming you rebooted the device during unlocking which you shouldn't. Don't reboot the device during the unlock process or else the unlock token will change.


### The code says my fastboot token is invalid or fastboot says "unknown command".
Try using `fastboot getvar token` instead of `fastboot oem get_token`


### The code gives "Unknown error"
Open a new issue, post a screenshot of the output there and I will try to figure out what's wrong.
   

## Special thanks to:
@GiorgioUghini
@penn5
@notmarek
@pcfighter
@rien333
