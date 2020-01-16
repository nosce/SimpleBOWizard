# SimpleBOWizard

## What is it?
This script helps with all steps required for simple buffer overflows. I created it when preparing for my OSCP exam.

Not all buffer overflows are created equal. Therefore, this script only covers the most basic ones:
- ESP points to a possible payload location
- EAX points to a possible payload location

Feel free to use and customize the script according to your needs.

## How to use it?

### Requirements

The script calls the **Metasploit framework** to create a pattern, calculate offsets and create payloads. 
So to use this script, Metasploit must be installed.

When starting, the script will check if all dependencies are fulfilled and shows a message if something is missing.

### Running the script

Just make the script executable and run it:
```shell script
chmod 700 SimpleBOWizard.py
./SimpleBOWizard.py
```

### Working with the wizard

I recommend walking through all wizard steps in the given order. This ensures that everything is set properly. To do so,
simply enter `start`.

To repeat a step, enter `set step X` (where X is the step number). The same command can be used to jump to any step.

Instead of walking through all steps, you can also set all required values manually using the command `set parameter value`.

To get help on all available commands, enter `show help`.

:heavy_exclamation_mark: Don't forget to check that the application is running (and you are monitoring it in a debugger) 
before letting the wizard send a remote buffer overflow payload.

#### Step 0: Fuzzing

In this step you will:
- select the type of buffer overflow (remote/local)
- set the file type *(local buffer overflow)*
- set target IP and port *(remote buffer overflow)*
- customize the fuzzing buffer
  - use `set command` to enter a command which will be placed before the fuzzing buffer, e.g. `set command "USER "`
  - use `set end_command` to enter a command which will be placed after the fuzzing buffer, e.g. `set command "\r\n"`
  - to enter a raw ASCII command use `b""`, e.g. `set command b"\x41\x42\x90"`
  - use `set fuzz_increase` to specify how much the buffer will be increased each time, e.g. `set fuzz_increase 200` creates
  buffer sizes of 200, 400, 600 etc.
  - use `set fuzz_length` to specify how many fuzzing files/requests will be sent, e.g. `set fuzz_length 30`  
  > Example: fuzz_increase = 200 and fuzz_length = 30 will lead to a maximum buffer size of 200 * 30 = 6000

At the end of this step, the wizard will:
- create multiple files with increasing size *(local buffer overflows)*
- create a file *fuzzing.py* and start sending the fuzzing buffers to the target *(remote buffer overflow)*

#### Step 1: Finding offsets
         
In this step you will:
- set the buffer size for the exploit which you have determined through fuzzing

At the end of this step, the wizard will:
- create an exploit file with a unique pattern as payload
- send the payload to the target *(remote buffer overflow)*

#### Step 2: Checking offsets
         
In this step you will:
- enter the pattern that ended up in EIP to determine the offset
- enter the pattern that ended up in Top of Stack to determine if you need a certain nop sled size

At the end of this step, the wizard will:
- update the exploit file with an A-B-C payload, so you can check the offset in the debugger
- send the payload to the target *(remote buffer overflow)*              

#### Step 3: Finding bad characters
In this step you will:
- enter characters which break the exploit 

The wizard will then update the payload so that you can resend it. If you want to use mona in Immunity debugger to find
the bad characters, the wizard will show you which commands you must enter. If you want to inspect the payload manually, 
the command `show ascii` will help you see which characters were sent with the payload (and might cause problems).

#### Step 4: Finding return address 
In this step you will:
- set where the payload can be placed
- set the return address

At the end of this step, the wizard will:
- update the exploit file with an A - return address - C payload, so you can check if the return address works properly
- send the payload to the target *(remote buffer overflow)*    


#### Step 5: Create payload 
In this step you will:
- set the payload

At the end of this step, the wizard will:       
- update the exploit file with the payload
- send the payload to the target *(remote buffer overflow)*

If you do not want to send the payload to the target automatically, you can enter `skip` and run the exploit file manually.

After creating the exploit file in step 1, the wizard will only update the buffer in the following steps. This ensures that
manual changes that you make in the exploit script will be retained.  
Manual changes might be required, for example, if you need another request before sending the buffer.


<sup>Author proof: b9a0eabd3f59c55c0828edf52e05a3fa4ef886084f1edce042ed4f695c42907a</sup>
