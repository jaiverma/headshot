# headshot
Trainer(aimbot and esp) for Assault Cube on macOS

- The frida trainer is written in Python and uses Frida (https://frida.re/)

Usage:
```bash
$ cd frida_trainer
$ python ac_trainer.py <pid of assaultcube>

$ python ac_trainer.py `pidof assaultcube`


****************************
    1. Set Health to 999
    2. Set Clip to 999
    3. Set Ammo to 999
    4. Toggle ESP
    5. Toggle Aimbot
****************************


>
```

- The native trainer is written in C++ and uses the mach_vm API

The native implelemtation requires task_for_pid and must be run as root.
