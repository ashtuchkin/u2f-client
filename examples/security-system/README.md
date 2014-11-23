# Example security system using U2F hardware keys.

This system is a REPL that emulates a security system.  
It tries to authorize user when the key is inserted to USB port.  
Prints == ACCESS GRANTED == when user is authenticated.  
User keys are kept in `keys.json` file.  

To run: `node index.js` (don't forget to `npm install`)

```
Commands available:
  help             Prints this message
  register <user>  Registers given user with currently connected device
  login <user>     Try to log in as a given user
  remove <user>    Clears access for given user
  users            Prints registered users
  devices          Prints currently connected devices
```
