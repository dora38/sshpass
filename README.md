# sshpass with TOTP support

For ssh servers with 2FA, with a normal password and time-based one time password.


## Usage

Create a file containing your ssh password. ex: `~/.ssh/pw`

Create an shell executable file printing your One time password. ex: `~/.ssh/totp`

```shell=1
#!/bin/sh

oathtool --totp -b YOUR-SECRET-KEY
```  

Remember setting executable bit:

```
chmod +x ~/.ssh/totp
```

Run sshpass with -f and -c parameters:

```
sshpass -f ~/.ssh/pw -c ~/.ssh/totp ssh your-ssh-server
```

You can use -v parameter if something wrong.


### 2FA bastion server and beyond servers

You can use sshpass and ssh as a proxy command for connecting beyond severs. Edit your `~/.ssh/config`:

```
Host beyond
  ProxyCommand sshpass -f ~/.ssh/pw -c ~/.ssh/totp ssh bastion -qW %h:%p
```

Then run ssh.

```
ssh beyond
```


## Parameters

Added parameters:

```
-o OTP        One time password
-c command    executable file name printing one time password
-O OTP prompt Which string should sshpass search for the one time password prompt
```

-O option's default is `Verification code:`.


## Build

```
./bootstrap
./configure
make
```

You might need installing autoconf and automake.


## Fork from

This is a fork from the sourceforge project "sshpass".

https://sourceforge.net/projects/sshpass/

I used git-svn to create "sourceforge" branch in my github repository.
