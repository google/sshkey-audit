# sshkey-audit

This is not an official Google product.

## Example

```
$ cat > keys.txt
ssh-rsa AAAAAhuteonhuneo… my-awesome-laptop
ssh-rsa AAAAhtuhsotiesi…  carol@my-desktop
ssh-rsa AAAAhtuhutnuheo…  corp@work-laptop
ssh-rsa AAAAhtuhuueoueo…  my-manager@their-work-laptop
^D

$ cat > groups.txt
home    my-awesome-laptop carol@my-desktop
work    corp@work-laptop  my-manager@their-work-laptop
laptops my-awesome-laptop corp@work-laptop
^D

$ cat > accounts.txt
alice@home.local          @home
bob@foo.example.com       @work
carol@my-deskop.lan       @laptops  carol@my-desktop
irc@my-irc.shell          @home @work @laptops
^D

$ go get github.com/sirupsen/logrus
$ go build sshkey-audit.go
$ ./sshkey-audit --keys=keys.txt --groups=groups.txt --accounts=accounts.txt expand
alice@home.local
  carol@my-desktop
  my-awesome-laptop
bob@foo.example.com
  corp@work-laptop
  my-awesome-laptop
  my-manager@their-work-laptop
carol@my-deskop.lan
  carol@my-desktop
  corp@work-laptop
  my-awesome-laptop
irc@my-irc.shell
  carol@my-desktop
  corp@work-laptop
  my-awesome-laptop

$ ./sshkey-audit --keys=keys.txt --groups=groups.txt --accounts=accounts.txt check
[… tool logs in to all accounts and checks that this is correct …]

$ ./sshkey-audit --keys=keys.txt --groups=groups.txt --accounts=accounts.txt --add_missing check
[… tool logs in to all accounts and adds any missing keys  …]
```

Adding the `carol@my-desktop` key to allow logging in to `carol@my-desktop.lan` can sometimes be useful to `ssh localhost`.
