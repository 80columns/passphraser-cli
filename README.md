# Passphraser CLI
Passphraser is an application which can be used to generate passwords which are both secure and memorable.

A sample generated passphrase looks like this:

```
*password2023security-INCREASED
```

By default, generated passphrases have 3 words, 2 special characters, and a 4-digit number. This provides 78 bits of entropy, which is equivalent to the strength of a fully-random 12-character ASCII password.

The benefit of using Passphraser is that a password like `*password2023security-INCREASED` is much more memorable than `tZ0e4Sc#63$h`, yet it provides the same level of security and only requires you to remember 6 distinct items instead of 12.

## Setting up Passphraser
To run the command-line version, you will need to [install the .NET runtime](https://learn.microsoft.com/en-us/dotnet/core/install/). .NET is available for [Windows](https://learn.microsoft.com/en-us/dotnet/core/install/windows?tabs=net80) / [MacOS](https://learn.microsoft.com/en-us/dotnet/core/install/macos) / [Linux](https://learn.microsoft.com/en-us/dotnet/core/install/linux). The Passphraser CLI is currently written for .NET 8 and should be compatible with future versions.

After installing .NET, you can build & run Passphraser with the commands below:

```
git clone --recurse-submodules https://github.com/80columns/passphraser-cli.git

cd passphraser-cli

make

./bin/Release/net8.0/passphraser
```

If you are on Windows and can't run `make`, you can run `dotnet build --configuration Release` instead and it will perform the same action.

Binaries for Passphraser are not made available on purpose. In general it is not wise to generate passwords using code you cannot audit. There are exceptions to this of course, for example when using well-known password manager applications.

If you'd like to use Passphraser without installing any software, you can reference the [Passphraser Scripts](https://github.com/80columns/passphraser-scripts).

## Using Passphraser
You can view the full list of options for Passphraser by running this command:

```
./bin/Release/net8.0/passphraser --help

Description:
  Generates a secure and memorable passphrase

Usage:
  passphraser [options]

Options:
  -w, --wordCount <wordCount>  The number of words that should be in the generated passphrase [default: 3]
  -v, --verbose                Print the complexity details of the generated passphrase [default: False]
  --version                    Show version information
  -?, -h, --help               Show help and usage information
```

If you run passphraser with the -v or --verbose flags, it will print the detailed entropy information of the generated passphrase:

```
./bin/Release/net8.0/passphraser -v

*TRIARCH9118unallocated<placoidean

This passphrase is 1 of 4.97E+23 possible passphrases and has 78 bits of entropy
The strength of this passphrase is equivalent to or better than that of a fully-random 12-character ASCII password, which has 4.76E+23 possible passwords and 78 bits of entropy
```

Passphraser will only generate passphrases with a minimum of 3 words, but you can specify any number of words above that:

```
./bin/Release/net8.0/passphraser -w 4 -v
2347mazarine5368INEFFECTIVE=videotaped}TOEBOARD

This passphrase is 1 of 3.25E+33 possible passphrases and has 111 bits of entropy
The strength of this passphrase is equivalent to or better than that of a fully-random 16-character ASCII password, which has 3.72E+31 possible passwords and 104 bits of entropy

./bin/Release/net8.0/passphraser -w 5
%asyndetically9883FALTERINGLY4272PRECOGNITIVE_sapples}suffusive

This passphrase is 1 of 5.25E+40 possible passphrases and has 135 bits of entropy
The strength of this passphrase is equivalent to or better than that of a fully-random 20-character ASCII password, which has 2.9E+39 possible passwords and 131 bits of entropy
```

The generated passphrase will always start with either a special character or a number. If you generate a passphrase with an odd number of words, there will always be N lowercase words, N-1 uppercase words, N special characters, and N-1 numbers. If you generate a passphrase with an even number of words, there will always be an equal number of lowercase words, uppercase words, special characters, and numbers.

## When should this be used?
Passphraser generates passwords which are secure & memorable and satisfy the most popular password complexity requirements - a lowercase letter, an uppercase letter, a special character, and a number. ***You should only use Passphraser to generate a password when you are using an application or website whose password compelxity requirements match all of these conditions***:

* Lowercase letters are allowed
* Uppercase letters are allowed
* Numbers are allowed
* All ASCII special characters are allowed
* The password length limit is at least 63 characters

While many websites offer passwordless or 2-factor authentication login, passwords will always be a necessity in some computing environments because there are 3 possible factors of authentication - something you know, something you have, and something you are. Below are some scenarios where passwords may always be necessary and using Passphraser can help you easily generate the "something you know":

* WiFi passwords
* Linux / Mac / Windows local accounts
* Corporate person and non-person network accounts
* Disk & file encryption
* SSH keys
* PGP keys
* Crypto wallets

## Contributing
Contributions are welcome though development of Passphraser is guided by the single-responsibility principle. The author does not intend that it should become a jack-of-all-trades password generator. .NET was chosen as the development platform for the CLI based on the author's experience and ease of setup for cross-platform usage. It is possible that in the future the CLI will be rewritten in Rust, but there are no significant reasons to do so currently. The goal of Passphraser is to generate passphrases which are consistent, secure, and easily remembered (or easily typed while read from another device).

## Word list
Passphraser uses a public-domain word list which is available at [Passphraser Word List](https://github.com/80columns/passphraser-wordlist). The word list repository is a submodule of this one, so cloning this repository using Git with the `--recurse-submodules` flag will also pull down the word list.

## How it works
You can read about the algorithm developed for Passphraser at [Passphraser Paper](https://github.com/80columns/passphraser-paper), as well as the motivation behind this project.

## FAQ

### What is an ASCII special character?
ASCII special characters are the set of special characters found on standard US English keyboards. There are 32 characters as shown below:

|     |     |     |     |     |     |     |     |
| :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
|  `  |  ~  |  !  |  @  |  #  |  $  |  %  |  ^  |
|  &  |  *  |  (  |  )  |  -  |  _  |  +  |  =  |
|  [  |  ]  |  {  |  }  |  :  |  ;  |  "  |  '  |
|  ,  |  <  |  .  |  >  |  ?  |  /  |  \|  |  \  |

You can learn more about ASCII at [Wikipedia](https://simple.wikipedia.org/wiki/ASCII).

## Questions
Any questions not answered in this README can be sent to pdf _at_ 80columns.com
