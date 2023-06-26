namespace Passphraser;

using System.CommandLine;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

static class BigIntegerExtensions {
    public static BigInteger Factorial(this BigInteger number) {
        var factorial = number;

        for (var i = number - 1; i > 0; i--) {
            factorial *= i;
        }

        return factorial;
    }
}

static class Program {
    static readonly string wordlistFile = "wordlist/wordlist.txt";
    static readonly int numberLowerBoundInclusive = 1_000;
    static readonly int numberUpperBoundExclusive = 10_000;
    // there are 32 special characters on a US-English keyboard
    static readonly char[] specialCharacters = new char[] {
        '`', '~', '!', '@',
        '#', '$', '%', '^',
        '&', '*', '(', ')',
        '-', '_', '+', '=',
        '[', ']', '{', '}',
        ':', ';', '"', '\'',
        ',', '<', '.', '>',
        '?', '/', '|', '\\'
    };

    static async Task<string[]> ReadWordlistAsync() {
        var wordlist = await File.ReadAllLinesAsync(path: Program.wordlistFile);

        return wordlist;
    }

    static bool GenerateRandomBool() {
        // this call returns either a 0 or a 1
        // for more details, see https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator.getint32?view=net-7.0
        var result = RandomNumberGenerator.GetInt32(fromInclusive: 0, toExclusive: 2);

        // 0 -> true
        // 1 -> false
        return (result == 0);
    }

    static string GenerateRandomNumber() {
        // this call returns a random 4-digit year
        var number = RandomNumberGenerator.GetInt32(fromInclusive: Program.numberLowerBoundInclusive, toExclusive: Program.numberUpperBoundExclusive);

        return Convert.ToString(number);
    }

    static string GenerateRandomSpecialCharacter() {
        return Convert.ToString(Program.specialCharacters[RandomNumberGenerator.GetInt32(fromInclusive: 0, toExclusive: specialCharacters.Length)]);
    }

    static string GenerateRandomWord(bool isLowercase, string[] wordlist) {
        var word = wordlist[RandomNumberGenerator.GetInt32(fromInclusive: 0, toExclusive: wordlist.Length)];

        return isLowercase ? word : word.ToUpper();
    }

    static void AppendToken(ref StringBuilder builder, ref int decrementCounter, string appendValue) {
        builder.Append(appendValue);
        decrementCounter--;
    }

    static string GeneratePassphrase(int wordCount, string[] wordlist) {
        var passphrase = new StringBuilder();
        int lowercaseWordCount, uppercaseWordCount, numberCount, specialCharacterCount;

        void AppendSpecialCharacter() => AppendToken(ref passphrase, ref specialCharacterCount, GenerateRandomSpecialCharacter());
        void AppendNumber() => AppendToken(ref passphrase, ref numberCount, GenerateRandomNumber());
        void AppendLowercaseWord() => AppendToken(ref passphrase, ref lowercaseWordCount, GenerateRandomWord(isLowercase: true, wordlist));
        void AppendUppercaseWord() => AppendToken(ref passphrase, ref uppercaseWordCount, GenerateRandomWord(isLowercase: false, wordlist));

        // for an odd wordCount (wordCount = 2N + 1), there will be:
        //      N numbers and N + 1 special characters
        //      N uppercase words and N + 1 lowercase words

        // for an even wordCount (wordCount = 2N), there will be:
        //      N numbers and N special characters
        //      N uppercase words and N lowercase words
        lowercaseWordCount = uppercaseWordCount = numberCount = specialCharacterCount = wordCount / 2;

        if (wordCount % 2 == 1) {
            lowercaseWordCount++;
            specialCharacterCount++;
        }

        // run the loop while there are words to append
        while (lowercaseWordCount > 0 || uppercaseWordCount > 0) {
            if (numberCount > 0 && specialCharacterCount > 0) {
                if (GenerateRandomBool()) {
                    AppendSpecialCharacter();
                } else {
                    AppendNumber();
                }
            } else if (specialCharacterCount > 0) {
                AppendSpecialCharacter();
            } else {
                AppendNumber();
            }

            if (uppercaseWordCount > 0 && lowercaseWordCount > 0) {
                if (GenerateRandomBool()) {
                    AppendLowercaseWord();
                } else {
                    AppendUppercaseWord();
                }
            } else if (lowercaseWordCount > 0) {
                AppendLowercaseWord();
            } else {
                AppendUppercaseWord();
            }
        }

        return passphrase.ToString();
    }

    static (BigInteger passphrasePermutations, BigInteger passphraseBitEntropy) GetPassphraseStrength(int wordCount, string[] wordlist) {
        int lowercaseWordCount, uppercaseWordCount, numberCount, specialCharacterCount;
        specialCharacterCount = lowercaseWordCount = (wordCount % 2 == 0) ? (wordCount / 2) : ((wordCount / 2) + 1);
        numberCount = uppercaseWordCount = wordCount / 2;

        // see https://en.wikipedia.org/wiki/Permutation, "Permutations of multisets"
        // or https://byjus.com/maths/permutation/, "Permutation of multi-sets"
        //
        // below we take the multiset permutation of the words, which is the same as the multiset permutation of the special characters & numbers,
        // and then multiply them together to get the total number of passphrase formats which can be generated by this program given a specific N number of words
        // this is different than taking the multiset of all items together, because there is a specific alternating order and all generated passphrases start
        // with either a special character or a number
        var wordCountFactorial = new BigInteger(wordCount).Factorial();
        var lowercaseWordCountFactorial = new BigInteger(lowercaseWordCount).Factorial();
        var uppercaseWordCountFactorial = new BigInteger(uppercaseWordCount).Factorial();
        var lowercaseUppercaseWordPermutations = wordCountFactorial / (lowercaseWordCountFactorial * uppercaseWordCountFactorial);
        var passphraseFormatPermutations = BigInteger.Pow(value: lowercaseUppercaseWordPermutations, exponent: 2);
        var passphrasePermutations =
            BigInteger.Pow(wordlist.Length, wordCount)
            * BigInteger.Pow(Program.specialCharacters.Length, specialCharacterCount)
            * BigInteger.Pow(Program.numberUpperBoundExclusive - Program.numberLowerBoundInclusive, numberCount)
            * passphraseFormatPermutations;

        // this is a good explanation of password entropy calculation
        // https://crypto.stackexchange.com/a/376
        var passphraseBitEntropy = BigInteger.Log2(passphrasePermutations);

        return (passphrasePermutations, passphraseBitEntropy);
    }

    static (BigInteger passwordPermutations, BigInteger passwordLength, BigInteger passwordBitEntropy) GetComparablePasswordStrength(BigInteger passphrasePermutations) {
        var passwordLength = 12;
        var validAsciiCharacterCount = 94;
        var passwordPermutations = BigInteger.Pow(validAsciiCharacterCount, passwordLength);
        var previousPasswordPermutations = passwordPermutations;

        while (passwordPermutations < passphrasePermutations) {
            previousPasswordPermutations = passwordPermutations;
            passwordLength++;
            passwordPermutations = BigInteger.Pow(validAsciiCharacterCount, passwordLength);
        }

        // previousPasswordPermutations is used here because at this point in the code passwordPermutations will be greater than passphrasePermutations
        // we need to return the maximum password permutations which is less than the passphrase permutations
        var passwordBitEntropy = BigInteger.Log2(previousPasswordPermutations);

        return (previousPasswordPermutations, passwordLength - 1, passwordBitEntropy);
    }

    static async Task RunProgramAsync(int wordCount, bool verbose) {
        if (wordCount < 3) {
            wordCount = 3;

            Console.WriteLine("The -w/--wordCount parameter has a minimum value of 3\n");
        }

        var wordlist = await ReadWordlistAsync();
        var passphrase = GeneratePassphrase(wordCount, wordlist);

        Console.WriteLine(passphrase);

        if (verbose) {
            var (passphrasePermutations, passphraseBitEntropy) = GetPassphraseStrength(wordCount, wordlist);
            var (passwordPermutations, passwordLength, passwordBitEntropy) = GetComparablePasswordStrength(passphrasePermutations);

            Console.WriteLine(
                $"\nThis passphrase is 1 of {passphrasePermutations:#.##E+0} possible passphrases and has {passphraseBitEntropy} bits of entropy"
              + $"\nThe strength of this passphrase is equivalent to or better than that of a fully-random {passwordLength}-character ASCII password, which has {passwordPermutations:#.##E+0} possible passwords and {passwordBitEntropy} bits of entropy"
            );
        }
    }

    static async Task<int> Main(string[] args) {
        var rootCommand = new RootCommand("Generates a secure and memorable passphrase");
        var wordCountOption = new Option<int>(
            aliases: new string[] { "-w", "--wordCount" },
            getDefaultValue: () => 3,
            description: "The number of words that should be in the generated passphrase"
        );
        var verboseOption = new Option<bool>(
            aliases: new string[] { "-v", "--verbose" },
            getDefaultValue: () => false,
            description: "Print the complexity details of the generated passphrase"
        );

        rootCommand.AddOption(wordCountOption);
        rootCommand.AddOption(verboseOption);

        rootCommand.SetHandler(async (wordCount, verbose) => {
            await RunProgramAsync(wordCount, verbose);
        },
        wordCountOption, verboseOption);

        return await rootCommand.InvokeAsync(args);
    }
}
